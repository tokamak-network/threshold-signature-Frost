/*!
Tokamak FROST — DKG Client (secp256k1/ed25519)
-------------------------------------
This binary is **client-only**. It connects to a WebSocket coordinator and
executes the three-round FROST DKG protocol:

1) Announce/Login & session join.
2) Round 1: run `dkg::part1` and broadcast the Round-1 package.
3) Round 2: run `dkg::part2` to produce **per-recipient** packages. Each package
   is ECIES-encrypted to the target’s long-term roster public key, and then signed
   by the sender.
4) Finalize: run `dkg::part3` to derive the KeyPackage and group VK, then submit
   a signed finalize message.

After finalize, the client writes `group.json` and `share_*.json` compatible with
`signing` tooling.
*/

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use frost_core::keys::CoefficientCommitment;
use frost_secp256k1 as frost;
use futures::{sink::SinkExt, stream::StreamExt};
use helper::{
    auth_payload_finalize, auth_payload_round1, auth_payload_round2,
    read_roster_signing_key_from_env, EncryptedPayload, RosterPublicKey, RosterSigningKey,
};
use k256::ecdsa::VerifyingKey as EcdsaVerifyingKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ========================= CLI =========================

#[derive(Debug, Parser)]
#[command(name = "dkg", author, version, about = "DKG client (FROST secp256k1)")]
struct Cli {
    /// WebSocket URL, e.g. ws://127.0.0.1:9000/ws
    #[arg(long, default_value = "ws://127.0.0.1:9000/ws")]
    url: String,
    /// Creator mode: create a new session on the server and receive its id
    #[arg(long, default_value_t = false)]
    create: bool,
    /// Minimum signers (threshold) [creator only]
    #[arg(long, default_value_t = 2)]
    min_signers: u16,
    /// Maximum/total signers [creator only]
    #[arg(long, default_value_t = 2)]
    max_signers: u16,
    /// Group id label [creator only]
    #[arg(long, default_value = "tokamak")]
    group_id: String,
    /// Participant user IDs (comma-separated) when creating a session
    #[arg(long, default_value = "")]
    participants: String,
    /// Output directory for artifacts (group.json, share_*.json, session.txt)
    #[arg(long, default_value = "out")]
    out_dir: String,
    /// Optional: explicit session id for followers (UUID). If absent, --session-file is used.
    #[arg(long)]
    session: Option<String>,
    /// Optional: file path to read/write the session id (defaults to <out_dir>/session.txt)
    #[arg(long)]
    session_file: Option<String>,
    /// Only when --create: roster mapping "uid;;;json_roster_pub_key,..."
    #[arg(long, default_value = "")]
    participants_pubs: String,
    /// Roster key type for this client
    #[arg(long, global = true, env = "ROSTER_KEY_TYPE")]
    key_type: Option<String>,
    /// Roster private key (32-byte hex) for this client
    #[arg(long, global = true, env = "ROSTER_PRIVATE_KEY")]
    private_key: Option<String>,
}

// ========================= Messages =========================

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
enum ClientMsg {
    AnnounceDKGSession {
        min_signers: u16,
        max_signers: u16,
        group_id: String,
        participants: Vec<u32>,
        participants_pubs: Vec<(u32, RosterPublicKey)>,
    },
    RequestChallenge,
    Login {
        challenge: String,
        public_key: RosterPublicKey,
        signature_hex: String,
    },
    Logout,
    JoinDKGSession {
        session: String,
    },
    Round1Submit {
        session: String,
        id_hex: String,
        pkg_bincode_hex: String,
        signature_hex: String,
    },
    Round2Submit {
        session: String,
        id_hex: String,
        pkgs_cipher: Vec<(String, EncryptedPayload, String)>, // (recipient_id_hex, EncryptedPayload, signature_hex)
    },
    FinalizeSubmit {
        session: String,
        id_hex: String,
        group_vk_sec1_hex: String,
        signature_hex: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
enum ServerMsg {
    Error {
        message: String,
    },
    Info {
        message: String,
    },
    Challenge {
        challenge: String,
    },
    LoginOk {
        principal: String,
        suid: u32,
        access_token: String,
    },
    DKGSessionCreated {
        session: String,
    },
    ReadyRound1 {
        session: String,
        id_hex: String,
        min_signers: u16,
        max_signers: u16,
        group_id: String,
        roster: Vec<(u32, String, RosterPublicKey)>,
    },
    Round1All {
        session: String,
        packages: Vec<(String, String, String)>,
    },
    ReadyRound2 {
        session: String,
    },
    Round2All {
        session: String,
        packages: Vec<(String, EncryptedPayload, String)>,
    },
    Finalized {
        session: String,
        group_vk_sec1_hex: String,
    },
}

/// Share file format expected by the signing tool
#[derive(Debug, Serialize, Deserialize)]
struct ShareFile {
    group_id: String,
    threshold: u16,
    participants: u16,
    #[serde(default)]
    session: Option<String>,
    signer_id_bincode_hex: String,
    secret_share_bincode_hex: String,
    verifying_share_bincode_hex: String,
    group_vk_sec1_hex: String,
}

/// Group file format expected by the signing/aggregate tool
#[derive(Debug, Serialize, Deserialize)]
struct GroupFile {
    group_id: String,
    threshold: u16,
    participants: u16,
    group_vk_sec1_hex: String,
    #[serde(default)]
    session: Option<String>,
}

// ========================= Client =========================
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    run_client(
        cli.url,
        cli.create,
        cli.min_signers,
        cli.max_signers,
        cli.group_id,
        cli.participants,
        cli.out_dir,
        cli.session,
        cli.session_file,
        cli.participants_pubs,
        cli.key_type,
        cli.private_key,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_client(
    url: String,
    create: bool,
    min_signers: u16,
    max_signers: u16,
    group_id: String,
    participants: String,
    out_dir: String,
    session_cli: Option<String>,
    session_file_cli: Option<String>,
    participants_pubs: String,
    key_type: Option<String>,
    private_key: Option<String>,
) -> Result<()> {
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .context("connect ws")?;
    let (mut write, mut read) = ws_stream.split();

    let out_dir_path = PathBuf::from(&out_dir);
    let session_file_path = session_file_cli
        .map(PathBuf::from)
        .unwrap_or_else(|| out_dir_path.join("session.txt"));

    let roster_sk = match (key_type, private_key) {
        (Some(ty), Some(hex)) => {
            let bytes = hex::decode(hex.trim())?;
            if bytes.len() != 32 {
                return Err(anyhow!("Roster private key must be 32 bytes (hex)"));
            }
            let key = match ty.to_lowercase().as_str() {
                "secp256k1" => {
                    let fb = k256::FieldBytes::from_slice(&bytes);
                    let sk = k256::ecdsa::SigningKey::from_bytes(fb)?;
                    RosterSigningKey::Secp256k1(sk)
                }
                "ed25519" => {
                    let mut sk_bytes = [0u8; 32];
                    sk_bytes.copy_from_slice(&bytes);
                    RosterSigningKey::Ed25519(sk_bytes)
                }
                _ => return Err(anyhow!("Unsupported key-type: {}", ty)),
            };
            Ok(Some(key))
        }
        _ => read_roster_signing_key_from_env(),
    }?
    .ok_or_else(|| anyhow!("Roster key not provided via CLI or env vars"))?;
    let roster_pk = roster_sk.public_key();

    let mut roster_idhex_to_pk: HashMap<String, RosterPublicKey> = HashMap::new();
    let mut group_label_client: Option<String> = None;
    let mut t_value: u16 = 0;
    let mut n_value: u16 = 0;
    let mut final_kp: Option<frost::keys::KeyPackage> = None;
    let mut session_id: Option<String> = None;
    let mut logged_in = bool::default();

    macro_rules! send_json {
        ($w:expr, $m:expr) => {{
            let s = serde_json::to_string(&$m)?;
            $w.send(tungstenite::Message::Text(s)).await?;
        }};
    }

    let mut announce_msg: Option<ClientMsg> = None;
    if create {
        let parts: Vec<u32> = participants
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().parse::<u32>().expect("u32 id"))
            .collect();
        let pubs: Vec<(u32, RosterPublicKey)> = participants_pubs
            .split('|')
            .filter(|s| !s.is_empty())
            .map(|kv| {
                let (uid_str, key_json) = kv.split_once(";;;").expect("uid;;;json_key");
                let uid = uid_str.trim().parse::<u32>().expect("uid u32");
                let key: RosterPublicKey =
                    serde_json::from_str(key_json).expect("valid RosterPublicKey JSON");
                (uid, key)
            })
            .collect();
        announce_msg = Some(ClientMsg::AnnounceDKGSession {
            min_signers,
            max_signers,
            group_id: group_id.clone(),
            participants: parts,
            participants_pubs: pubs,
        });
        println!("[client] Prepared session announcement (waiting for login)");
    } else if let Some(sid) = session_cli {
        session_id = Some(sid);
    } else if let Ok(text) = fs::read_to_string(&session_file_path) {
        let sid = text.trim().to_string();
        if !sid.is_empty() {
            session_id = Some(sid);
        }
    }

    send_json!(write, ClientMsg::RequestChallenge);

    let mut rng = OsRng;
    let mut my_id: Option<frost::Identifier> = None;
    let mut r1_secret: Option<frost::keys::dkg::round1::SecretPackage> = None;
    let mut r1_pkgs: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package> =
        BTreeMap::new();
    let mut r2_secret: Option<frost::keys::dkg::round2::SecretPackage> = None;
    let mut r2_pkgs_from_all: BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package> =
        BTreeMap::new();

    async fn try_join(
        write: &mut (impl futures::Sink<tungstenite::Message, Error = tungstenite::Error> + Unpin),
        session_id: &Option<String>,
        logged_in: bool,
    ) -> Result<()> {
        if logged_in {
            if let Some(s) = session_id {
                let msg = ClientMsg::JoinDKGSession { session: s.clone() };
                send_json!(write, msg);
            }
        }
        Ok(())
    }

    while let Some(msg) = read.next().await {
        if let tungstenite::protocol::Message::Text(txt) = msg? {
            let smsg: ServerMsg = serde_json::from_str(&txt)?;
            match smsg {
                ServerMsg::DKGSessionCreated { session } => {
                    println!("[client] Session created: {}", session);
                    fs::create_dir_all(&out_dir_path)?;
                    fs::write(&session_file_path, &session)?;
                    session_id = Some(session);
                    try_join(&mut write, &session_id, logged_in).await?;
                }
                ServerMsg::Challenge { challenge } => {
                    println!("Received challenge, signing...");
                    let challenge_uuid =
                        Uuid::parse_str(&challenge).context("challenge is not a valid UUID")?;
                    let sig_hex = roster_sk.sign(challenge_uuid.as_bytes());
                    send_json!(
                        write,
                        ClientMsg::Login {
                            challenge,
                            public_key: roster_pk.clone(),
                            signature_hex: sig_hex
                        }
                    );
                }
                ServerMsg::LoginOk { .. } => {
                    println!("Logged in.");
                    logged_in = true;
                    if let Some(msg) = announce_msg.take() {
                        send_json!(write, msg);
                        println!("[client] Announced new session");
                    }
                    try_join(&mut write, &session_id, logged_in).await?;
                }
                ServerMsg::ReadyRound1 {
                    session: s,
                    id_hex,
                    min_signers,
                    max_signers,
                    group_id: group_label,
                    roster,
                } => {
                    if Some(&s) != session_id.as_ref() {
                        continue;
                    }
                    let id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                    my_id = Some(id);
                    group_label_client = Some(group_label.clone());
                    t_value = min_signers;
                    n_value = max_signers;
                    roster_idhex_to_pk.clear();
                    for (_uid, idh, pk) in roster {
                        roster_idhex_to_pk.insert(idh, pk);
                    }
                    println!(
                        "[client] ReadyRound1: id={}, t={}, n={}",
                        hex::encode(bincode::serialize(&id)?),
                        min_signers,
                        max_signers
                    );
                    let (r1s, r1p) = frost::keys::dkg::part1(id, max_signers, min_signers, rng)?;
                    r1_secret = Some(r1s);
                    let session = session_id
                        .clone()
                        .ok_or_else(|| anyhow!("no session id yet"))?;
                    let payload = auth_payload_round1(&session, &id, &r1p);
                    let sig_hex = roster_sk.sign(&payload);
                    let msg = ClientMsg::Round1Submit {
                        session,
                        id_hex: hex::encode(bincode::serialize(&id)?),
                        pkg_bincode_hex: hex::encode(bincode::serialize(&r1p)?),
                        signature_hex: sig_hex,
                    };
                    send_json!(write, msg);
                    println!("[client] Sent Round1Submit");
                }
                ServerMsg::Round1All {
                    session: s,
                    packages,
                } => {
                    if Some(&s) != session_id.as_ref() {
                        continue;
                    }
                    r1_pkgs.clear();
                    for (id_hex, pkg_hex, sig_hex) in &packages {
                        let id: frost::Identifier = bincode::deserialize(&hex::decode(id_hex)?)?;
                        let pkg: frost::keys::dkg::round1::Package =
                            bincode::deserialize(&hex::decode(pkg_hex)?)?;
                        if let Some(vk) = roster_idhex_to_pk.get(id_hex) {
                            let session = session_id
                                .clone()
                                .ok_or_else(|| anyhow!("no session id yet"))?;
                            let payload = auth_payload_round1(&session, &id, &pkg);
                            vk.verify(&payload, sig_hex)?;
                            r1_pkgs.insert(id, pkg);
                        } else {
                            return Err(anyhow!("no vk for id_hex in roster"));
                        }
                    }
                    println!("[client] Received Round1All: {} packages", r1_pkgs.len());
                }
                ServerMsg::ReadyRound2 { session: s } => {
                    if Some(&s) != session_id.as_ref() {
                        continue;
                    }
                    let my_id = my_id.ok_or_else(|| anyhow!("no id yet"))?;
                    let r1s = r1_secret.take().ok_or_else(|| anyhow!("no r1 secret"))?;
                    let mut r1_for_me = r1_pkgs.clone();
                    r1_for_me.remove(&my_id);
                    let (r2s, r2_out) = frost::keys::dkg::part2(r1s, &r1_for_me)?;
                    r2_secret = Some(r2s);
                    let mut pairs_enc: Vec<(String, EncryptedPayload, String)> = Vec::new();
                    for (rid, p) in r2_out.into_iter() {
                        let rid_hex = hex::encode(bincode::serialize(&rid)?);
                        let vk = roster_idhex_to_pk
                            .get(&rid_hex)
                            .ok_or_else(|| anyhow!("no vk for rid in roster"))?;
                        let plaintext = bincode::serialize(&p)?;
                        let encrypted_payload = vk.encrypt_for(&plaintext, &mut rng)?;
                        let session = session_id
                            .clone()
                            .ok_or_else(|| anyhow!("no session id yet"))?;
                        let eph_pub_bytes = match &encrypted_payload.ephemeral_public_key {
                            RosterPublicKey::Secp256k1(b) => hex::decode(b)?,
                            RosterPublicKey::Ed25519(b) => hex::decode(b)?,
                        };
                        let nonce_bytes = hex::decode(&encrypted_payload.nonce)?;
                        let ciphertext_bytes = hex::decode(&encrypted_payload.ciphertext)?;
                        let payload = auth_payload_round2(
                            &session,
                            &my_id,
                            &rid,
                            &eph_pub_bytes,
                            &nonce_bytes,
                            &ciphertext_bytes,
                        );
                        let sig_hex = roster_sk.sign(&payload);
                        pairs_enc.push((rid_hex, encrypted_payload, sig_hex));
                    }
                    let session = session_id
                        .clone()
                        .ok_or_else(|| anyhow!("no session id yet"))?;
                    let msg = ClientMsg::Round2Submit {
                        session,
                        id_hex: hex::encode(bincode::serialize(&my_id)?),
                        pkgs_cipher: pairs_enc.clone(),
                    };
                    send_json!(write, msg);
                    println!(
                        "[client] Sent Round2Submit with {} packages",
                        pairs_enc.len()
                    );
                }
                ServerMsg::Round2All {
                    session: s,
                    packages,
                } => {
                    if Some(&s) != session_id.as_ref() {
                        continue;
                    }
                    r2_pkgs_from_all.clear();
                    for (from_hex, encrypted_payload, sig_hex) in &packages {
                        let fid: frost::Identifier = bincode::deserialize(&hex::decode(from_hex)?)?;
                        if let Some(vk) = roster_idhex_to_pk.get(from_hex) {
                            let my_id_now = my_id.ok_or_else(|| anyhow!("no id"))?;
                            let session = session_id
                                .clone()
                                .ok_or_else(|| anyhow!("no session id yet"))?;
                            let eph_pub_bytes = match &encrypted_payload.ephemeral_public_key {
                                RosterPublicKey::Secp256k1(b) => hex::decode(b)?,
                                RosterPublicKey::Ed25519(b) => hex::decode(b)?,
                            };
                            let nonce_bytes = hex::decode(&encrypted_payload.nonce)?;
                            let ciphertext_bytes = hex::decode(&encrypted_payload.ciphertext)?;
                            let payload = auth_payload_round2(
                                &session,
                                &fid,
                                &my_id_now,
                                &eph_pub_bytes,
                                &nonce_bytes,
                                &ciphertext_bytes,
                            );
                            vk.verify(&payload, sig_hex)?;
                            let pt = roster_sk.decrypt_with(encrypted_payload)?;
                            let pkg: frost::keys::dkg::round2::Package = bincode::deserialize(&pt)?;
                            r2_pkgs_from_all.insert(fid, pkg);
                        } else {
                            return Err(anyhow!("no vk for from id in roster"));
                        }
                    }
                    if let Some(my_id) = my_id {
                        r2_pkgs_from_all.remove(&my_id);
                    }
                    let my_id = my_id.ok_or_else(|| anyhow!("no id"))?;
                    let mut r1_for_me = r1_pkgs.clone();
                    r1_for_me.remove(&my_id);
                    let r2s = r2_secret.take().ok_or_else(|| anyhow!("no r2 secret"))?;
                    let (kp, pkp) = frost::keys::dkg::part3(&r2s, &r1_for_me, &r2_pkgs_from_all)?;
                    final_kp = Some(kp.clone());
                    let mut group_vk_sec1 = pkp.verifying_key().serialize()?;
                    if group_vk_sec1.len() == 65 {
                        let vk = EcdsaVerifyingKey::from_sec1_bytes(&group_vk_sec1)
                            .map_err(|_| anyhow!("invalid group vk"))?;
                        group_vk_sec1 = vk.to_encoded_point(true).as_bytes().to_vec();
                    }
                    let id_hex_mine = hex::encode(bincode::serialize(&my_id)?);
                    let session = session_id
                        .clone()
                        .ok_or_else(|| anyhow!("no session id yet"))?;
                    let payload_fin = auth_payload_finalize(&session, &my_id, &group_vk_sec1);
                    let sig_fin_hex = roster_sk.sign(&payload_fin);
                    send_json!(
                        write,
                        ClientMsg::FinalizeSubmit {
                            session,
                            id_hex: id_hex_mine,
                            group_vk_sec1_hex: hex::encode(&group_vk_sec1),
                            signature_hex: sig_fin_hex,
                        }
                    );
                    println!("[client] Sent FinalizeSubmit");
                }
                ServerMsg::Finalized {
                    session: s,
                    group_vk_sec1_hex,
                } => {
                    if Some(&s) != session_id.as_ref() {
                        continue;
                    }
                    println!("DKG finalized. Group VK (SEC1): {group_vk_sec1_hex}");
                    fs::create_dir_all(&out_dir_path)?;
                    let gid = group_label_client.clone().unwrap_or(group_id.clone());
                    let my_id = my_id.ok_or_else(|| anyhow!("no id for writing artifacts"))?;
                    let kp = final_kp
                        .take()
                        .ok_or_else(|| anyhow!("no key package to write"))?;
                    let group = GroupFile {
                        group_id: gid.clone(),
                        threshold: t_value,
                        participants: n_value,
                        group_vk_sec1_hex: group_vk_sec1_hex.clone(),
                        session: session_id.clone(),
                    };
                    let group_path = out_dir_path.join("group.json");
                    fs::write(&group_path, serde_json::to_vec_pretty(&group)?)?;
                    println!("Wrote {}", group_path.display());
                    let identifier_hex_cs = hex::encode(my_id.serialize());
                    let signer_id_bincode_hex = hex::encode(bincode::serialize(&my_id)?);
                    let share_path = out_dir_path.join(format!("share_{}.json", identifier_hex_cs));
                    use frost::keys::VerifiableSecretSharingCommitment;
                    let agg_commitment: VerifiableSecretSharingCommitment = {
                        let mut iter = r1_pkgs.values();
                        let first_pkg = iter.next().expect("no Round1 packages cached");
                        let mut acc_vec: Vec<_> = first_pkg.commitment().coefficients().to_vec();
                        for pkg in iter {
                            for (a, b) in acc_vec.iter_mut().zip(pkg.commitment().coefficients()) {
                                *a = CoefficientCommitment::new(
                                    a.clone().value() + b.clone().value(),
                                );
                            }
                        }
                        VerifiableSecretSharingCommitment::new(acc_vec)
                    };
                    let ss =
                        frost::keys::SecretShare::new(my_id, *kp.signing_share(), agg_commitment);
                    let share = ShareFile {
                        group_id: gid.clone(),
                        threshold: t_value,
                        participants: n_value,
                        session: session_id.clone(),
                        signer_id_bincode_hex,
                        secret_share_bincode_hex: hex::encode(bincode::serialize(&ss)?),
                        verifying_share_bincode_hex: hex::encode(bincode::serialize(
                            &kp.verifying_share(),
                        )?),
                        group_vk_sec1_hex: group_vk_sec1_hex.clone(),
                    };
                    fs::write(&share_path, serde_json::to_vec_pretty(&share)?)?;
                    println!("Wrote {}", share_path.display());
                    send_json!(write, ClientMsg::Logout);
                    let _ = write.send(tungstenite::Message::Close(None)).await;
                    drop(write);
                    break;
                }
                ServerMsg::Info { message } => println!("[server] {message}"),
                ServerMsg::Error { message } => eprintln!("[server error] {message}"),
            }
        }
    }
    Ok(())
}
