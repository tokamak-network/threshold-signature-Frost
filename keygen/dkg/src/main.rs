/*!
Tokamak FROST — DKG Client (secp256k1)
-------------------------------------
This binary is **client-only**. It connects to a WebSocket coordinator and
executes the three-round FROST DKG protocol:

1) Announce/Login & topic join.
2) Round 1: run `dkg::part1` and broadcast the Round-1 package.
3) Round 2: run `dkg::part2` to produce **per-recipient** packages. Each package
   is ECIES-encrypted (secp256k1 ECDH + AES-256-GCM) to the target’s long-term
   ECDSA public key, and then signed (ECDSA) by the sender.
4) Finalize: run `dkg::part3` to derive the KeyPackage and group VK, then submit
   a signed finalize message.

After finalize, the client writes `group.json` and `share_*.json` compatible with
`signing` tooling.
*/

mod helper;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use frost_core::keys::CoefficientCommitment;
use frost_secp256k1 as frost;
use futures::{sink::SinkExt, stream::StreamExt};
use k256::ecdsa::{
    Signature as EcdsaSignature,
    SigningKey as EcdsaSigningKey,
    VerifyingKey as EcdsaVerifyingKey,
};
use k256::SecretKey as K256SecretKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use signature::{DigestSigner, DigestVerifier};
use crate::helper::parse_sig_hex;
use uuid::Uuid;

// -------- ECDSA auth helpers (source integrity & authentication) --------
fn auth_payload_round1(
    topic: &str,
    id: &frost::Identifier,
    pkg: &frost::keys::dkg::round1::Package,
) -> Vec<u8> {
    let mut v = b"TOKAMAK_FROST_DKG_R1|".to_vec();
    v.extend_from_slice(topic.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(id).unwrap());
    v.extend_from_slice(&bincode::serialize(pkg).unwrap());
    v
}
fn auth_payload_round2(
    topic: &str,
    from: &frost::Identifier,
    to: &frost::Identifier,
    eph_pub_sec1: &[u8],
    nonce: &[u8],
    ct: &[u8],
) -> Vec<u8> {
    // Sign the encrypted envelope (not the plaintext): topic | from | to | eph_pub | nonce | ct
    let mut v = b"TOKAMAK_FROST_DKG_R2|".to_vec();
    v.extend_from_slice(topic.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(from).unwrap());
    v.extend_from_slice(&bincode::serialize(to).unwrap());
    v.extend_from_slice(eph_pub_sec1);
    v.extend_from_slice(nonce);
    v.extend_from_slice(ct);
    v
}
fn auth_payload_finalize(topic: &str, id: &frost::Identifier, group_vk_sec1: &[u8]) -> Vec<u8> {
    let mut v = b"TOKAMAK_FROST_DKG_FIN|".to_vec();
    v.extend_from_slice(topic.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(id).unwrap());
    v.extend_from_slice(group_vk_sec1);
    v
}

// ========================= CLI =========================

#[derive(Debug, Parser)]
#[command(
    name = "dkg",
    author,
    version,
    about = "DKG client (FROST secp256k1)"
)]
struct Cli {
    /// WebSocket URL, e.g. ws://127.0.0.1:9000/ws
    #[arg(long, default_value = "ws://127.0.0.1:9000/ws")]
    url: String,
    /// Topic identifier (string)
    #[arg(long)]
    topic: String,
    /// If set, this client will create the topic with these parameters
    #[arg(long, default_value_t = false)]
    create: bool,
    /// Minimum signers (threshold)
    #[arg(long, default_value_t = 3)]
    min_signers: u16,
    /// Maximum/total signers
    #[arg(long, default_value_t = 3)]
    max_signers: u16,
    /// Group id label
    #[arg(long, default_value = "tokamak")]
    group_id: String,
    /// Participant user IDs (comma-separated) when creating a topic
    #[arg(long, default_value = "")]
    participants: String,
    /// Output directory for artifacts (group.json, share_*.json)
    #[arg(long, default_value = "out")]
    out_dir: String,
    /// Hex-encoded 32-byte ECDSA private key (secp256k1) used to sign DKG packets
    #[arg(long, env = "DKG_ECDSA_PRIV_HEX")]
    ecdsa_priv_hex: String,
    /// Only when --create: roster mapping "uid:pubhex,uid:pubhex,..."
    #[arg(long, default_value = "")]
    participants_pubs: String,
}

// ========================= Messages =========================

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
enum ClientMsg {
    AnnounceTopic {
        topic: String,
        min_signers: u16,
        max_signers: u16,
        group_id: String,
        participants: Vec<u32>,
        participants_pubs: Vec<(u32, String)>,
    },
    RequestChallenge,
    Login {
        challenge: String,
        pubkey_hex: String,
        signature_hex: String,
    },
    Logout,
    JoinTopic {
        topic: String,
    },

    // DKG round messages
    Round1Submit {
        topic: String,
        id_hex: String,
        pkg_bincode_hex: String,
        sig_ecdsa_hex: String,
    },
    Round2Submit {
        topic: String,
        id_hex: String,
        // encrypted triples: (recipient_id_hex, eph_pub_sec1_hex, nonce_hex, ct_hex, sig_hex)
        pkgs_cipher_hex: Vec<(String, String, String, String, String)>,
    },
    FinalizeSubmit {
        topic: String,
        id_hex: String,
        group_vk_sec1_hex: String,
        sig_ecdsa_hex: String,
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
        user_id: u32,
        access_token: String,
    },

    // Signals
    ReadyRound1 {
        topic: String,
        id_hex: String,
        min_signers: u16,
        max_signers: u16,
        group_id: String,
        // (uid, id_hex, ecdsa_pub_sec1_hex)
        roster: Vec<(u32, String, String)>,
    },
    Round1All {
        topic: String,
        // (id_hex, pkg_bincode_hex, sig_ecdsa_hex)
        packages: Vec<(String, String, String)>,
    },
    ReadyRound2 {
        topic: String,
    },
    Round2All {
        topic: String,
        // encrypted tuples: (from_id_hex, eph_pub_sec1_hex, nonce_hex, ct_hex, sig_ecdsa_hex)
        packages: Vec<(String, String, String, String, String)>,
    },
    Finalized {
        topic: String,
        group_vk_sec1_hex: String,
    },
}

/// Share file format expected by the signing tool
#[derive(Debug, Serialize, Deserialize)]
struct ShareFile {
    // Who we are and which group we belong to
    group_id: String,
    threshold: u16,
    participants: u16,

    // Participant identity and secret share
    signer_id_bincode_hex: String,
    secret_share_bincode_hex: String,

    // Public data useful to others
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
}

// ========================= Client =========================
#[tokio::main]
async fn main() -> Result<()> {
    let Cli {
        url,
        topic,
        create,
        min_signers,
        max_signers,
        group_id,
        participants,
        out_dir,
        ecdsa_priv_hex,
        participants_pubs,
    } = Cli::parse();

    run_client(
        url,
        topic,
        create,
        min_signers,
        max_signers,
        group_id,
        participants,
        out_dir,
        ecdsa_priv_hex,
        participants_pubs,
    )
        .await
}


async fn run_client(
    url: String,
    topic: String,
    create: bool,
    min_signers: u16,
    max_signers: u16,
    group_id: String,
    participants: String,
    out_dir: String,
    ecdsa_priv_hex: String,
    participants_pubs: String,
) -> Result<()> {
    let (ws_stream, _) = tokio_tungstenite::connect_async(&url)
        .await
        .context("connect ws")?;
    let (mut write, mut read) = ws_stream.split();

    // output dir
    let out_dir_path = PathBuf::from(&out_dir);

    // Long-term ECDSA signing key (required)
    let ecdsa_sk_bytes = hex::decode(ecdsa_priv_hex.clone()).context("ecdsa priv hex")?;
    if ecdsa_sk_bytes.len() != 32 {
        return Err(anyhow!("ECDSA priv must be 32 bytes (hex)"));
    }
    let sk = K256SecretKey::from_slice(&ecdsa_sk_bytes)
        .context("ECDSA private key parse")?;
    let ecdsa_sign = EcdsaSigningKey::from_bytes(&sk.to_bytes())
        .context("ECDSA signing key from bytes")?;
    let ecdsa_verify = ecdsa_sign.verifying_key();
    let pubkey_hex = hex::encode(ecdsa_verify.to_encoded_point(true).as_bytes());

    // map id_hex -> ECDSA verifying key (from roster)
    let mut roster_idhex_to_vk: HashMap<String, EcdsaVerifyingKey> = HashMap::new();

    // cache group/session values for writing artifacts after finalize
    let mut group_label_client: Option<String> = None;
    let mut t_value: u16 = 0;
    let mut n_value: u16 = 0;
    let mut final_kp: Option<frost::keys::KeyPackage> = None;

    // helper macro to send a JSON message over tungstenite
    macro_rules! send_json {
        ($w:expr, $m:expr) => {{
            let s = serde_json::to_string(&$m)?;
            $w.send(tungstenite::Message::Text(s)).await?;
        }};
    }

    // If creator, announce the topic first (unauthenticated).
    if create {
        let parts: Vec<u32> = participants
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().parse::<u32>().expect("u32 id"))
            .collect();
        // parse roster "uid:hex,uid:hex"
        let pubs: Vec<(u32, String)> = participants_pubs
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|kv| {
                let mut it = kv.split(':');
                let uid = it
                    .next()
                    .expect("uid")
                    .trim()
                    .parse::<u32>()
                    .expect("uid u32");
                let hexpk = it.next().expect("pubhex").trim().to_string();
                (uid, hexpk)
            })
            .collect();
        send_json!(
            write,
            ClientMsg::AnnounceTopic {
                topic: topic.clone(),
                min_signers,
                max_signers,
                group_id: group_id.clone(),
                participants: parts,
                participants_pubs: pubs
            }
        );
        println!("[client] Announced topic '{}'", topic);
    }

    // All clients (creator and followers) must now authenticate.
    send_json!(write, ClientMsg::RequestChallenge);

    // local ephemeral DKG memory
    let mut rng = OsRng;
    let mut my_id: Option<frost::Identifier> = None;
    let mut r1_secret: Option<frost::keys::dkg::round1::SecretPackage> = None;
    let mut r1_pkgs: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package> =
        BTreeMap::new();
    let mut r2_secret: Option<frost::keys::dkg::round2::SecretPackage> = None;
    let mut r2_pkgs_from_all: BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package> =
        BTreeMap::new();

    while let Some(msg) = read.next().await {
        match msg? {
            tungstenite::protocol::Message::Text(txt) => {
                let smsg: ServerMsg = serde_json::from_str(&txt)?;
                match smsg {
                    ServerMsg::Challenge { challenge } => {
                        println!("Received challenge, signing...");
                        let challenge_uuid = Uuid::parse_str(&challenge).context("challenge is not a valid UUID")?;
                        let challenge_bytes = challenge_uuid.as_bytes();

                        let sig: EcdsaSignature = ecdsa_sign.sign_digest(Keccak256::new().chain_update(challenge_bytes));
                        let sig_hex = hex::encode(sig.to_der().as_bytes());

                        send_json!(
                            write,
                            ClientMsg::Login {
                                challenge,
                                pubkey_hex: pubkey_hex.clone(),
                                signature_hex: sig_hex,
                            }
                        );
                    }
                    ServerMsg::LoginOk { user_id, .. } => {
                        println!("Logged in as uid {user_id}");
                        // After successful login, all clients join the topic.
                        send_json!(
                            write,
                            ClientMsg::JoinTopic {
                                topic: topic.clone()
                            }
                        );
                    }
                    ServerMsg::ReadyRound1 {
                        topic: t,
                        id_hex,
                        min_signers,
                        max_signers,
                        group_id: group_label,
                        roster,
                    } if t == topic => {
                        let id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                        my_id = Some(id);
                        group_label_client = Some(group_label.clone());
                        t_value = min_signers;
                        n_value = max_signers;
                        // Build id_hex -> verifying key map
                        roster_idhex_to_vk.clear();
                        for (_uid, idh, pkhex) in roster {
                            let bytes = hex::decode(&pkhex)?;
                            let vk = EcdsaVerifyingKey::from_sec1_bytes(&bytes)
                                .map_err(|_| anyhow!("bad roster vk"))?;
                            roster_idhex_to_vk.insert(idh, vk);
                        }
                        println!(
                            "[client] ReadyRound1: id={}, t={}, n={}",
                            hex::encode(bincode::serialize(&id)?),
                            min_signers,
                            max_signers
                        );
                        let (r1s, r1p) =
                            frost::keys::dkg::part1(id, max_signers, min_signers, &mut rng)?;
                        r1_secret = Some(r1s);
                        // sign round1 package
                        let payload = auth_payload_round1(&topic, &id, &r1p);
                        let sig: EcdsaSignature =
                            ecdsa_sign.sign_digest(Keccak256::new().chain_update(&payload));
                        let sig_hex = hex::encode(sig.to_der().as_bytes());
                        let msg = ClientMsg::Round1Submit {
                            topic: topic.clone(),
                            id_hex: hex::encode(bincode::serialize(&id)?),
                            pkg_bincode_hex: hex::encode(bincode::serialize(&r1p)?),
                            sig_ecdsa_hex: sig_hex,
                        };
                        send_json!(write, msg);
                        println!("[client] Sent Round1Submit");
                    }
                    ServerMsg::Round1All { topic: t, packages } if t == topic => {
                        r1_pkgs.clear();
                        for (id_hex, pkg_hex, sig_hex) in &packages {
                            let id: frost::Identifier =
                                bincode::deserialize(&hex::decode(&id_hex)?)?;
                            let pkg: frost::keys::dkg::round1::Package =
                                bincode::deserialize(&hex::decode(&pkg_hex)?)?;
                            // verify signature against roster
                            if let Some(vk) = roster_idhex_to_vk.get(id_hex) {
                                let payload = auth_payload_round1(&topic, &id, &pkg);
                                let sig = parse_sig_hex(sig_hex)?;
                                vk.verify_digest(Keccak256::new().chain_update(&payload), &sig)
                                    .map_err(|_| anyhow!("peer ECDSA verify failed (round1)"))?;
                                r1_pkgs.insert(id, pkg);
                            } else {
                                return Err(anyhow!("no vk for id_hex in roster"));
                            }
                        }
                        println!("[client] Received Round1All: {} packages", r1_pkgs.len());
                    }
                    ServerMsg::ReadyRound2 { topic: t } if t == topic => {
                        let my_id = my_id.ok_or_else(|| anyhow!("no id yet"))?;
                        let r1s = r1_secret.take().ok_or_else(|| anyhow!("no r1 secret"))?;
                        // DKG part2 expects OTHER participants' round1 packages (exclude self)
                        let mut r1_for_me = r1_pkgs.clone();
                        let _ = r1_for_me.remove(&my_id);
                        let expected = (max_signers as usize).saturating_sub(1);
                        println!(
                            "[client] part2: using {} R1 pkgs (expected {})",
                            r1_for_me.len(),
                            expected
                        );
                        let (r2s, r2_out) = frost::keys::dkg::part2(r1s, &r1_for_me)?;
                        r2_secret = Some(r2s);
                        // Encrypt each outgoing r2 pkg for its recipient and sign the encrypted envelope.
                        let mut pairs_enc: Vec<(String, String, String, String, String)> = Vec::new();
                        for (rid, p) in r2_out.into_iter() {
                            let rid_hex = hex::encode(bincode::serialize(&rid)?);
                            let vk = roster_idhex_to_vk
                                .get(&rid_hex)
                                .ok_or_else(|| anyhow!("no vk for rid in roster"))?;
                            let plaintext = bincode::serialize(&p)?;
                            // ECIES: helper returns (ephemeral_pub_sec1, nonce12, ciphertext)
                            let (eph_pub, nonce, ct) = helper::ecies_encrypt_for(vk, &plaintext, &mut rng)
                                .context("ecies encrypt")?;
                            let payload = auth_payload_round2(&topic, &my_id, &rid, &eph_pub, &nonce, &ct);
                            let sig: EcdsaSignature =
                                ecdsa_sign.sign_digest(Keccak256::new().chain_update(&payload));
                            pairs_enc.push((
                                rid_hex,
                                hex::encode(eph_pub),
                                hex::encode(&nonce),
                                hex::encode(ct),
                                hex::encode(sig.to_der().as_bytes()),
                            ));
                        }
                        let pairs_len = pairs_enc.len();
                        let msg = ClientMsg::Round2Submit {
                            topic: topic.clone(),
                            id_hex: hex::encode(bincode::serialize(&my_id)?),
                            pkgs_cipher_hex: pairs_enc,
                        };
                        send_json!(write, msg);
                        println!("[client] Sent Round2Submit with {} packages", pairs_len);
                    }
                    ServerMsg::Round2All { topic: t, packages } if t == topic => {
                        r2_pkgs_from_all.clear();
                        for (from_hex, eph_pub_hex, nonce_hex, ct_hex, sig_hex) in &packages {
                            let fid: frost::Identifier = bincode::deserialize(&hex::decode(&from_hex)?)?;
                            let eph_pub = hex::decode(eph_pub_hex)?;
                            let nonce = hex::decode(nonce_hex)?;
                            let ct = hex::decode(ct_hex)?;
                            if let Some(vk) = roster_idhex_to_vk.get(from_hex) {
                                let my_id_now = my_id.ok_or_else(|| anyhow!("no id"))?;
                                // verify signature over the encrypted envelope
                                let payload = auth_payload_round2(&topic, &fid, &my_id_now, &eph_pub, &nonce, &ct);
                                let sig = parse_sig_hex(sig_hex)?;
                                vk.verify_digest(Keccak256::new().chain_update(&payload), &sig)
                                    .map_err(|_| anyhow!("peer ECDSA verify failed (round2)"))?;
                                // decrypt using our long-term private key (same secp256k1 key as for ECDSA)
                                let pt = helper::ecies_decrypt_with(&sk, &eph_pub, &nonce, &ct)
                                    .context("ecies decrypt")?;
                                let pkg: frost::keys::dkg::round2::Package = bincode::deserialize(&pt)?;
                                r2_pkgs_from_all.insert(fid, pkg);
                            } else {
                                return Err(anyhow!("no vk for from id in roster"));
                            }
                        }
                        // Remove our own package if present (should not be used)
                        if let Some(my_id) = my_id {
                            r2_pkgs_from_all.remove(&my_id);
                        }
                        let expected = (max_signers as usize).saturating_sub(1);
                        println!(
                            "[client] Received Round2All: {} packages (expected {})",
                            r2_pkgs_from_all.len(),
                            expected
                        );
                        // Rebuild the filtered R1 map (exclude self) for part3
                        let my_id = my_id.ok_or_else(|| anyhow!("no id"))?;
                        let mut r1_for_me = r1_pkgs.clone();
                        let _ = r1_for_me.remove(&my_id);
                        if r1_for_me.len() != expected {
                            eprintln!(
                                "[client] WARNING: R1 filtered count {} != expected {}",
                                r1_for_me.len(),
                                expected
                            );
                        }
                        // finalize (part3)
                        let r2s = r2_secret.take().ok_or_else(|| anyhow!("no r2 secret"))?;
                        let (kp, pkp) =
                            frost::keys::dkg::part3(&r2s, &r1_for_me, &r2_pkgs_from_all)?;
                        final_kp = Some(kp.clone());
                        // keep kp locally (private); report group VK to coordinator
                        let group_vk_sec1 = pkp.verifying_key().serialize()?;
                        let vk_len = group_vk_sec1.len();
                        // sign finalize
                        let id_hex_mine = hex::encode(bincode::serialize(&my_id)?);
                        let payload_fin = auth_payload_finalize(&topic, &my_id, &group_vk_sec1);
                        let sig_fin: EcdsaSignature = ecdsa_sign
                            .sign_digest(Keccak256::new().chain_update(&payload_fin));
                        let sig_fin_hex = hex::encode(sig_fin.to_der().as_bytes());
                        send_json!(
                            write,
                            ClientMsg::FinalizeSubmit {
                                topic: topic.clone(),
                                id_hex: id_hex_mine,
                                group_vk_sec1_hex: hex::encode(&group_vk_sec1),
                                sig_ecdsa_hex: sig_fin_hex,
                            }
                        );
                        println!(
                            "[client] Sent FinalizeSubmit (group VK length bytes: {})",
                            vk_len
                        );

                        // Optionally write our local key package for convenience (stdout)
                        println!("My identifier: {}", hex::encode(my_id.serialize()));
                        println!(
                            "My key package (bincode hex): {}",
                            hex::encode(bincode::serialize(&kp)?)
                        );
                    }
                    ServerMsg::Finalized {
                        topic: t,
                        group_vk_sec1_hex,
                    } if t == topic => {
                        println!("DKG finalized. Group VK (SEC1): {group_vk_sec1_hex}");
                        // Build artifacts similar to trusted setup
                        fs::create_dir_all(&out_dir_path)?;
                        let gid = group_label_client
                            .clone()
                            .unwrap_or_else(|| group_id.clone());
                        let my_id = my_id.ok_or_else(|| anyhow!("no id for writing artifacts"))?;
                        let kp = final_kp
                            .take()
                            .ok_or_else(|| anyhow!("no key package to write"))?;
                        // group.json (compat schema)
                        let group = GroupFile {
                            group_id: gid.clone(),
                            threshold: t_value,
                            participants: n_value,
                            group_vk_sec1_hex: group_vk_sec1_hex.clone(),
                        };
                        let group_path = out_dir_path.join("group.json");
                        fs::write(&group_path, serde_json::to_vec_pretty(&group)?)?;
                        println!("Wrote {}", group_path.display());
                        // share_*.json for this participant (keep private!)
                        let identifier_hex_cs = hex::encode(my_id.serialize());
                        let signer_id_bincode_hex = hex::encode(bincode::serialize(&my_id)?);
                        let share_path =
                            out_dir_path.join(format!("share_{}.json", identifier_hex_cs));

                        use frost::keys::VerifiableSecretSharingCommitment;

                        let agg_commitment: VerifiableSecretSharingCommitment = {
                            let mut iter = r1_pkgs.values();
                            let first_pkg = iter.next().expect("no Round1 packages cached");
                            let mut acc_vec: Vec<_> =
                                first_pkg.commitment().coefficients().to_vec();
                            // Sum each coefficient element-wise across all commitments
                            for pkg in iter {
                                for (a, b) in acc_vec
                                    .iter_mut()
                                    .zip(pkg.commitment().coefficients().to_vec())
                                {
                                    *a = CoefficientCommitment::new(
                                        a.clone().value() + b.clone().value(),
                                    );
                                }
                            }
                            VerifiableSecretSharingCommitment::new(acc_vec)
                        };

                        // 2) Build the SecretShare with (identifier, signing_share, aggregated VSS commitment).
                        let ss = frost::keys::SecretShare::new(
                            my_id.clone(),
                            kp.signing_share().clone(),
                            agg_commitment,
                        );

                        let share = ShareFile {
                            group_id: gid.clone(),
                            threshold: t_value,
                            participants: n_value,
                            signer_id_bincode_hex,
                            secret_share_bincode_hex: hex::encode(bincode::serialize(&ss)?),
                            verifying_share_bincode_hex: hex::encode(bincode::serialize(
                                &kp.verifying_share(),
                            )?),
                            group_vk_sec1_hex: group_vk_sec1_hex.clone(),
                        };

                        fs::write(&share_path, serde_json::to_vec_pretty(&share)?)?;
                        println!("Wrote {}", share_path.display());
                        // Politely close the websocket and finish
                        send_json!(write, ClientMsg::Logout);
                        use tungstenite::Message as WsMsg;
                        let _ = write.send(WsMsg::Close(None)).await;
                        // Ensure the sink is closed so the server observes disconnect immediately
                        let _ = write.close().await;
                        // Drop the writer half explicitly
                        drop(write);
                        break;
                    }
                    ServerMsg::Info { message } => println!("[server] {message}"),
                    ServerMsg::Error { message } => {
                        eprintln!("[server error] {message}");
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    Ok(())
}
