/*!
signing — per-participant FROST(secp256k1) signing tool
-------------------------------------------------------
This binary implements the three-step workflow to produce and verify a FROST signature:

• Round 1 (per participant): generate ephemeral nonces + commitments from your share.
• Round 2 (per participant): use all participants' Round1 outputs + your share to compute
  a signature share over a message (Keccak-256 hashed).
• Aggregate (single run): combine all Round1 + Round2 outputs to obtain the final signature.

File formats are JSON wrappers around bincode-serialized FROST types, hex-encoded for
portability. The outputs are compatible with the on-chain verifier and off-chain tools.
*/
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use helper::{
    auth_payload_sign_r1, auth_payload_sign_r2, auth_payload_signing_round1,
    auth_payload_signing_round2, parse_participants_pubs_map, read_roster_signing_key_from_env,
    RosterPublicKey, RosterSigningKey,
};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use frost_core::Field;
use frost_secp256k1 as frost;
use futures::{sink::SinkExt, stream::StreamExt};
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::PublicKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tokio_tungstenite::connect_async;
use tungstenite::Message as WsMsg;

/// Messages used by the interactive signing WS flow (must mirror server definitions)
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
enum ClientMsg {
    // Auth
    RequestChallenge,
    Login {
        challenge: String,
        public_key: RosterPublicKey,
        signature_hex: String,
    },

    // Interactive signing session control
    AnnounceSignSession {
        group_id: String,
        threshold: u16,
        participants: Vec<u32>,
        participants_pubs: Vec<(u32, RosterPublicKey)>,
        group_vk_sec1_hex: String,
        message: String,
        message_hex: String,
    },
    JoinSignSession {
        session: String,
        signer_id_bincode_hex: String,
        verifying_share_bincode_hex: String,
    },
    SignRound1Submit {
        session: String,
        id_hex: String,
        commitments_bincode_hex: String,
        signature_hex: String,
    },
    SignRound2Submit {
        session: String,
        id_hex: String,
        signature_share_bincode_hex: String,
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
        #[serde(rename = "suid")]
        user_id: u32,
        access_token: String,
    },

    // Interactive signing session events
    SignSessionCreated {
        session: String,
    },
    SignReadyRound1 {
        session: String,
        group_id: String,
        threshold: u16,
        participants: u16,
        msg_keccak32_hex: String,
        roster: Vec<(u32, String, RosterPublicKey)>,
    },
    SignSigningPackage {
        session: String,
        signing_package_bincode_hex: String,
    },
    SignatureReady {
        session: String,
        signature_bincode_hex: String,
        px: String,
        py: String,
        rx: String,
        ry: String,
        s: String,
        message: String,
    },
}

/// Command-line interface for the signing tool.
#[derive(Parser, Debug)]
#[command(
    name = "signing",
    about = "Run FROST(secp256k1) signing stages (per-participant)"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Roster key type for this client [secp256k1 | ed25519]
    #[arg(long, global = true, env = "ROSTER_KEY_TYPE")]
    key_type: Option<String>,

    /// Roster private key (32-byte hex) for this client
    #[arg(long, global = true, env = "ROSTER_PRIVATE_KEY")]
    private_key: Option<String>,
}

/// Subcommands covering each stage of the FROST signing flow.
#[derive(Subcommand, Debug)]
enum Commands {
    /// Round 1 (per participant): generate nonces & commitments for ONE signer.
    /// Provide that signer's share_*.json file. Produces one round1_<id>.json.
    Round1 {
        /// Path to *this participant's* share_*.json (from keygen)
        #[arg(long)]
        share: PathBuf,
        /// Output JSON path for round1. If omitted, defaults to <share_dir>/round1_<id>.json
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Round 2 (per participant): compute signature share using ALL participants' round1 files.
    /// Provide this signer's share_*.json and a directory of round1_*.json.
    Round2 {
        /// Path to *this participant's* share_*.json (from keygen)
        #[arg(long)]
        share: PathBuf,
        /// Directory containing per-participant round1_*.json files
        #[arg(long, default_value = "out")]
        round1_dir: PathBuf,
        /// Message to sign (ASCII). If prefixed with 0x, interpreted as hex bytes.
        #[arg(long)]
        message: String,
        /// Output JSON path for round2. If omitted, defaults to <round1_dir>/round2_<id>.json
        #[arg(long)]
        out: Option<PathBuf>,
        /// Optional map of long‑term public keys for authentication: "id_hex:pub1,id_hex:pub2,...".
        #[arg(long)]
        participants_pubs: Option<String>,
    },
    /// Aggregate: build final signature from a directory of per-participant round1 files
    /// and a directory of per-participant round2 files.
    Aggregate {
        /// Path to group.json from keygen
        #[arg(long, default_value = "out/group.json")]
        group: PathBuf,
        /// Directory containing per-participant round1_*.json files
        #[arg(long, default_value = "out")]
        round1_dir: PathBuf,
        /// Directory containing per-participant round2_*.json files
        #[arg(long, default_value = "out")]
        round2_dir: PathBuf,
        /// Output signature JSON
        #[arg(long, default_value = "out/signature.json")]
        out: PathBuf,
        /// Optional map of long‑term public keys for authentication: "id_hex:pub1,id_hex:pub2,...".
        #[arg(long)]
        participants_pubs: Option<String>,
    },
    /// Interactive signing over WebSocket with fserver.
    /// Creator: announces a session for (group, message, roster), others: join and participate.
    Ws {
        /// WebSocket URL, e.g. ws://127.0.0.1:9000/ws
        #[arg(long, default_value = "ws://127.0.0.1:9000/ws")]
        url: String,
        /// If set, this client creates the signing session
        #[arg(long, default_value_t = false)]
        create: bool,
        /// Group identifier label (creator)
        #[arg(long, default_value = "tokamak")]
        group_id: String,
        /// Threshold (creator)
        #[arg(long, default_value_t = 2)]
        threshold: u16,
        /// Comma-separated participant UIDs (creator)
        #[arg(long, default_value = "")]
        participants: String,
        /// Roster map uid:json_roster_pub_key,... (creator)
        #[arg(long, default_value = "")]
        participants_pubs: String,
        /// Group verifying key (compressed SEC1 hex) (creator)
        #[arg(long, default_value = "")]
        group_vk_sec1_hex: String,
        /// Message to sign (ASCII or 0xHEX) (creator)
        #[arg(long, default_value = "tokamak message to sign")]
        message: String,
        /// For all signers: path to this participant's share_*.json
        #[arg(long)]
        share: PathBuf,
        /// Optional explicit session id to join (if not creator)
        #[arg(long)]
        session: Option<String>,
        /// Optional file to persist/read the session id
        #[arg(long)]
        session_file: Option<PathBuf>,
        /// Output directory to write signature.json and logs
        #[arg(long, default_value = "out")]
        out_dir: PathBuf,
    },
}

/// Participant share file written by keygen/DKG. All bincode blobs are hex-encoded.
#[derive(Serialize, Deserialize, Clone)]
struct ShareFile {
    group_id: String,
    threshold: u16,
    participants: u16,
    signer_id_bincode_hex: String,
    secret_share_bincode_hex: String,
    verifying_share_bincode_hex: String,
    group_vk_sec1_hex: String,
    #[serde(default)]
    session: Option<String>,
}

/// Output file produced by `Round1` for a single participant.
#[derive(Serialize, Deserialize, Clone)]
struct Round1One {
    group_id: String,
    signer_id_bincode_hex: String,
    nonces_bincode_hex: String,
    commitments_bincode_hex: String,
    #[serde(default)]
    session: Option<String>,
    roster_pub_key: Option<RosterPublicKey>,
    auth_sig_hex: Option<String>,
}

/// Output file produced by `Round2` for a single participant.
#[derive(Serialize, Deserialize, Clone)]
struct Round2One {
    group_id: String,
    signer_id_bincode_hex: String,
    signature_share_bincode_hex: String,
    msg_plain_hex: String,
    msg_keccak32_hex: String,
    #[serde(default)]
    session: Option<String>,
    roster_pub_key: Option<RosterPublicKey>,
    auth_sig_hex: Option<String>,
}

/// Minimal group metadata (verifying key and thresholds) used by `Aggregate`.
#[derive(Serialize, Deserialize)]
struct GroupFile {
    group_id: String,
    threshold: u16,
    participants: u16,
    group_vk_sec1_hex: String,
    #[serde(default)]
    session: Option<String>,
}

/// Final signature object written by `Aggregate`, including human-friendly fields.
#[derive(Serialize, Deserialize)]
struct SignatureOut {
    group_id: String,
    signature_bincode_hex: String,
    px: String,
    py: String,
    rx: String,
    ry: String,
    s: String,
    message: String,
    #[serde(default)]
    session: Option<String>,
}

/// Read a JSON file and deserialize into `T`, attaching file path to any error.
fn read_json<P: AsRef<Path>, T: for<'de> serde::Deserialize<'de>>(path: P) -> Result<T> {
    let s = fs::read_to_string(&path)?;
    serde_json::from_str(&s).with_context(|| format!("parsing JSON {}", path.as_ref().display()))
}

/// Serialize `value` as pretty JSON to `path`, creating parent directories if needed.
fn write_json<P: AsRef<Path>, T: serde::Serialize>(path: P, value: &T) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() {
        fs::create_dir_all(parent)?;
    }
    let s = serde_json::to_string_pretty(value)?;
    fs::write(path, s)?;
    Ok(())
}

/// Parse a message string: if it starts with `0x`, treat as hex; otherwise use ASCII bytes.
fn parse_message_to_bytes(msg: &str) -> Result<Vec<u8>> {
    let stripped = msg.strip_prefix("0x").unwrap_or(msg);
    Ok(hex::decode(stripped)?)
}

/// Populate `vmap` with verifying shares for the `needed_ids` by scanning `dir` for `share_*.json`.
fn scan_dir_for_vshares(
    dir: &Path,
    needed_ids: &[frost::Identifier],
    vmap: &mut BTreeMap<frost::Identifier, frost::keys::VerifyingShare>,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if !p
            .file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("share_"))
        {
            continue;
        }
        let sf_one: ShareFile = match read_json(&p) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id: frost::Identifier =
            bincode::deserialize(&hex::decode(&sf_one.signer_id_bincode_hex)?)?;
        if needed_ids.contains(&id) && !vmap.contains_key(&id) {
            let vshare: frost::keys::VerifyingShare =
                bincode::deserialize(&hex::decode(&sf_one.verifying_share_bincode_hex)?)?;
            vmap.insert(id, vshare);
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let roster_sk = match (cli.key_type, cli.private_key) {
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
    }?;

    match cli.command {
        Commands::Round1 { share, out } => {
            let sf: ShareFile = read_json(&share)?;
            let secret_share: frost::keys::SecretShare =
                bincode::deserialize(&hex::decode(&sf.secret_share_bincode_hex)?)?;
            let id_hex = sf.signer_id_bincode_hex.clone();
            let mut rng = OsRng;
            let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
            let (nonces, commitments) =
                frost::round1::commit(key_package.signing_share(), &mut rng);

            let nonces_hex = hex::encode(bincode::serialize(&nonces)?);
            let commits_hex = hex::encode(bincode::serialize(&commitments)?);
            let mut r1 = Round1One {
                group_id: sf.group_id.clone(),
                signer_id_bincode_hex: id_hex.clone(),
                nonces_bincode_hex: nonces_hex.clone(),
                commitments_bincode_hex: commits_hex.clone(),
                session: sf.session.clone(),
                roster_pub_key: None,
                auth_sig_hex: None,
            };
            if let Some(sk) = roster_sk {
                let payload = auth_payload_signing_round1(
                    &r1.group_id,
                    &r1.signer_id_bincode_hex,
                    &nonces_hex,
                    &commits_hex,
                    r1.session.as_deref(),
                );
                let sig_hex = sk.sign(&payload);
                r1.roster_pub_key = Some(sk.public_key());
                r1.auth_sig_hex = Some(sig_hex);
            }
            let base_dir = share.parent().unwrap_or_else(|| Path::new("out"));
            let out_path = out.unwrap_or_else(|| {
                if let Some(sid) = sf.session.as_deref() {
                    base_dir.join(format!("round1_{}_{}.json", sid, id_hex))
                } else {
                    base_dir.join(format!("round1_{}.json", id_hex))
                }
            });
            write_json(&out_path, &r1)?;
            println!("Wrote {}", out_path.display());
        }

        Commands::Round2 {
            share,
            round1_dir,
            message,
            out,
            participants_pubs,
        } => {
            let sf: ShareFile = read_json(&share)?;
            let my_id_hex = sf.signer_id_bincode_hex.clone();
            let mut commitments_map: BTreeMap<
                frost::Identifier,
                frost::round1::SigningCommitments,
            > = BTreeMap::new();
            let mut my_nonces: Option<frost::round1::SigningNonces> = None;
            for entry in fs::read_dir(&round1_dir)? {
                let p = entry?.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let r1: Round1One = match read_json(&p) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let id: frost::Identifier =
                    bincode::deserialize(&hex::decode(&r1.signer_id_bincode_hex)?)?;
                let commitments: frost::round1::SigningCommitments =
                    bincode::deserialize(&hex::decode(&r1.commitments_bincode_hex)?)?;
                commitments_map.insert(id, commitments);
                if r1.signer_id_bincode_hex == my_id_hex {
                    let n: frost::round1::SigningNonces =
                        bincode::deserialize(&hex::decode(&r1.nonces_bincode_hex)?)?;
                    my_nonces = Some(n);
                }
            }
            let auth_map = if let Some(s) = participants_pubs.as_ref() {
                parse_participants_pubs_map(s)?
            } else {
                BTreeMap::new()
            };
            for entry in fs::read_dir(&round1_dir)? {
                let p = entry?.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let r1: Round1One = match read_json(&p) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let (Some(pub_key), Some(sig_hex)) = (&r1.roster_pub_key, &r1.auth_sig_hex) {
                    if let Some(expected_pub_str) = auth_map.get(&r1.signer_id_bincode_hex) {
                        let expected_pub: RosterPublicKey = serde_json::from_str(expected_pub_str)?;
                        if &expected_pub != pub_key {
                            return Err(anyhow!(
                                "Round1 pub mismatch for id {}",
                                r1.signer_id_bincode_hex
                            ));
                        }
                    }
                    let payload = auth_payload_signing_round1(
                        &r1.group_id,
                        &r1.signer_id_bincode_hex,
                        &r1.nonces_bincode_hex,
                        &r1.commitments_bincode_hex,
                        r1.session.as_deref(),
                    );
                    pub_key.verify(&payload, sig_hex)?;
                }
            }
            let my_nonces = my_nonces.ok_or_else(|| {
                anyhow!(
                    "could not find round1 for this participant in {}",
                    round1_dir.display()
                )
            })?;
            if commitments_map.len() < sf.threshold as usize {
                return Err(anyhow!(
                    "not enough commitments: have {}, need at least {}",
                    commitments_map.len(),
                    sf.threshold
                ));
            }
            let msg_bytes = parse_message_to_bytes(&message)?;
            let msg32 = Keccak256::digest(&msg_bytes);
            let signing_package = frost::SigningPackage::new(commitments_map, msg32.as_slice());
            let secret_share: frost::keys::SecretShare =
                bincode::deserialize(&hex::decode(&sf.secret_share_bincode_hex)?)?;
            let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
            let sig_share = frost::round2::sign(&signing_package, &my_nonces, &key_package)?;
            let sigshare_hex = hex::encode(bincode::serialize(&sig_share)?);
            let msg32_hex = format!("0x{}", hex::encode(msg32));
            let mut r2 = Round2One {
                group_id: sf.group_id.clone(),
                signer_id_bincode_hex: my_id_hex.clone(),
                signature_share_bincode_hex: sigshare_hex.clone(),
                msg_plain_hex: format!("0x{}", hex::encode(&msg_bytes)),
                msg_keccak32_hex: msg32_hex.clone(),
                session: sf.session.clone(),
                roster_pub_key: None,
                auth_sig_hex: None,
            };
            if let Some(sk) = roster_sk {
                let payload = auth_payload_signing_round2(
                    &r2.group_id,
                    &r2.signer_id_bincode_hex,
                    &sigshare_hex,
                    &msg32_hex,
                    r2.session.as_deref(),
                );
                let sig_hex = sk.sign(&payload);
                r2.roster_pub_key = Some(sk.public_key());
                r2.auth_sig_hex = Some(sig_hex);
            }
            let base_dir = &round1_dir;
            let out_path = out.unwrap_or_else(|| {
                if let Some(sid) = sf.session.as_deref() {
                    base_dir.join(format!("round2_{}_{}.json", sid, my_id_hex))
                } else {
                    base_dir.join(format!("round2_{}.json", my_id_hex))
                }
            });
            write_json(&out_path, &r2)?;
            println!("Wrote {}", out_path.display());
        }

        Commands::Aggregate {
            group,
            round1_dir,
            round2_dir,
            out,
            participants_pubs,
        } => {
            let g: GroupFile = read_json(&group)?;
            let target_session_from_group = g.session.clone();
            let mut commitments_map: BTreeMap<
                frost::Identifier,
                frost::round1::SigningCommitments,
            > = BTreeMap::new();
            let mut target_session: Option<String> = None;
            for entry in fs::read_dir(&round1_dir)? {
                let p = entry?.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let r1: Round1One = match read_json(&p) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some(s) = r1.session.clone() {
                    if let Some(ts) = target_session.clone() {
                        if ts != s {
                            return Err(anyhow!("session mismatch among Round1 files"));
                        }
                    } else {
                        target_session = Some(s);
                    }
                }
                let id: frost::Identifier =
                    bincode::deserialize(&hex::decode(&r1.signer_id_bincode_hex)?)?;
                let commitments: frost::round1::SigningCommitments =
                    bincode::deserialize(&hex::decode(&r1.commitments_bincode_hex)?)?;
                commitments_map.insert(id, commitments);
            }
            let auth_map = if let Some(s) = participants_pubs.as_ref() {
                parse_participants_pubs_map(s)?
            } else {
                BTreeMap::new()
            };
            for entry in fs::read_dir(&round1_dir)? {
                let p = entry?.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let r1: Round1One = match read_json(&p) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let (Some(pub_key), Some(sig_hex)) = (&r1.roster_pub_key, &r1.auth_sig_hex) {
                    if let Some(expected_pub_str) = auth_map.get(&r1.signer_id_bincode_hex) {
                        let expected_pub: RosterPublicKey = serde_json::from_str(expected_pub_str)?;
                        if &expected_pub != pub_key {
                            return Err(anyhow!(
                                "Round1 pub mismatch for id {}",
                                r1.signer_id_bincode_hex
                            ));
                        }
                    }
                    let payload = auth_payload_signing_round1(
                        &r1.group_id,
                        &r1.signer_id_bincode_hex,
                        &r1.nonces_bincode_hex,
                        &r1.commitments_bincode_hex,
                        r1.session.as_deref(),
                    );
                    pub_key.verify(&payload, sig_hex)?;
                }
            }
            if commitments_map.is_empty() {
                return Err(anyhow!(
                    "no round1_*.json files found in {}",
                    round1_dir.display()
                ));
            }

            let mut sig_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare> =
                BTreeMap::new();
            let mut msg_hex: Option<String> = None;
            for entry in fs::read_dir(&round2_dir)? {
                let p = entry?.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let r2: Round2One = match read_json(&p) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if let Some(prev) = &msg_hex {
                    if *prev != r2.msg_keccak32_hex {
                        return Err(anyhow!("mismatched msg_keccak32 across round2 files"));
                    }
                } else {
                    msg_hex = Some(r2.msg_keccak32_hex.clone());
                }
                if let Some(s) = r2.session.clone() {
                    if let Some(ts) = target_session.clone() {
                        if ts != s {
                            return Err(anyhow!("session mismatch among Round2 files"));
                        }
                    } else {
                        target_session = Some(s);
                    }
                }
                let id: frost::Identifier =
                    bincode::deserialize(&hex::decode(&r2.signer_id_bincode_hex)?)?;
                let sshare: frost::round2::SignatureShare =
                    bincode::deserialize(&hex::decode(&r2.signature_share_bincode_hex)?)?;
                sig_shares.insert(id, sshare);
            }
            if let Some(gs) = target_session_from_group.as_ref() {
                if let Some(ts) = target_session.as_ref() {
                    if gs != ts {
                        return Err(anyhow!("group.json session does not match rounds session"));
                    }
                } else {
                    target_session = Some(gs.clone());
                }
            }
            if sig_shares.is_empty() {
                return Err(anyhow!(
                    "no round2_*.json files found in {}",
                    round2_dir.display()
                ));
            }

            let msg32 = if let Some(h) = msg_hex.expect("message").strip_prefix("0x") {
                hex::decode(h)?
            } else {
                unreachable!()
            };
            let group_vk_bytes = hex::decode(&g.group_vk_sec1_hex)?;
            let group_vk = frost::VerifyingKey::deserialize(&group_vk_bytes)
                .map_err(|e| anyhow!("group verifying key deserialize failed: {e}"))?;
            let needed_ids: Vec<frost::Identifier> = sig_shares.keys().cloned().collect();
            let mut vmap: BTreeMap<frost::Identifier, frost::keys::VerifyingShare> =
                BTreeMap::new();
            scan_dir_for_vshares(&round1_dir, &needed_ids, &mut vmap)?;
            if vmap.len() < needed_ids.len() {
                if let Some(gdir) = group.parent() {
                    scan_dir_for_vshares(gdir, &needed_ids, &mut vmap)?;
                }
            }
            if vmap.len() < needed_ids.len() {
                return Err(anyhow!("missing verifying shares for some participants"));
            }

            let pubkey_package = frost::keys::PublicKeyPackage::new(vmap, group_vk);
            let signing_package = frost::SigningPackage::new(commitments_map, &msg32);
            let sig = frost::aggregate(&signing_package, &sig_shares, &pubkey_package)?;

            let vk_sec1 = hex::decode(&g.group_vk_sec1_hex)?;
            let vk_parsed = PublicKey::from_sec1_bytes(&vk_sec1)?;
            let vk_unc = vk_parsed.to_encoded_point(false);
            let px = format!("0x{}", hex::encode(vk_unc.x().expect("x")));
            let py = format!("0x{}", hex::encode(vk_unc.y().expect("y")));
            let r_aff = sig.R().to_affine();
            let r_pt = r_aff.to_encoded_point(false);
            let rx = format!("0x{}", hex::encode(r_pt.x().expect("x")));
            let ry = format!("0x{}", hex::encode(r_pt.y().expect("y")));
            let s_hex = {
                let z_bytes = frost::Secp256K1ScalarField::serialize(sig.z());
                format!("0x{}", hex::encode(z_bytes))
            };

            let out_obj = SignatureOut {
                group_id: g.group_id,
                signature_bincode_hex: hex::encode(bincode::serialize(&sig)?),
                px,
                py,
                rx,
                ry,
                s: s_hex,
                message: format!("0x{}", hex::encode(msg32)),
                session: target_session,
            };
            write_json(out, &out_obj)?;
            println!("Wrote signature.json");
        }

        Commands::Ws {
            url,
            create,
            group_id,
            threshold,
            participants,
            participants_pubs,
            group_vk_sec1_hex,
            message,
            share,
            session,
            session_file,
            out_dir,
        } => {
            let sf: ShareFile = read_json(&share)?;
            let my_id_hex = sf.signer_id_bincode_hex.clone();
            let _my_id: frost::Identifier = bincode::deserialize(&hex::decode(&my_id_hex)?)?;

            let roster_sk = roster_sk.ok_or_else(|| {
                anyhow!("Roster key must be provided for WebSocket mode via CLI or env vars")
            })?;
            let roster_pk = roster_sk.public_key();

            let (ws_stream, _) = connect_async(&url).await.context("connect ws")?;
            let (mut write, mut read) = ws_stream.split();

            macro_rules! send_json_ws {
                ($m:expr) => {{
                    let s = serde_json::to_string(&$m)?;
                    write.send(WsMsg::Text(s)).await?;
                }};
            }

            send_json_ws!(ClientMsg::RequestChallenge);

            let mut session_id: Option<String> = session.map(|s| s.trim().to_string());
            let session_file_path =
                session_file.unwrap_or_else(|| out_dir.join("sign_session.txt"));
            if !create && session_id.is_none() {
                if let Ok(s) = fs::read_to_string(&session_file_path) {
                    let st = s.trim().to_string();
                    if !st.is_empty() {
                        session_id = Some(st);
                    }
                }
            }

            let secret_share: frost::keys::SecretShare =
                bincode::deserialize(&hex::decode(&sf.secret_share_bincode_hex)?)?;
            let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
            let mut rng = OsRng;
            let mut my_nonces_opt: Option<frost::round1::SigningNonces> = None;

            while let Some(msg) = read.next().await {
                if let WsMsg::Text(txt) = msg? {
                    let smsg: ServerMsg = serde_json::from_str(&txt)?;
                    match smsg {
                        ServerMsg::Error { message } => {
                            return Err(anyhow!("server error: {message}"))
                        }
                        ServerMsg::SignSessionCreated { session } => {
                            fs::create_dir_all(&out_dir)?;
                            fs::write(&session_file_path, &session)?;
                            session_id = Some(session.clone());
                            send_json_ws!(ClientMsg::JoinSignSession {
                                session,
                                signer_id_bincode_hex: my_id_hex.clone(),
                                verifying_share_bincode_hex: sf.verifying_share_bincode_hex.clone(),
                            });
                        }
                        ServerMsg::Challenge { challenge } => {
                            let uuid =
                                uuid::Uuid::parse_str(&challenge).context("challenge uuid")?;
                            let sig_hex = roster_sk.sign(uuid.as_bytes());
                            send_json_ws!(ClientMsg::Login {
                                challenge,
                                public_key: roster_pk.clone(),
                                signature_hex: sig_hex
                            });
                        }
                        ServerMsg::LoginOk { user_id, .. } => {
                            println!("[ws] logged in as uid {user_id}");
                            if create {
                                let parts: Vec<u32> = participants
                                    .split(',')
                                    .filter(|s| !s.is_empty())
                                    .map(|s| s.trim().parse::<u32>().expect("uid u32"))
                                    .collect();
                                let pubs: Vec<(u32, RosterPublicKey)> = participants_pubs
                                    .split('|')
                                    .filter(|s| !s.is_empty())
                                    .map(|kv| {
                                        let (u, p) = kv.split_once(";;;").expect("uid;;;pub");
                                        (
                                            u.trim().parse::<u32>().expect("uid"),
                                            serde_json::from_str(p)
                                                .expect("valid RosterPublicKey JSON"),
                                        )
                                    })
                                    .collect();
                                let msg_bytes = {
                                    let stripped = message.trim_start_matches("0x");
                                    hex::decode(stripped).context("message must be valid hex")?
                                };
                                let msg_hex = if msg_bytes.len() == 32 {
                                    format!("0x{}", hex::encode(&msg_bytes))
                                } else {
                                    let digest = Keccak256::digest(&msg_bytes);
                                    format!("0x{}", hex::encode(digest))
                                };
                                send_json_ws!(ClientMsg::AnnounceSignSession {
                                    group_id: group_id.clone(),
                                    threshold,
                                    participants: parts,
                                    participants_pubs: pubs,
                                    group_vk_sec1_hex: group_vk_sec1_hex.clone(),
                                    message: message.clone(),
                                    message_hex: msg_hex,
                                });
                            } else {
                                if session_id.is_none() {
                                    println!("[ws] waiting for session file...");
                                    for _ in 0..50 {
                                        if let Ok(s) = fs::read_to_string(&session_file_path) {
                                            let st = s.trim().to_string();
                                            if !st.is_empty() {
                                                session_id = Some(st);
                                                break;
                                            }
                                        }
                                        tokio::time::sleep(std::time::Duration::from_millis(100))
                                            .await;
                                    }
                                }
                                let sid = session_id
                                    .clone()
                                    .ok_or_else(|| anyhow!("no session id yet"))?;
                                send_json_ws!(ClientMsg::JoinSignSession {
                                    session: sid,
                                    signer_id_bincode_hex: my_id_hex.clone(),
                                    verifying_share_bincode_hex: sf
                                        .verifying_share_bincode_hex
                                        .clone(),
                                });
                            }
                        }
                        ServerMsg::SignReadyRound1 {
                            session,
                            group_id: gid,
                            ..
                        } => {
                            println!("[ws] Received SignReadyRound1 for session {}", session);
                            if Some(&session) != session_id.as_ref() {
                                println!(
                                    "[ws] Ignored SignReadyRound1 (session mismatch: {:?} vs {:?})",
                                    session, session_id
                                );
                                continue;
                            }
                            let (nonces, commitments) =
                                frost::round1::commit(key_package.signing_share(), &mut rng);
                            let commits_hex = hex::encode(bincode::serialize(&commitments)?);
                            my_nonces_opt = Some(nonces);
                            println!("[ws] Generated nonces");
                            let sid = session_id.clone().unwrap();
                            let payload =
                                auth_payload_sign_r1(&sid, &gid, &my_id_hex, &commits_hex);
                            let sig_hex = roster_sk.sign(&payload);
                            send_json_ws!(ClientMsg::SignRound1Submit {
                                session: sid,
                                id_hex: my_id_hex.clone(),
                                commitments_bincode_hex: commits_hex,
                                signature_hex: sig_hex
                            });
                        }
                        ServerMsg::SignSigningPackage {
                            session,
                            signing_package_bincode_hex,
                        } => {
                            println!("[ws] Received SignSigningPackage for session {}", session);
                            if Some(&session) != session_id.as_ref() {
                                continue;
                            }
                            let sp: frost::SigningPackage =
                                bincode::deserialize(&hex::decode(&signing_package_bincode_hex)?)?;
                            let my_nonces = my_nonces_opt
                                .take()
                                .ok_or_else(|| anyhow!("missing my nonces"))?;
                            let sig_share = frost::round2::sign(&sp, &my_nonces, &key_package)?;
                            let sigshare_hex = hex::encode(bincode::serialize(&sig_share)?);
                            let gid = group_id.clone();
                            let msg32_hex = format!("0x{}", hex::encode(sp.message()));
                            let sid = session_id.clone().unwrap();
                            let payload = auth_payload_sign_r2(
                                &sid,
                                &gid,
                                &my_id_hex,
                                &sigshare_hex,
                                &msg32_hex,
                            );
                            let sig_hex = roster_sk.sign(&payload);
                            send_json_ws!(ClientMsg::SignRound2Submit {
                                session: sid,
                                id_hex: my_id_hex.clone(),
                                signature_share_bincode_hex: sigshare_hex,
                                signature_hex: sig_hex
                            });
                        }
                        ServerMsg::SignatureReady {
                            session,
                            signature_bincode_hex,
                            px,
                            py,
                            rx,
                            ry,
                            s,
                            message,
                        } => {
                            if Some(&session) != session_id.as_ref() {
                                continue;
                            }
                            let pxb = hex::decode(px.trim_start_matches("0x"))?;
                            let pyb = hex::decode(py.trim_start_matches("0x"))?;
                            let mut vk_un = [0u8; 65];
                            vk_un[0] = 0x04;
                            vk_un[1..33].copy_from_slice(&pxb);
                            vk_un[33..65].copy_from_slice(&pyb);
                            let ep = k256::EncodedPoint::from_bytes(vk_un)?;
                            let affine = k256::AffinePoint::from_encoded_point(&ep).unwrap();
                            let compressed = affine.to_encoded_point(true);
                            let vk = frost::VerifyingKey::deserialize(compressed.as_bytes())?;
                            let sig: frost::Signature =
                                bincode::deserialize(&hex::decode(&signature_bincode_hex)?)?;
                            let m = hex::decode(message.trim_start_matches("0x"))?;
                            let mut m32 = [0u8; 32];
                            m32.copy_from_slice(&m);
                            let ok = vk.verify(&m32, &sig).is_ok();
                            fs::create_dir_all(&out_dir)?;
                            let out = SignatureOut {
                                group_id: group_id.clone(),
                                signature_bincode_hex: hex::encode(bincode::serialize(&sig)?),
                                px,
                                py,
                                rx,
                                ry,
                                s,
                                message,
                                session: session_id.clone(),
                            };
                            write_json(out_dir.join("signature.json"), &out)?;
                            println!("[ws] Signature verify: {}", ok);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    Ok(())
}
