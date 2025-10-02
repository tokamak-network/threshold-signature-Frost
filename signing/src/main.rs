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
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use futures::{sink::SinkExt, stream::StreamExt};
use frost_core::Field;
use frost_secp256k1 as frost;
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::ecdsa::{
    signature::{DigestSigner, DigestVerifier},
    Signature as EcdsaSignature,
    SigningKey as EcdsaSigningKey,
    VerifyingKey as EcdsaVerifyingKey,
};
use k256::PublicKey;
use k256::FieldBytes;
use k256::Scalar;
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
    Login { challenge: String, pubkey_hex: String, signature_hex: String },

    // Interactive signing session control
    AnnounceSignSession {
        group_id: String,
        threshold: u16,
        participants: Vec<u32>,
        participants_pubs: Vec<(u32, String)>,
        group_vk_sec1_hex: String,
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
        sig_ecdsa_hex: String,
    },
    SignRound2Submit {
        session: String,
        id_hex: String,
        signature_share_bincode_hex: String,
        sig_ecdsa_hex: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
enum ServerMsg {
    Error { message: String },
    Info { message: String },
    Challenge { challenge: String },
    LoginOk { user_id: u32, access_token: String },

    // Interactive signing session events
    SignSessionCreated { session: String },
    SignReadyRound1 {
        session: String,
        group_id: String,
        threshold: u16,
        participants: u16,
        msg_keccak32_hex: String,
        // (uid, id_hex, ecdsa_pub_sec1_hex)
        roster: Vec<(u32, String, String)>,
    },
    SignSigningPackage { session: String, signing_package_bincode_hex: String },
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

// Additional auth helpers for the interactive signing WS flow
fn auth_payload_sign_r1(session: &str, group_id: &str, id_hex: &str, commits_hex: &str) -> Vec<u8> {
    format!("SIGN_WS_R1|{}|{}|{}|{}", session, group_id, id_hex, commits_hex).into_bytes()
}
fn auth_payload_sign_r2(session: &str, group_id: &str, id_hex: &str, sigshare_hex: &str, msg32_hex: &str) -> Vec<u8> {
    format!("SIGN_WS_R2|{}|{}|{}|{}|{}", session, group_id, id_hex, sigshare_hex, msg32_hex).into_bytes()
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
        /// Optional map of long‑term ECDSA public keys for authentication: "id_hex:pub1,id_hex:pub2,...".
        /// Each id_hex is the *bincode-hex* of the signer id (as in share_*.json). If omitted,
        /// signatures are still checked against the embedded pubkey, but not bound to an external map.
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
        /// Optional map of long‑term ECDSA public keys for authentication: "id_hex:pub1,id_hex:pub2,...".
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
        /// Roster map uid:ecdsa_pub_sec1_hex,... (creator)
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
    /// Optional session id (UUID) to disambiguate across concurrent DKGs
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
    /// Optional session id (UUID) to disambiguate across concurrent DKGs
    #[serde(default)]
    session: Option<String>,
    /// Optional ECDSA(sec1) pubkey hex for source authentication (compressed 33-byte SEC1)
    #[serde(default)]
    ecdsa_pub_sec1_hex: Option<String>,
    /// Optional compact ECDSA signature (64-byte r||s hex) over Keccak256(payload)
    /// where payload =
    ///   with session:   "signing:R1|session|group_id|signer_id_bincode_hex|nonces_bincode_hex|commitments_bincode_hex"
    ///   without:        "signing:R1|group_id|signer_id_bincode_hex|nonces_bincode_hex|commitments_bincode_hex"
    #[serde(default)]
    ecdsa_sig_keccak_hex: Option<String>,
}

/// Output file produced by `Round2` for a single participant.
#[derive(Serialize, Deserialize, Clone)]
struct Round2One {
    group_id: String,
    signer_id_bincode_hex: String,
    signature_share_bincode_hex: String,
    msg_plain_hex: String,
    msg_keccak32_hex: String,
    /// Optional session id (UUID) to disambiguate across concurrent DKGs
    #[serde(default)]
    session: Option<String>,
    /// Optional ECDSA(sec1) pubkey hex for source authentication (compressed 33-byte SEC1)
    #[serde(default)]
    ecdsa_pub_sec1_hex: Option<String>,
    /// Optional compact ECDSA signature (64-byte r||s) over Keccak256(payload)
    /// where payload =
    ///   with session:   "signing:R2|session|group_id|signer_id_bincode_hex|signature_share_bincode_hex|msg_keccak32_hex"
    ///   without:        "signing:R2|group_id|signer_id_bincode_hex|signature_share_bincode_hex|msg_keccak32_hex"
    #[serde(default)]
    ecdsa_sig_keccak_hex: Option<String>,
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
    // Human-friendly fields
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
    Ok(serde_json::from_str(&s)
        .with_context(|| format!("parsing JSON {}", path.as_ref().display()))?)
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

/// Read an ECDSA signing key from env. Checks SIGNING_ECDSA_PRIV_HEX then DKG_ECDSA_PRIV_HEX.
/// Returns (SigningKey, compressed SEC1 pub hex) if present, otherwise Ok(None).
fn read_ecdsa_signing_key_from_env() -> Result<Option<(EcdsaSigningKey, String)>> {
    {
        let sk_hex = env::var("SIGNING_ECDSA_PRIV_HEX")
            .ok()
            .or_else(|| env::var("DKG_ECDSA_PRIV_HEX").ok());
        let Some(sk_hex) = sk_hex else { return Ok(None); };
        let bytes = hex::decode(sk_hex.trim())?;
        if bytes.len() != 32 {
            return Err(anyhow!("ECDSA priv must be 32 bytes (hex)"));
        }
        // Build a concrete FieldBytes (32 bytes) and create an ECDSA SigningKey.
        let fb = FieldBytes::from_slice(&bytes);
        let sk = EcdsaSigningKey::from_bytes(&fb)
            .map_err(|_| anyhow!("invalid ECDSA private key bytes"))?;
        let vk = EcdsaVerifyingKey::from(&sk);
        let pub_hex = hex::encode(vk.to_encoded_point(true).as_bytes());
        Ok(Some((sk, pub_hex)))
    }
}

/// Build the Round1 authentication payload from its fields (excluding auth fields).
fn auth_payload_round1(group_id: &str, id_hex: &str, nonces_hex: &str, commits_hex: &str, session: Option<&str>) -> Vec<u8> {
    if let Some(sid) = session {
        format!("signing:R1|{}|{}|{}|{}|{}", sid, group_id, id_hex, nonces_hex, commits_hex).into_bytes()
    } else {
        format!("signing:R1|{}|{}|{}|{}", group_id, id_hex, nonces_hex, commits_hex).into_bytes()
    }
}

/// Build the Round2 authentication payload from its fields (excluding auth fields).
fn auth_payload_round2(group_id: &str, id_hex: &str, sigshare_hex: &str, msg32_hex: &str, session: Option<&str>) -> Vec<u8> {
    if let Some(sid) = session {
        format!("signing:R2|{}|{}|{}|{}|{}", sid, group_id, id_hex, sigshare_hex, msg32_hex).into_bytes()
    } else {
        format!("signing:R2|{}|{}|{}|{}", group_id, id_hex, sigshare_hex, msg32_hex).into_bytes()
    }
}

/// Verify a compact ECDSA signature (r||s) over Keccak256(payload) against a compressed SEC1 pub hex.
fn verify_ecdsa_keccak(payload: &[u8], pub_sec1_hex: &str, sig_hex: &str) -> Result<()> {
    let pub_bytes = hex::decode(pub_sec1_hex)?;
    let vk = EcdsaVerifyingKey::from_sec1_bytes(&pub_bytes)
        .map_err(|e| anyhow!("bad ECDSA pub: {e}"))?;
    let sig_bytes = hex::decode(sig_hex)?;
    let sig = EcdsaSignature::from_slice(&sig_bytes)
        .map_err(|_| anyhow!("bad ECDSA signature bytes"))?;
    let hasher = Keccak256::new().chain_update(payload);
    vk.verify_digest(hasher, &sig)
        .map_err(|_| anyhow!("ECDSA signature verification failed"))
}

/// Parse a participants pub map string `id:pub,id:pub,...`. `id` may be the exact
/// bincode-hex signer id or a small decimal (1..n), which will be converted to bincode-hex.
fn parse_participants_pubs_map(s: &str) -> Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    if s.trim().is_empty() { return Ok(out); }
    for pair in s.split(',') {
        let (id_raw, pub_hex) = pair.split_once(':')
            .ok_or_else(|| anyhow!("invalid participants-pubs entry (missing colon): {pair}"))?;
        let id_key = if id_raw.chars().all(|c| c.is_ascii_hexdigit()) && id_raw.len() > 2 {
            id_raw.to_string()
        } else {
            // try parse as integer index
            let idx: u16 = id_raw.trim().parse()
                .map_err(|_| anyhow!("invalid id '{id_raw}', expected hex or integer"))?;
            let sc = Scalar::from(idx as u64);
            let ident = frost::Identifier::new(sc).expect("invalid identifier index: {idx}");
            hex::encode(bincode::serialize(&ident)?)
        };
        out.insert(id_key, pub_hex.to_string());
    }
    Ok(out)
}

/// Parse a message string: if it starts with `0x`, treat as hex; otherwise use ASCII bytes.
fn parse_message_to_bytes(msg: &str) -> Result<Vec<u8>> {
    if let Some(stripped) = msg.strip_prefix("0x") {
        Ok(hex::decode(stripped)?)
    } else {
        Ok(msg.as_bytes().to_vec())
    }
}

/// Populate `vmap` with verifying shares for the `needed_ids` by scanning `dir` for `share_*.json`.
/// This is used during aggregation to reconstruct the `PublicKeyPackage` when only `group.json`
/// and Round files are present.
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
            .map(|s| s.starts_with("share_"))
            .unwrap_or(false)
        {
            continue;
        }
        let sf_one: ShareFile = match read_json(&p) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id: frost::Identifier =
            bincode::deserialize(&hex::decode(&sf_one.signer_id_bincode_hex)?)?;
        if needed_ids.iter().any(|x| *x == id) && !vmap.contains_key(&id) {
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

    match cli.command {
        Commands::Round1 { share, out } => {
            let sf: ShareFile = read_json(&share)?;
            // Decode our secret share and identifier from the share file.
            let secret_share: frost::keys::SecretShare =
                bincode::deserialize(&hex::decode(&sf.secret_share_bincode_hex)?)?;
            let id_hex = sf.signer_id_bincode_hex.clone();
            let _id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;

            // Build a KeyPackage to access our signing share (private scalar).
            let mut rng = OsRng;
            let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
            // Generate ephemeral nonces and their public commitments for this signing session.
            let (nonces, commitments) =
                frost::round1::commit(key_package.signing_share(), &mut rng);

            // Persist Round1 output for THIS participant, with optional ECDSA authentication.
            let nonces_hex = hex::encode(bincode::serialize(&nonces)?);
            let commits_hex = hex::encode(bincode::serialize(&commitments)?);
            let mut r1 = Round1One {
                group_id: sf.group_id.clone(),
                signer_id_bincode_hex: id_hex.clone(),
                nonces_bincode_hex: nonces_hex.clone(),
                commitments_bincode_hex: commits_hex.clone(),
                session: sf.session.clone(),
                ecdsa_pub_sec1_hex: None,
                ecdsa_sig_keccak_hex: None,
            };
            if let Some((sk, pub_hex)) = read_ecdsa_signing_key_from_env()? {
                let payload = auth_payload_round1(&r1.group_id, &r1.signer_id_bincode_hex, &nonces_hex, &commits_hex, r1.session.as_deref());
                let sig: EcdsaSignature = sk.sign_digest(Keccak256::new().chain_update(&payload));
                r1.ecdsa_pub_sec1_hex = Some(pub_hex);
                r1.ecdsa_sig_keccak_hex = Some(hex::encode(sig.to_bytes()));
            }
            let base_dir = share.parent().unwrap_or_else(|| Path::new("out"));
            let out_path = out
                .clone()
                .unwrap_or_else(|| {
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
            // Identify ourselves and collect ALL participants' Round1 files.
            let my_id_hex = sf.signer_id_bincode_hex.clone();
            let _my_id: frost::Identifier = bincode::deserialize(&hex::decode(&my_id_hex)?)?;

            // Build the commitments map {id -> SigningCommitments} and find OUR nonces.
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
            // Optional authentication: verify ECDSA signatures on Round1 files.
            let auth_map = if let Some(s) = participants_pubs.as_ref() {
                parse_participants_pubs_map(s)?
            } else {
                BTreeMap::new()
            };
            for entry in fs::read_dir(&round1_dir)? {
                let p = entry?.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
                let r1: Round1One = match read_json(&p) { Ok(v) => v, Err(_) => continue };
                if let (Some(pub_hex), Some(sig_hex)) = (&r1.ecdsa_pub_sec1_hex, &r1.ecdsa_sig_keccak_hex) {
                    // If an external map is provided, ensure the pub matches the expected for this id.
                    if let Some(expected_pub) = auth_map.get(&r1.signer_id_bincode_hex) {
                        if expected_pub.trim().to_lowercase() != pub_hex.trim().to_lowercase() {
                            return Err(anyhow!("Round1 pub mismatch for id {}", r1.signer_id_bincode_hex));
                        }
                    }
                    let payload = auth_payload_round1(&r1.group_id, &r1.signer_id_bincode_hex, &r1.nonces_bincode_hex, &r1.commitments_bincode_hex, r1.session.as_deref());
                    verify_ecdsa_keccak(&payload, pub_hex, sig_hex)?;
                }
            }
            let my_nonces = my_nonces.ok_or_else(|| {
                anyhow!(
                    "could not find round1 for this participant in {}",
                    round1_dir.display()
                )
            })?;

            // Sanity check: ensure at least `t` participants are present.
            if commitments_map.len() < sf.threshold as usize {
                return Err(anyhow!(
                    "not enough commitments: have {}, need at least {}",
                    commitments_map.len(),
                    sf.threshold
                ));
            }

            // Build the message digest: Keccak-256(message-bytes).
            let msg_bytes = parse_message_to_bytes(&message)?;
            let msg32 = Keccak256::digest(&msg_bytes);

            // Bundle (commitments, message) for Round2 signing.
            let signing_package = frost::SigningPackage::new(commitments_map, msg32.as_slice());

            // Rebuild our KeyPackage from the secret share in the share file.
            let secret_share: frost::keys::SecretShare =
                bincode::deserialize(&hex::decode(&sf.secret_share_bincode_hex)?)?;
            let key_package = frost::keys::KeyPackage::try_from(secret_share)?;

            // Compute OUR signature share.
            let sig_share = frost::round2::sign(&signing_package, &my_nonces, &key_package)?;

            // Persist Round2 output for THIS participant, with optional ECDSA authentication.
            let sigshare_hex = hex::encode(bincode::serialize(&sig_share)?);
            let msg32_hex = format!("0x{}", hex::encode(msg32));
            let mut r2 = Round2One {
                group_id: sf.group_id.clone(),
                signer_id_bincode_hex: my_id_hex.clone(),
                signature_share_bincode_hex: sigshare_hex.clone(),
                msg_plain_hex: format!("0x{}", hex::encode(&msg_bytes)),
                msg_keccak32_hex: msg32_hex.clone(),
                session: sf.session.clone(),
                ecdsa_pub_sec1_hex: None,
                ecdsa_sig_keccak_hex: None,
            };
            if let Some((sk, pub_hex)) = read_ecdsa_signing_key_from_env()? {
                let payload = auth_payload_round2(&r2.group_id, &r2.signer_id_bincode_hex, &sigshare_hex, &msg32_hex, r2.session.as_deref());
                let sig: EcdsaSignature = sk.sign_digest(Keccak256::new().chain_update(&payload));
                r2.ecdsa_pub_sec1_hex = Some(pub_hex);
                r2.ecdsa_sig_keccak_hex = Some(hex::encode(sig.to_bytes()));
            }
            let base_dir = &round1_dir;
            let out_path = out
                .clone()
                .unwrap_or_else(|| {
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
            // 1) Collect all Round1 commitments.
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
                    if let Some(ts) = target_session.clone() { if ts != s { return Err(anyhow!("session mismatch among Round1 files")); } } else { target_session = Some(s); }
                }
                let id: frost::Identifier =
                    bincode::deserialize(&hex::decode(&r1.signer_id_bincode_hex)?)?;
                let commitments: frost::round1::SigningCommitments =
                    bincode::deserialize(&hex::decode(&r1.commitments_bincode_hex)?)?;
                commitments_map.insert(id, commitments);
            }
            // Optional authentication: verify ECDSA signatures on Round1 files.
            let auth_map = if let Some(s) = participants_pubs.as_ref() {
                parse_participants_pubs_map(s)?
            } else {
                BTreeMap::new()
            };
            for entry in fs::read_dir(&round1_dir)? {
                let p = entry?.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
                let r1: Round1One = match read_json(&p) { Ok(v) => v, Err(_) => continue };
                if let (Some(pub_hex), Some(sig_hex)) = (&r1.ecdsa_pub_sec1_hex, &r1.ecdsa_sig_keccak_hex) {
                    if let Some(expected_pub) = auth_map.get(&r1.signer_id_bincode_hex) {
                        if expected_pub.trim().to_lowercase() != pub_hex.trim().to_lowercase() {
                            return Err(anyhow!("Round1 pub mismatch for id {}", r1.signer_id_bincode_hex));
                        }
                    }
                    let payload = auth_payload_round1(&r1.group_id, &r1.signer_id_bincode_hex, &r1.nonces_bincode_hex, &r1.commitments_bincode_hex, r1.session.as_deref());
                    verify_ecdsa_keccak(&payload, pub_hex, sig_hex)?;
                }
            }
            if commitments_map.is_empty() {
                return Err(anyhow!(
                    "no round1_*.json files found in {}",
                    round1_dir.display()
                ));
            }

            // 2) Collect all Round2 signature shares and ensure SAME message digest and session.
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
                    if let Some(ts) = target_session.clone() { if ts != s { return Err(anyhow!("session mismatch among Round2 files")); } } else { target_session = Some(s); }
                }
                let id: frost::Identifier =
                    bincode::deserialize(&hex::decode(&r2.signer_id_bincode_hex)?)?;
                let sshare: frost::round2::SignatureShare =
                    bincode::deserialize(&hex::decode(&r2.signature_share_bincode_hex)?)?;
                sig_shares.insert(id, sshare);
            }
            // Check group.json session vs files if present
            if let Some(gs) = target_session_from_group.as_ref() {
                if let Some(ts) = target_session.as_ref() {
                    if gs != ts { return Err(anyhow!("group.json session does not match rounds session")); }
                } else {
                    // prefer group session if rounds omitted it
                    target_session = Some(gs.clone());
                }
            }
            if sig_shares.is_empty() {
                return Err(anyhow!(
                    "no round2_*.json files found in {}",
                    round2_dir.display()
                ));
            }

            // Recover the message bytes32 for aggregation.
            let msg32 = if let Some(h) = msg_hex.expect("message").strip_prefix("0x") {
                hex::decode(h)?
            } else {
                unreachable!()
            };

            // 3) Reconstruct the group verifying key and per-signer verifying shares.
            let group_vk_bytes = hex::decode(&g.group_vk_sec1_hex)?;
            let group_vk = frost::VerifyingKey::deserialize(&group_vk_bytes)
                .map_err(|e| anyhow!("group verifying key deserialize failed: {e}"))?;

            let needed_ids: Vec<frost::Identifier> = sig_shares.keys().cloned().collect();
            let mut vmap: BTreeMap<frost::Identifier, frost::keys::VerifyingShare> =
                BTreeMap::new();

            // Try to recover verifying shares from nearby share_*.json files (round1_dir or its parent).
            scan_dir_for_vshares(&round1_dir, &needed_ids, &mut vmap)?;
            if vmap.len() < needed_ids.len() {
                if let Some(gdir) = group.parent() {
                    scan_dir_for_vshares(gdir, &needed_ids, &mut vmap)?;
                }
            }
            if vmap.len() < needed_ids.len() {
                return Err(anyhow!("missing verifying shares for some participants"));
            }

            // Assemble the PublicKeyPackage needed to verify the signature shares.
            let pubkey_package = frost::keys::PublicKeyPackage::new(vmap, group_vk);
            // 4) Aggregate signature shares into the final signature.
            let signing_package = frost::SigningPackage::new(commitments_map, &msg32);
            let sig = frost::aggregate(&signing_package, &sig_shares, &pubkey_package)?;

            // Derive human-friendly affine coordinates for group VK and R.
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

            // Persist the final signature JSON for on-chain / off-chain verification.
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

        Commands::Ws { url, create, group_id, threshold, participants, participants_pubs, group_vk_sec1_hex, message, share, session, session_file, out_dir } => {
            // Load this signer's share
            let sf: ShareFile = read_json(&share)?;
            let my_id_hex = sf.signer_id_bincode_hex.clone();
            let my_id: frost::Identifier = bincode::deserialize(&hex::decode(&my_id_hex)?)?;
            let vshare_hex = sf.verifying_share_bincode_hex.clone();

            // ECDSA signing key for WS auth and payload signatures
            let ecdsa_keys = read_ecdsa_signing_key_from_env()?;
            let (ecdsa_sign, ecdsa_pub_hex) = if let Some((sk, pub_hex)) = ecdsa_keys { (sk, pub_hex) } else { return Err(anyhow!("Missing DKG_ECDSA_PRIV_HEX or SIGNING_ECDSA_PRIV_HEX in env")); };

            // Connect WS
            let (ws_stream, _) = connect_async(&url).await.context("connect ws")?;
            let (mut write, mut read) = ws_stream.split();

            // Helper macro
            macro_rules! send_json_ws {
                ($m:expr) => {{ let s = serde_json::to_string(&$m)?; write.send(WsMsg::Text(s)).await?; }};
            }

            // If creator, announce signing session
            if create {
                let parts: Vec<u32> = participants.split(',').filter(|s| !s.is_empty()).map(|s| s.trim().parse::<u32>().expect("uid u32")).collect();
                let pubs: Vec<(u32, String)> = participants_pubs.split(',').filter(|s| !s.is_empty()).map(|kv| { let (u,p) = kv.split_once(':').expect("uid:pub"); (u.trim().parse::<u32>().expect("uid"), p.trim().to_string()) }).collect();
                let msg_hex = if message.starts_with("0x") { message.clone() } else { format!("0x{}", hex::encode(message.as_bytes())) };
                send_json_ws!(ClientMsg::AnnounceSignSession {
                    group_id: group_id.clone(),
                    threshold,
                    participants: parts,
                    participants_pubs: pubs,
                    group_vk_sec1_hex: group_vk_sec1_hex.clone(),
                    message_hex: msg_hex,
                });
            }

            // Request auth challenge
            send_json_ws!(ClientMsg::RequestChallenge);

            // State
            let mut session_id: Option<String> = session.map(|s| s.trim().to_string());
            let session_file_path = session_file.unwrap_or_else(|| out_dir.join("sign_session.txt"));
            if !create && session_id.is_none() {
                if let Ok(s) = fs::read_to_string(&session_file_path) { let st = s.trim().to_string(); if !st.is_empty() { session_id = Some(st); } }
            }

            // Round1 local variables
            let secret_share: frost::keys::SecretShare = bincode::deserialize(&hex::decode(&sf.secret_share_bincode_hex)?)?;
            let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
            let mut rng = OsRng;
            let (mut my_nonces_opt, mut my_commitments_opt) = (None, None);

            while let Some(msg) = read.next().await {
                match msg? {
                    WsMsg::Text(txt) => {
                        let smsg: ServerMsg = serde_json::from_str(&txt)?;
                        match smsg {
                            ServerMsg::SignSessionCreated { session } => {
                                fs::create_dir_all(&out_dir)?;
                                fs::write(&session_file_path, &session)?;
                                session_id = Some(session);
                            }
                            ServerMsg::Challenge { challenge } => {
                                // Sign challenge
                                let uuid = uuid::Uuid::parse_str(&challenge).context("challenge uuid")?;
                                let sig: EcdsaSignature = ecdsa_sign.sign_digest(Keccak256::new().chain_update(uuid.as_bytes()));
                                let sig_hex = hex::encode(sig.to_der().as_bytes());
                                send_json_ws!(ClientMsg::Login { challenge, pubkey_hex: ecdsa_pub_hex.clone(), signature_hex: sig_hex });
                            }
                            ServerMsg::LoginOk { user_id, .. } => {
                                // Join signing session with our verifying share
                                let sid = session_id.clone().ok_or_else(|| anyhow!("no session id yet"))?;
                                send_json_ws!(ClientMsg::JoinSignSession {
                                    session: sid,
                                    signer_id_bincode_hex: my_id_hex.clone(),
                                    verifying_share_bincode_hex: sf.verifying_share_bincode_hex.clone(),
                                });
                                println!("[ws] logged in as uid {user_id}");
                            }
                            ServerMsg::SignReadyRound1 { session, group_id: gid, threshold: _t, participants: _n, msg_keccak32_hex: _m, roster: _ } => {
                                // Ensure this is our session
                                if Some(&session) != session_id.as_ref() { continue; }
                                // Generate round1 nonces/commitments then submit
                                let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);
                                let commits_hex = hex::encode(bincode::serialize(&commitments)?);
                                my_nonces_opt = Some(nonces);
                                my_commitments_opt = Some(commitments.clone());
                                let sid = session_id.clone().unwrap();
                                let _payload = auth_payload_round1(&gid, &my_id_hex, "", &commits_hex, None);
                                let sig: EcdsaSignature = ecdsa_sign.sign_digest(Keccak256::new().chain_update(&auth_payload_sign_r1(&sid, &gid, &my_id_hex, &commits_hex)));
                                let sig_hex = hex::encode(sig.to_der().as_bytes());
                                send_json_ws!(ClientMsg::SignRound1Submit { session: sid, id_hex: my_id_hex.clone(), commitments_bincode_hex: commits_hex, sig_ecdsa_hex: sig_hex });
                            }
                            ServerMsg::SignSigningPackage { session, signing_package_bincode_hex } => {
                                if Some(&session) != session_id.as_ref() { continue; }
                                // Round2 signing
                                let sp: frost::SigningPackage = bincode::deserialize(&hex::decode(&signing_package_bincode_hex)?)?;
                                let my_nonces = my_nonces_opt.take().ok_or_else(|| anyhow!("missing my nonces"))?;
                                let sig_share = frost::round2::sign(&sp, &my_nonces, &key_package)?;
                                let sigshare_hex = hex::encode(bincode::serialize(&sig_share)?);
                                let gid = group_id.clone();
                                let msg32_hex = format!("0x{}", hex::encode(sp.message()));
                                let sid = session_id.clone().unwrap();
                                let sig: EcdsaSignature = ecdsa_sign.sign_digest(Keccak256::new().chain_update(&auth_payload_sign_r2(&sid, &gid, &my_id_hex, &sigshare_hex, &msg32_hex)));
                                let sig_hex = hex::encode(sig.to_der().as_bytes());
                                send_json_ws!(ClientMsg::SignRound2Submit { session: sid, id_hex: my_id_hex.clone(), signature_share_bincode_hex: sigshare_hex, sig_ecdsa_hex: sig_hex });
                            }
                            ServerMsg::SignatureReady { session, signature_bincode_hex, px, py, rx, ry, s, message } => {
                                if Some(&session) != session_id.as_ref() { continue; }
                                // Verify offchain (like offchain-verify)
                                let pxb = hex::decode(px.trim_start_matches("0x"))?; let pyb = hex::decode(py.trim_start_matches("0x"))?;
                                let mut vk_un = [0u8;65]; vk_un[0]=0x04; vk_un[1..33].copy_from_slice(&pxb); vk_un[33..65].copy_from_slice(&pyb);
                                let ep = k256::EncodedPoint::from_bytes(&vk_un)?; let affine = k256::AffinePoint::from_encoded_point(&ep).unwrap();
                                let compressed = affine.to_encoded_point(true);
                                let vk = frost::VerifyingKey::deserialize(compressed.as_bytes())?;
                                let sig = frost::Signature::deserialize(&hex::decode(signature_bincode_hex)?)?;
                                let m = hex::decode(message.trim_start_matches("0x"))?; let mut m32=[0u8;32]; m32.copy_from_slice(&m);
                                let ok = vk.verify(&m32, &sig).is_ok();
                                fs::create_dir_all(&out_dir)?;
                                let out = SignatureOut { group_id: group_id.clone(), signature_bincode_hex: hex::encode(bincode::serialize(&sig)?), px, py, rx, ry, s, message, session: session_id.clone() };
                                write_json(out_dir.join("signature.json"), &out)?;
                                println!("[ws] Signature verify: {}", ok);
                                break;
                            }
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}
