use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};
use frost_core::Field;
use frost_secp256k1 as frost;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

#[derive(Parser, Debug)]
#[command(name = "signing", about = "Run FROST(secp256k1) signing stages (per-participant)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

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
    },
}

#[derive(Serialize, Deserialize, Clone)]
struct ShareFile {
    group_id: String,
    threshold: u16,
    participants: u16,
    signer_id_bincode_hex: String,
    secret_share_bincode_hex: String,
    verifying_share_bincode_hex: String,
    group_vk_sec1_hex: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Round1One {
    group_id: String,
    signer_id_bincode_hex: String,
    nonces_bincode_hex: String,
    commitments_bincode_hex: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Round2One {
    group_id: String,
    signer_id_bincode_hex: String,
    signature_share_bincode_hex: String,
    msg_plain_hex: String,
    msg_keccak32_hex: String,
}

#[derive(Serialize, Deserialize)]
struct GroupFile {
    group_id: String,
    threshold: u16,
    participants: u16,
    group_vk_sec1_hex: String,
}

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
}

fn read_json<P: AsRef<Path>, T: for<'de> serde::Deserialize<'de>>(path: P) -> Result<T> {
    let s = fs::read_to_string(&path)?;
    Ok(serde_json::from_str(&s).with_context(|| format!("parsing JSON {}", path.as_ref().display()))?)
}

fn write_json<P: AsRef<Path>, T: serde::Serialize>(path: P, value: &T) -> Result<()> {
    if let Some(parent) = path.as_ref().parent() { fs::create_dir_all(parent)?; }
    let s = serde_json::to_string_pretty(value)?;
    fs::write(path, s)?;
    Ok(())
}

fn parse_message_to_bytes(msg: &str) -> Result<Vec<u8>> {
    if let Some(stripped) = msg.strip_prefix("0x") { Ok(hex::decode(stripped)?) } else { Ok(msg.as_bytes().to_vec()) }
}

fn scan_dir_for_vshares(
    dir: &Path,
    needed_ids: &[frost::Identifier],
    vmap: &mut BTreeMap<frost::Identifier, frost::keys::VerifyingShare>,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let p = entry?.path();
        if p.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
        if !p.file_name().and_then(|s| s.to_str()).map(|s| s.starts_with("share_")).unwrap_or(false) { continue; }
        let sf_one: ShareFile = match read_json(&p) { Ok(v) => v, Err(_) => continue };
        let id: frost::Identifier = bincode::deserialize(&hex::decode(&sf_one.signer_id_bincode_hex)?)?;
        if needed_ids.iter().any(|x| *x == id) && !vmap.contains_key(&id) {
            let vshare: frost::keys::VerifyingShare = bincode::deserialize(&hex::decode(&sf_one.verifying_share_bincode_hex)?)?;
            vmap.insert(id, vshare);
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Round1 { share, out } => {
            let sf: ShareFile = read_json(&share)?;
            let secret_share: frost::keys::SecretShare =
                bincode::deserialize(&hex::decode(&sf.secret_share_bincode_hex)?)?;
            let id_hex = sf.signer_id_bincode_hex.clone();
            let _id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;

            let mut rng = OsRng;
            let key_package = frost::keys::KeyPackage::try_from(secret_share)?;
            let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut rng);

            let r1 = Round1One {
                group_id: sf.group_id,
                signer_id_bincode_hex: id_hex.clone(),
                nonces_bincode_hex: hex::encode(bincode::serialize(&nonces)?),
                commitments_bincode_hex: hex::encode(bincode::serialize(&commitments)?),
            };
            let base_dir = share.parent().unwrap_or_else(|| Path::new("out"));
            let out_path = out.clone().unwrap_or_else(|| base_dir.join(format!("round1_{}.json", id_hex)));
            write_json(&out_path, &r1)?;
            println!("Wrote {}", out_path.display());
        }

        Commands::Round2 { share, round1_dir, message, out } => {
            let sf: ShareFile = read_json(&share)?;
            let my_id_hex = sf.signer_id_bincode_hex.clone();
            let _my_id: frost::Identifier = bincode::deserialize(&hex::decode(&my_id_hex)?)?;

            // Load all round1 files to build full commitments map and to fetch *my* nonces
            let mut commitments_map: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> = BTreeMap::new();
            let mut my_nonces: Option<frost::round1::SigningNonces> = None;
            for entry in fs::read_dir(&round1_dir)? {
                let p = entry?.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
                let r1: Round1One = match read_json(&p) { Ok(v) => v, Err(_) => continue };
                let id: frost::Identifier = bincode::deserialize(&hex::decode(&r1.signer_id_bincode_hex)?)?;
                let commitments: frost::round1::SigningCommitments =
                    bincode::deserialize(&hex::decode(&r1.commitments_bincode_hex)?)?;
                commitments_map.insert(id, commitments);
                if r1.signer_id_bincode_hex == my_id_hex {
                    let n: frost::round1::SigningNonces = bincode::deserialize(&hex::decode(&r1.nonces_bincode_hex)?)?;
                    my_nonces = Some(n);
                }
            }
            let my_nonces = my_nonces.ok_or_else(|| anyhow!("could not find round1 for this participant in {}", round1_dir.display()))?;

            // Optional sanity: ensure we have at least threshold participants
            if commitments_map.len() < sf.threshold as usize {
                return Err(anyhow!(
                    "not enough commitments: have {}, need at least {}",
                    commitments_map.len(), sf.threshold
                ));
            }

            // Build message
            let msg_bytes = parse_message_to_bytes(&message)?;
            let msg32 = Keccak256::digest(&msg_bytes);

            // Build signing package from ALL commitments
            let signing_package = frost::SigningPackage::new(commitments_map, msg32.as_slice());

            // Rebuild this participant's key package
            let secret_share: frost::keys::SecretShare =
                bincode::deserialize(&hex::decode(&sf.secret_share_bincode_hex)?)?;
            let key_package = frost::keys::KeyPackage::try_from(secret_share)?;

            // Compute signature share
            let sig_share = frost::round2::sign(&signing_package, &my_nonces, &key_package)?;

            let r2 = Round2One {
                group_id: sf.group_id,
                signer_id_bincode_hex: my_id_hex.clone(),
                signature_share_bincode_hex: hex::encode(bincode::serialize(&sig_share)?),
                msg_plain_hex: format!("0x{}", hex::encode(&msg_bytes)),
                msg_keccak32_hex: format!("0x{}", hex::encode(msg32)),
            };
            let base_dir = &round1_dir;
            let out_path = out.clone().unwrap_or_else(|| base_dir.join(format!("round2_{}.json", my_id_hex)));
            write_json(&out_path, &r2)?;
            println!("Wrote {}", out_path.display());
        }

        Commands::Aggregate { group, round1_dir, round2_dir, out } => {
            let g: GroupFile = read_json(&group)?;

            // Load all per-participant round1 files (commitments)
            let mut commitments_map: BTreeMap<frost::Identifier, frost::round1::SigningCommitments> = BTreeMap::new();
            for entry in fs::read_dir(&round1_dir)? {
                let p = entry?.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
                let r1: Round1One = match read_json(&p) { Ok(v) => v, Err(_) => continue };
                let id: frost::Identifier = bincode::deserialize(&hex::decode(&r1.signer_id_bincode_hex)?)?;
                let commitments: frost::round1::SigningCommitments =
                    bincode::deserialize(&hex::decode(&r1.commitments_bincode_hex)?)?;
                commitments_map.insert(id, commitments);
            }
            if commitments_map.is_empty() {
                return Err(anyhow!("no round1_*.json files found in {}", round1_dir.display()));
            }

            // Load all per-participant round2 files (signature shares) and check the message matches
            let mut sig_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare> = BTreeMap::new();
            let mut msg_hex: Option<String> = None;
            for entry in fs::read_dir(&round2_dir)? {
                let p = entry?.path();
                if p.extension().and_then(|e| e.to_str()) != Some("json") { continue; }
                let r2: Round2One = match read_json(&p) { Ok(v) => v, Err(_) => continue };
                if let Some(prev) = &msg_hex {
                    if *prev != r2.msg_keccak32_hex { return Err(anyhow!("mismatched msg_keccak32 across round2 files")); }
                } else { msg_hex = Some(r2.msg_keccak32_hex.clone()); }
                let id: frost::Identifier = bincode::deserialize(&hex::decode(&r2.signer_id_bincode_hex)?)?;
                let sshare: frost::round2::SignatureShare =
                    bincode::deserialize(&hex::decode(&r2.signature_share_bincode_hex)?)?;
                sig_shares.insert(id, sshare);
            }
            if sig_shares.is_empty() { return Err(anyhow!("no round2_*.json files found in {}", round2_dir.display())); }

            // message bytes32
            let msg32 = if let Some(h) = msg_hex.expect("message").strip_prefix("0x") { hex::decode(h)? } else { unreachable!() };

            // Build verifying key package from minimal group.json + available share_*.json files
            let group_vk_bytes = hex::decode(&g.group_vk_sec1_hex)?;
            let group_vk = frost::VerifyingKey::deserialize(&group_vk_bytes)
                .map_err(|e| anyhow!("group verifying key deserialize failed: {e}"))?;

            let needed_ids: Vec<frost::Identifier> = sig_shares.keys().cloned().collect();
            let mut vmap: BTreeMap<frost::Identifier, frost::keys::VerifyingShare> = BTreeMap::new();

            scan_dir_for_vshares(&round1_dir, &needed_ids, &mut vmap)?;
            if vmap.len() < needed_ids.len() {
                if let Some(gdir) = group.parent() { scan_dir_for_vshares(gdir, &needed_ids, &mut vmap)?; }
            }
            if vmap.len() < needed_ids.len() {
                return Err(anyhow!("missing verifying shares for some participants"));
            }

            let pubkey_package = frost::keys::PublicKeyPackage::new(vmap, group_vk);
            // Final signing package from all commitments
            let signing_package = frost::SigningPackage::new(commitments_map, &msg32);
            let sig = frost::aggregate(&signing_package, &sig_shares, &pubkey_package)?;

            // Pretty outputs
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
                px, py, rx, ry, s: s_hex,
                message: format!("0x{}", hex::encode(msg32)),
            };
            write_json(out, &out_obj)?;
            println!("Wrote signature.json");
        }
    }

    Ok(())
}
