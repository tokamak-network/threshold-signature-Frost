use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use frost_secp256k1 as frost;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

#[derive(Parser, Debug)]
#[command(name = "keygen", about = "Dealer-based FROST(secp256k1) key generation")]
struct Args {
    /// Minimum number of signers required to produce a signature
    #[arg(long)]
    min_signers: u16,
    /// Maximum number of signers (total participants)
    #[arg(long)]
    max_signers: u16,
    /// Arbitrary group identifier to tag outputs
    #[arg(long)]
    group_id: String,
    /// Output directory (will be created if missing)
    #[arg(long, default_value = "out")]
    out_dir: PathBuf,
}
#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
struct GroupFile {
    group_id: String,
    threshold: u16,
    participants: u16,
    group_vk_sec1_hex: String,
}

fn write_json<P: AsRef<Path>, T: Serialize>(path: P, value: &T) -> Result<()> {
    let s = serde_json::to_string_pretty(value)?;
    fs::write(path, s)?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.out_dir).context("creating output dir")?;

    let mut rng = OsRng;
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        args.max_signers,
        args.min_signers,
        frost::keys::IdentifierList::Default,
        &mut rng,
    )
        .context("frost dealer keygen failed")?;

    // Persist group info (minimal)
    let vk_sec1 = pubkey_package
        .verifying_key()
        .serialize()
        .expect("verifying key should serialize");
    let group = GroupFile {
        group_id: args.group_id.clone(),
        threshold: args.min_signers,
        participants: args.max_signers,
        group_vk_sec1_hex: hex::encode(&vk_sec1),
    };
    write_json(args.out_dir.join("group.json"), &group)?;

    // Persist each participant's secret share
    for (identifier, secret_share) in shares {
        let id_hex = hex::encode(bincode::serialize(&identifier)?);

        // Fetch this participant's verifying share from the dealer's package
        let verifying_share = pubkey_package
            .verifying_shares()
            .get(&identifier)
            .expect("verifying share exists for identifier");

        let sf = ShareFile {
            group_id: args.group_id.clone(),
            threshold: args.min_signers,
            participants: args.max_signers,
            signer_id_bincode_hex: id_hex.clone(),
            secret_share_bincode_hex: hex::encode(bincode::serialize(&secret_share)?),
            verifying_share_bincode_hex: hex::encode(bincode::serialize(verifying_share)?),
            group_vk_sec1_hex: hex::encode(&vk_sec1),
        };
        write_json(
            args.out_dir.join(format!("share_{}.json", id_hex)),
            &sf,
        )?;
        println!(
            "Wrote participant share: {}",
            args.out_dir.join(format!("share_{}.json", id_hex)).display()
        );
    }

    println!("Wrote group info: {}", args.out_dir.join("group.json").display());
    println!("Done.");
    Ok(())
}
