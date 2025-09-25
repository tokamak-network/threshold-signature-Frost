use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use k256::{AffinePoint, EncodedPoint};

#[derive(Parser, Debug)]
#[command(
    name = "verify",
    about = "Verify aggregated Schnorr (secp256k1, FROST ciphersuite) using only signature.json (px,py,rx,ry,s,message)"
)]
struct Args {
    /// Path to signature.json produced by `signing aggregate`
    #[arg(long, default_value = "out/signature.json")]
    signature: PathBuf,
}

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
}

fn read_json<T: for<'de> serde::Deserialize<'de>>(p: &PathBuf) -> Result<T> {
    let s = fs::read_to_string(p)?;
    Ok(serde_json::from_str(&s).with_context(|| format!("parsing {}", p.display()))?)
}

fn hex32(s: &str) -> Result<[u8; 32]> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    let b = hex::decode(h)?;
    b.as_slice()
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes for hex value, got {} bytes", b.len()))
}

fn main() -> Result<()> {
    let args = Args::parse();
    let sig_out: SignatureOut = read_json(&args.signature)?;

    // === Build verifying key (FROST) from (px, py) ===
    let px = hex32(&sig_out.px)?;
    let py = hex32(&sig_out.py)?;

    // Compose uncompressed SEC1: 0x04 || X || Y
    let mut sec1_uncompressed = [0u8; 65];
    sec1_uncompressed[0] = 0x04;
    sec1_uncompressed[1..33].copy_from_slice(&px);
    sec1_uncompressed[33..65].copy_from_slice(&py);

    let ep = EncodedPoint::from_bytes(&sec1_uncompressed)?;
    let affine = AffinePoint::from_encoded_point(&ep)
        .unwrap();

    // For frost_secp256k1, element serialization is compressed SEC1
    let compressed = affine.to_encoded_point(true); // 33-byte 0x02/0x03 || X
    let vk = frost_secp256k1::VerifyingKey::deserialize(compressed.as_bytes())
        .map_err(|e| anyhow!("verifying key deserialize failed: {e}"))?;

    // === Build FROST signature from (rx, ry, s) ===
    let rx = hex32(&sig_out.rx)?;
    let ry = hex32(&sig_out.ry)?;
    let s = hex32(&sig_out.s)?; // serialized field element for z

    // R as compressed SEC1
    let mut r_uncompressed = [0u8; 65];
    r_uncompressed[0] = 0x04;
    r_uncompressed[1..33].copy_from_slice(&rx);
    r_uncompressed[33..65].copy_from_slice(&ry);
    let r_ep = EncodedPoint::from_bytes(&r_uncompressed)?;
    let r_aff = AffinePoint::from_encoded_point(&r_ep)
        .expect("invalid (rx,ry) point on curve");
    let r_compressed = r_aff.to_encoded_point(true);

    // FROST signature serialization = serialize_element(R) || serialize_scalar(z)
    let mut sig_ser = Vec::with_capacity(33 + 32);
    sig_ser.extend_from_slice(r_compressed.as_bytes());
    sig_ser.extend_from_slice(&s);
    let sig = frost_secp256k1::Signature::deserialize(&sig_ser)
        .map_err(|e| anyhow!("signature deserialize failed: {e}"))?;

    // Message is a 32-byte Keccak digest in our pipeline
    let msg_hex = sig_out.message.strip_prefix("0x").unwrap_or(&sig_out.message);
    let msg = hex::decode(msg_hex)?;
    let msg32: [u8; 32] = msg
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("message must be 32 bytes, got {}", msg.len()))?;

    // Verify using the FROST ciphersuite (not BIP340)
    let ok = vk.verify(&msg32, &sig).is_ok();
    println!("Signature valid: {}", ok);
    if !ok {
        std::process::exit(1);
    }
    Ok(())
}
