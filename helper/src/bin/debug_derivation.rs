use ark_ec::{CurveGroup, Group};
use ark_ed_on_bls12_381::{EdwardsAffine, EdwardsProjective, Fr};
use ark_ff::PrimeField;
use ark_serialize::CanonicalDeserialize;
use eddsa::EdDSAPrivateKey;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha512};

// Helper to copy from slice (standard in codebase)
// Just use standard copy_from_slice

fn main() {
    let mut rng = OsRng;
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);

    println!("Seed: {}", hex::encode(sk_bytes));

    // 1. Get ground truth from crate
    let sk = EdDSAPrivateKey::from_bytes(sk_bytes);
    let pk_crate = sk.public();
    let pk_bytes_crate = pk_crate.to_compressed_bytes().unwrap();
    println!("Public Key (Crate): {}", hex::encode(pk_bytes_crate));

    // Parse crate pk to Arkworks point
    let pk_point = EdwardsAffine::deserialize_compressed(&pk_bytes_crate[..]).unwrap();

    // 2. Try Strategies
    check_strategy("Blake3", &sk_bytes, &pk_point, derive_blake3);
    check_strategy(
        "Blake3 (No Clamp)",
        &sk_bytes,
        &pk_point,
        derive_blake3_noclamp,
    );
    check_strategy("Sha512", &sk_bytes, &pk_point, derive_sha512);
    check_strategy(
        "Sha512 (No Clamp)",
        &sk_bytes,
        &pk_point,
        derive_sha512_noclamp,
    );
    check_strategy("Keccak256", &sk_bytes, &pk_point, derive_keccak256);
    check_strategy("Identity", &sk_bytes, &pk_point, derive_identity);
    check_strategy(
        "Identity (Clamp)",
        &sk_bytes,
        &pk_point,
        derive_identity_clamp,
    );
}

fn derive_identity(sk_bytes: &[u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(sk_bytes)
}

fn derive_identity_clamp(sk_bytes: &[u8; 32]) -> Fr {
    let mut buf = [0u8; 32];
    buf.copy_from_slice(sk_bytes);
    // Apply Clamping
    buf[0] &= 0xF8;
    buf[31] &= 0x7F;
    buf[31] |= 0x40;
    Fr::from_le_bytes_mod_order(&buf)
}

fn check_strategy<F>(name: &str, seed: &[u8; 32], expected_pk: &EdwardsAffine, derive_fn: F)
where
    F: Fn(&[u8; 32]) -> Fr,
{
    let scalar = derive_fn(seed);
    let derived_point = (EdwardsProjective::generator() * scalar).into_affine();

    if derived_point == *expected_pk {
        println!("MATCH FOUND: {}", name);
    } else {
        println!("Failed: {}", name);
    }
}

fn derive_blake3(sk_bytes: &[u8; 32]) -> Fr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(sk_bytes);
    let mut output = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut output);

    let mut buf = [0u8; 32];
    buf.clone_from_slice(&output[0..32]);
    // Apply Clamping
    buf[0] &= 0xF8;
    buf[31] &= 0x7F;
    buf[31] |= 0x40;

    Fr::from_le_bytes_mod_order(&buf)
}

fn derive_blake3_noclamp(sk_bytes: &[u8; 32]) -> Fr {
    let mut hasher = blake3::Hasher::new();
    hasher.update(sk_bytes);
    let mut output = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut output);

    let mut buf = [0u8; 32];
    buf.clone_from_slice(&output[0..32]);

    Fr::from_le_bytes_mod_order(&buf)
}

fn derive_sha512(sk_bytes: &[u8; 32]) -> Fr {
    let mut hasher = Sha512::new();
    hasher.update(sk_bytes);
    let d = hasher.finalize();

    let mut buf = [0u8; 32];
    buf.copy_from_slice(&d[0..32]);
    // Apply Clamping
    buf[0] &= 0xF8;
    buf[31] &= 0x7F;
    buf[31] |= 0x40;

    Fr::from_le_bytes_mod_order(&buf)
}

fn derive_sha512_noclamp(sk_bytes: &[u8; 32]) -> Fr {
    let mut hasher = Sha512::new();
    hasher.update(sk_bytes);
    let d = hasher.finalize();

    let mut buf = [0u8; 32];
    buf.copy_from_slice(&d[0..32]);

    Fr::from_le_bytes_mod_order(&buf)
}

fn derive_keccak256(sk_bytes: &[u8; 32]) -> Fr {
    use sha3::{Digest, Keccak256};
    let mut hasher = Keccak256::new();
    hasher.update(sk_bytes);
    let d = hasher.finalize();
    // Keccak gives 32 bytes
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&d[..]);

    Fr::from_le_bytes_mod_order(&buf)
}
