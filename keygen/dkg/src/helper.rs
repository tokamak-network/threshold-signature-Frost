use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use anyhow::anyhow;
use k256::ecdh::EphemeralSecret;
use k256::ecdsa::Signature as EcdsaSignature;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey as K256PublicKey, SecretKey as K256SecretKey};
use rand::rngs::OsRng;
use rand_core::RngCore;
use sha2::{Digest as Sha2Digest, Sha512};

/// Derive a 32-byte AES key from a secp256k1 ECDH secret via SHA-512(prefix || dh).first32
fn ecies_kdf_32(prefix: &[u8], shared: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(prefix);
    h.update(shared);
    let d = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&d[..32]);
    out
}

/// Encrypt `plaintext` for `recipient_vk` using ECIES(sec1) + AES-256-GCM.
/// Returns (ephemeral_pub_sec1, nonce12, ciphertext_with_tag).
pub(crate) fn ecies_encrypt_for(
    recipient_vk: &k256::ecdsa::VerifyingKey,
    plaintext: &[u8],
    rng: &mut OsRng,
) -> anyhow::Result<(Vec<u8>, [u8; 12], Vec<u8>)> {
    let enc_pt = recipient_vk.to_encoded_point(true);
    let recip_pk = K256PublicKey::from_sec1_bytes(enc_pt.as_bytes())
        .map_err(|_| anyhow!("bad recipient pubkey for ECIES"))?;

    let eph = EphemeralSecret::random(rng);
    let eph_pub = K256PublicKey::from(&eph);

    // 32-byte shared secret (X coordinate) from k256
    let shared = eph.diffie_hellman(&recip_pk);
    let shared_bytes = shared.raw_secret_bytes();
    let key = ecies_kdf_32(b"TOKAMAK_FROST_ECIES_v1", shared_bytes.as_slice());

    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let mut nonce = [0u8; 12];
    rng.fill_bytes(&mut nonce);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| anyhow!("aes-gcm encrypt: {e}"))?;

    Ok((eph_pub.to_encoded_point(true).as_bytes().to_vec(), nonce, ct))
}

/// Decrypt with our static private key and the sender's ephemeral public key.
pub(crate) fn ecies_decrypt_with(
    my_sk: &K256SecretKey,
    eph_pub_sec1: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let peer_pub = K256PublicKey::from_sec1_bytes(eph_pub_sec1)
        .map_err(|_| anyhow!("bad ephemeral pubkey in ECIES envelope"))?;

    // static secret × ephemeral public (ECDH)
    let my_scalar = my_sk.to_nonzero_scalar();
    let shared = k256::ecdh::diffie_hellman(my_scalar, peer_pub.as_affine());
    let shared_bytes = shared.raw_secret_bytes();
    let key = ecies_kdf_32(b"TOKAMAK_FROST_ECIES_v1", shared_bytes.as_slice());

    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let pt = cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| anyhow!("aes-gcm decrypt: {e}"))?;
    Ok(pt)
}
pub(crate) fn parse_sig_hex(hexstr: &str) -> anyhow::Result<EcdsaSignature> {
    use core::convert::TryFrom;
    let bytes = hex::decode(hexstr)?;
    // Prefer DER; if that fails, accept 64-byte compact signatures (r||s)
    if let Ok(sig) = EcdsaSignature::from_der(&bytes) {
        return Ok(sig);
    }
    EcdsaSignature::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("invalid ECDSA signature: expected DER or 64-byte compact"))
}
