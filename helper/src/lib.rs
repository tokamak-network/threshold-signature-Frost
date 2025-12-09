use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ark_ff::PrimeField;
use blake3::Hasher;
use rand::RngCore;

use anyhow::anyhow;
use frost_secp256k1 as frost;
use k256::ecdh::EphemeralSecret;
use k256::ecdsa::{
    Signature as EcdsaSignature, SigningKey as EcdsaSigningKey, VerifyingKey as EcdsaVerifyingKey,
};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, Scalar};
use k256::{PublicKey as K256PublicKey, SecretKey as K256SecretKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha512};
use sha3::Keccak256;
use signature::{DigestSigner, DigestVerifier};
use std::collections::BTreeMap;
use std::env;

// =============================================================================
// =================== Roster Key Enums and Encrypted Payload ==================
// =============================================================================

/// Represents a public key that can be either secp256k1 (ECDSA) or Edwards (EdDSA).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "key")]
pub enum RosterPublicKey {
    Secp256k1(String), // Compressed SEC1 hex string
    Ed25519(String),   // Compressed hex string
}

impl RosterPublicKey {
    /// Creates a Secp256k1 RosterPublicKey from an EcdsaVerifyingKey.
    pub fn from_secp256k1_vk(vk: &EcdsaVerifyingKey) -> Self {
        RosterPublicKey::Secp256k1(hex::encode(vk.to_encoded_point(true).as_bytes()))
    }

    /// Creates an Ed25519 RosterPublicKey from an EdDSAPublicKey.
    pub fn from_ed25519_pk(pk: &eddsa::EdDSAPublicKey) -> anyhow::Result<Self> {
        let pk_bytes = pk.to_compressed_bytes().unwrap();
        Ok(RosterPublicKey::Ed25519(hex::encode(pk_bytes)))
    }

    /// Verifies a signature against a payload.
    pub fn verify(&self, payload: &[u8], signature_hex: &str) -> anyhow::Result<()> {
        match self {
            RosterPublicKey::Secp256k1(pk_hex) => {
                let pk_bytes = hex::decode(pk_hex)?;
                let vk = EcdsaVerifyingKey::from_sec1_bytes(&pk_bytes)
                    .map_err(|e| anyhow!("bad ECDSA pub: {e}"))?;
                let sig = parse_ecdsa_sig_hex(signature_hex)?;
                vk.verify_digest(Keccak256::new().chain_update(payload), &sig)
                    .map_err(|_| anyhow!("ECDSA signature verification failed"))
            }
            RosterPublicKey::Ed25519(pk_hex) => {
                let pk_bytes = hex::decode(pk_hex)?;
                let pk = eddsa::EdDSAPublicKey::from_compressed_bytes(pk_bytes.as_slice()).unwrap();
                let sig = parse_eddsa_sig_hex(signature_hex)?;
                let message = Keccak256::digest(payload).to_vec();
                if pk.verify(message.as_slice(), &sig) {
                    Ok(())
                } else {
                    Err(anyhow!("EdDSA signature verification failed"))
                }
            }
        }
    }

    /// Encrypts `plaintext` for this public key using an appropriate ECIES-like scheme.
    pub fn encrypt_for(
        &self,
        plaintext: &[u8],
        rng: &mut OsRng,
    ) -> anyhow::Result<EncryptedPayload> {
        match self {
            RosterPublicKey::Secp256k1(pk_hex) => {
                let pk_bytes = hex::decode(pk_hex)?;
                let vk = EcdsaVerifyingKey::from_sec1_bytes(&pk_bytes)
                    .map_err(|_| anyhow!("bad recipient pubkey for ECIES"))?;
                let (eph_pub_bytes, nonce, ct) = ecies_encrypt_for_secp256k1(&vk, plaintext, rng)?;
                Ok(EncryptedPayload {
                    ephemeral_public_key: RosterPublicKey::Secp256k1(hex::encode(eph_pub_bytes)),
                    nonce: hex::encode(nonce),
                    ciphertext: hex::encode(ct),
                })
            }
            RosterPublicKey::Ed25519(pk_hex) => {
                let pk_bytes = hex::decode(pk_hex)?;
                let (eph_pub_bytes, encrypted_msg) =
                    encrypt_with_edwards_curve(&pk_bytes, plaintext);
                if encrypted_msg.len() < 12 {
                    return Err(anyhow!("Encrypted message too short from EdDSA encryption"));
                }
                let nonce = &encrypted_msg[0..12];
                let ciphertext = &encrypted_msg[12..];
                Ok(EncryptedPayload {
                    ephemeral_public_key: RosterPublicKey::Ed25519(hex::encode(eph_pub_bytes)),
                    nonce: hex::encode(nonce),
                    ciphertext: hex::encode(ciphertext),
                })
            }
        }
    }
}

/// Represents a private key that can be either secp256k1 (ECDSA) or Edwards (EdDSA).
#[derive(Debug)]
pub enum RosterSigningKey {
    Secp256k1(EcdsaSigningKey),
    Ed25519([u8; 32]),
}

impl RosterSigningKey {
    /// Returns the corresponding public key.
    pub fn public_key(&self) -> RosterPublicKey {
        match self {
            RosterSigningKey::Secp256k1(sk) => {
                RosterPublicKey::from_secp256k1_vk(sk.verifying_key())
            }
            RosterSigningKey::Ed25519(sk_bytes) => {
                let sk = eddsa::EdDSAPrivateKey::from_bytes(*sk_bytes);
                RosterPublicKey::from_ed25519_pk(&sk.public())
                    .expect("EdDSA public key derivation failed")
            }
        }
    }

    /// Signs a payload by first hashing it with Keccak256 and then creating a signature.
    /// Returns the hex-encoded signature.
    pub fn sign(&self, payload: &[u8]) -> String {
        match self {
            RosterSigningKey::Secp256k1(sk) => {
                let sig: EcdsaSignature = sk.sign_digest(Keccak256::new().chain_update(payload));
                hex::encode(sig.to_der().as_bytes())
            }
            RosterSigningKey::Ed25519(sk_bytes) => {
                let sk = eddsa::EdDSAPrivateKey::from_bytes(*sk_bytes);
                let message = Keccak256::digest(payload).to_vec();
                let sig = sk.sign_bytes(message.as_slice());
                let sig_bytes = sig
                    .to_compressed_bytes()
                    .expect("EdDSA signature serialization failed");
                hex::encode(sig_bytes)
            }
        }
    }

    /// Decrypts an `EncryptedPayload` using this private key.
    pub fn decrypt_with(&self, encrypted_payload: &EncryptedPayload) -> anyhow::Result<Vec<u8>> {
        match (self, &encrypted_payload.ephemeral_public_key) {
            (RosterSigningKey::Secp256k1(sk), RosterPublicKey::Secp256k1(eph_pub_hex)) => {
                let k256_sk = K256SecretKey::from_bytes(&sk.to_bytes()).unwrap();
                let eph_pub_bytes = hex::decode(eph_pub_hex)?;
                let nonce_bytes = hex::decode(&encrypted_payload.nonce)?;
                let ciphertext_bytes = hex::decode(&encrypted_payload.ciphertext)?;
                ecies_decrypt_with_secp256k1(
                    &k256_sk,
                    &eph_pub_bytes,
                    &nonce_bytes,
                    &ciphertext_bytes,
                )
            }
            (RosterSigningKey::Ed25519(sk_bytes), RosterPublicKey::Ed25519(eph_pub_hex)) => {
                let eph_pub_bytes = hex::decode(eph_pub_hex)?;
                let nonce_bytes = hex::decode(&encrypted_payload.nonce)?;
                let ciphertext_bytes = hex::decode(&encrypted_payload.ciphertext)?;
                let mut encrypted_msg = nonce_bytes;
                encrypted_msg.extend_from_slice(&ciphertext_bytes);
                Ok(decrypt_with_edwards_curve(
                    sk_bytes,
                    &eph_pub_bytes,
                    &encrypted_msg,
                ))
            }
            _ => Err(anyhow!("Mismatched key types for decryption")),
        }
    }
}

/// Standardized structure for encrypted data, regardless of curve.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub ephemeral_public_key: RosterPublicKey,
    pub nonce: String,
    pub ciphertext: String,
}

// =============================================================================
// =================== Curve-Specific ECIES and Signature Parsing =============
// =============================================================================

// Helper for EdDSA private key scalar derivation
#[allow(dead_code)]
fn derive_sk_scalar(sk_bytes: &[u8]) -> ark_ed_on_bls12_381::Fr {
    let mut hasher = Hasher::new();
    hasher.update(sk_bytes);
    let mut output = [0u8; 64];
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut output);

    let mut buf = [0u8; 32];
    buf.copy_from_slice(&output[0..32]);
    // Try NO CLAMPING: maybe eddsa crate uses raw hash output as scalar
    buf[0] &= 0xF8;
    buf[31] &= 0x7F;
    buf[31] |= 0x40;

    ark_ed_on_bls12_381::Fr::from_le_bytes_mod_order(&buf)
}

/// Encrypt `plaintext` for `receiver_pk_bytes` (EdDSA) using ECIES-like scheme.
/// Returns (ephemeral_pub_bytes, nonce || ciphertext).
pub fn encrypt_with_edwards_curve(receiver_pk_bytes: &[u8], message: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();

    //eddsa::EdDSAPrivateKey::from_bytes(*sk_bytes)
    // Deserialize Receiver's Public Key
    let receiver_pk = eddsa::EdDSAPublicKey::from_compressed_bytes(receiver_pk_bytes).unwrap();

    // 1. Generate Ephemeral Keypair
    let ephemeral_pv = eddsa::EdDSAPrivateKey::random(&mut rng);
    let ephemeral_pk = ephemeral_pv.public();

    // 2. Perform ECDH: Shared Secret = ephemeral_sk * receiver_pk
    let shared_point = ephemeral_pv.mul(receiver_pk).unwrap();

    // 3. Derive Symmetric Key
    let mut hasher = Hasher::new();
    let shared_bytes = shared_point.to_compressed_bytes().unwrap();
    hasher.update(&shared_bytes);
    let key_hash = hasher.finalize();
    let key = key_hash.as_bytes();

    // 4. Encrypt with AES-GCM
    let cipher = Aes256Gcm::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    rng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: message,
                aad: &[],
            },
        )
        .expect("encryption failure");

    // Pack nonce with ciphertext
    let mut encrypted_msg = nonce_bytes.to_vec();
    encrypted_msg.extend(ciphertext);

    let ephemeral_pk_bytes = ephemeral_pk.to_compressed_bytes().unwrap();

    (ephemeral_pk_bytes.to_vec(), encrypted_msg)
}

/// Decrypt with `sk_bytes` (EdDSA) and `ephemeral_pk_bytes`.
/// `encrypted_msg` is expected to be nonce || ciphertext.
pub fn decrypt_with_edwards_curve(
    sk_bytes: &[u8; 32],
    ephemeral_pk_bytes: &[u8],
    encrypted_msg: &[u8],
) -> Vec<u8> {
    // 1. Derive Receiver's Scalar Key
    let receiver_prv = eddsa::EdDSAPrivateKey::from_bytes(*sk_bytes);
    // Deserialize Ephemeral Public Key
    let ephemeral_pk = eddsa::EdDSAPublicKey::from_compressed_bytes(ephemeral_pk_bytes).unwrap();

    // 2. Perform ECDH: Shared Secret = sk_scalar * ephemeral_pk
    let shared_point = receiver_prv.mul(ephemeral_pk).unwrap();

    // 3. Derive Symmetric Key
    let mut hasher = Hasher::new();
    let shared_bytes = shared_point.to_compressed_bytes().unwrap();
    hasher.update(&shared_bytes);
    let key_hash = hasher.finalize();
    let key = key_hash.as_bytes();

    // 4. Decrypt with AES-GCM
    let cipher = Aes256Gcm::new(key.into());

    // Extract Nonce and Ciphertext
    if encrypted_msg.len() < 12 {
        panic!("Encrypted message too short");
    }
    let nonce = Nonce::from_slice(&encrypted_msg[0..12]);
    let ciphertext = &encrypted_msg[12..];

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .expect("decryption failure")
}

/// Derive a 32-byte AES key from a secp256k1 ECDH secret via SHA-512(prefix || dh).first32
fn ecies_kdf_32(prefix: &[u8], shared: &[u8]) -> [u8; 32] {
    let mut h = Sha512::new();
    h.update(prefix);
    h.update(shared);
    let d = h.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&d[..32]);
    output
}

/// Encrypt `plaintext` for `recipient_vk` (secp256k1) using ECIES + AES-256-GCM.
/// Returns (ephemeral_pub_sec1, nonce12, ciphertext_with_tag).
pub fn ecies_encrypt_for_secp256k1(
    recipient_vk: &EcdsaVerifyingKey,
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
    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|e| anyhow!("aes-gcm encrypt: {e}"))?;

    Ok((
        eph_pub.to_encoded_point(true).as_bytes().to_vec(),
        nonce,
        ct,
    ))
}

/// Decrypt with our static private key and the sender's ephemeral public key (secp256k1).
pub fn ecies_decrypt_with_secp256k1(
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
    let pt = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|e| anyhow!("aes-gcm decrypt: {e}"))?;
    Ok(pt)
}

/// Parses a hex-encoded ECDSA signature.
pub fn parse_ecdsa_sig_hex(hexstr: &str) -> anyhow::Result<EcdsaSignature> {
    use core::convert::TryFrom;
    let bytes = hex::decode(hexstr)?;
    // Prefer DER; if that fails, accept 64-byte compact signatures (r||s)
    if let Ok(sig) = EcdsaSignature::from_der(&bytes) {
        return Ok(sig);
    }
    EcdsaSignature::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("invalid ECDSA signature: expected DER or 64-byte compact"))
}

/// Parses a hex-encoded EdDSA signature.
pub fn parse_eddsa_sig_hex(hexstr: &str) -> anyhow::Result<eddsa::EdDSASignature> {
    let bytes = hex::decode(hexstr)?;
    eddsa::EdDSASignature::from_compressed_bytes(bytes.as_slice())
        .map_err(|e| anyhow!("invalid EdDSA signature: {e}"))
}

// =============================================================================
// =================== Authentication Payload Helpers ==========================
// =============================================================================

pub fn auth_payload_round1(
    session: &str,
    id: &frost::Identifier,
    pkg: &frost::keys::dkg::round1::Package,
) -> Vec<u8> {
    let mut v = b"TOKAMAK_FROST_DKG_R1|".to_vec();
    v.extend_from_slice(session.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(id).unwrap());
    v.extend_from_slice(&bincode::serialize(pkg).unwrap());
    v
}

pub fn auth_payload_round2(
    session: &str,
    from: &frost::Identifier,
    to: &frost::Identifier,
    eph_pub_bytes: &[u8],
    nonce: &[u8],
    ct: &[u8],
) -> Vec<u8> {
    // Sign the encrypted envelope (not the plaintext): session | from | to | eph_pub | nonce | ct
    let mut v = b"TOKAMAK_FROST_DKG_R2|".to_vec();
    v.extend_from_slice(session.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(from).unwrap());
    v.extend_from_slice(&bincode::serialize(to).unwrap());
    v.extend_from_slice(eph_pub_bytes);
    v.extend_from_slice(nonce);
    v.extend_from_slice(ct);
    v
}

pub fn auth_payload_finalize(
    session: &str,
    id: &frost::Identifier,
    group_vk_sec1: &[u8],
) -> Vec<u8> {
    let mut v = b"TOKAMAK_FROST_DKG_FIN|".to_vec();
    v.extend_from_slice(session.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(id).unwrap());
    v.extend_from_slice(group_vk_sec1);
    v
}

pub fn auth_payload_sign_r1(
    session: &str,
    group_id: &str,
    id_hex: &str,
    commits_hex: &str,
) -> Vec<u8> {
    format!(
        "SIGN_WS_R1|{}|{}|{}|{}",
        session, group_id, id_hex, commits_hex
    )
    .into_bytes()
}

pub fn auth_payload_sign_r2(
    session: &str,
    group_id: &str,
    id_hex: &str,
    sigshare_hex: &str,
    msg32_hex: &str,
) -> Vec<u8> {
    format!(
        "SIGN_WS_R2|{}|{}|{}|{}|{}",
        session, group_id, id_hex, sigshare_hex, msg32_hex
    )
    .into_bytes()
}

/// Build the Round1 authentication payload from its fields (excluding auth fields).
/// Used in signing tool.
pub fn auth_payload_signing_round1(
    group_id: &str,
    id_hex: &str,
    nonces_hex: &str,
    commits_hex: &str,
    session: Option<&str>,
) -> Vec<u8> {
    if let Some(sid) = session {
        format!(
            "signing:R1|{}|{}|{}|{}|{}",
            sid, group_id, id_hex, nonces_hex, commits_hex
        )
        .into_bytes()
    } else {
        format!(
            "signing:R1|{}|{}|{}|{}",
            group_id, id_hex, nonces_hex, commits_hex
        )
        .into_bytes()
    }
}

pub fn convert_group_vk1_to_uncompressed(group_vk_sec1_hex: &str) -> anyhow::Result<String> {
    let vk_bytes = hex::decode(group_vk_sec1_hex)?;
    let group_vk = frost::VerifyingKey::deserialize(&vk_bytes)
        .map_err(|e| anyhow!("group verifying key deserialize failed: {e}"))?;
    let hex = hex::encode(
        group_vk
            .to_element()
            .to_affine()
            .to_encoded_point(false)
            .as_bytes(),
    );
    Ok(hex)
}

/// Build the Round2 authentication payload from its fields (excluding auth fields).
/// Used in signing tool.
pub fn auth_payload_signing_round2(
    group_id: &str,
    id_hex: &str,
    sigshare_hex: &str,
    msg32_hex: &str,
    session: Option<&str>,
) -> Vec<u8> {
    if let Some(sid) = session {
        format!(
            "signing:R2|{}|{}|{}|{}|{}",
            sid, group_id, id_hex, sigshare_hex, msg32_hex
        )
        .into_bytes()
    } else {
        format!(
            "signing:R2|{}|{}|{}|{}",
            group_id, id_hex, sigshare_hex, msg32_hex
        )
        .into_bytes()
    }
}

/// Parse a participants pub map string `id:pub,id:pub,...`. `id` may be the exact
/// bincode-hex signer id or a small decimal (1..n), which will be converted to bincode-hex.
pub fn parse_participants_pubs_map(s: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    if s.trim().is_empty() {
        return Ok(out);
    }
    for pair in s.split(',') {
        let (id_raw, pub_hex) = pair
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid participants-pubs entry (missing colon): {pair}"))?;
        let id_key = if id_raw.chars().all(|c| c.is_ascii_hexdigit()) && id_raw.len() > 2 {
            id_raw.to_string()
        } else {
            // try parse as integer index
            let idx: u16 = id_raw
                .trim()
                .parse()
                .map_err(|_| anyhow!("invalid id '{id_raw}', expected hex or integer"))?;
            let sc = Scalar::from(idx as u64);
            let ident = frost::Identifier::new(sc).expect("invalid identifier index: {idx}");
            hex::encode(bincode::serialize(&ident)?)
        };
        out.insert(id_key, pub_hex.to_string());
    }
    Ok(out)
}

/// Read a RosterSigningKey from env vars.
pub fn read_roster_signing_key_from_env() -> anyhow::Result<Option<RosterSigningKey>> {
    let key_type = env::var("ROSTER_KEY_TYPE").ok();
    let priv_key_hex = env::var("ROSTER_PRIVATE_KEY").ok();

    match (key_type, priv_key_hex) {
        (Some(ty), Some(hex)) => {
            let bytes = hex::decode(hex.trim())?;
            if bytes.len() != 32 {
                return Err(anyhow!("Roster private key must be 32 bytes (hex)"));
            }
            let key = match ty.to_lowercase().as_str() {
                "secp256k1" => {
                    let fb = FieldBytes::from_slice(&bytes);
                    let sk = EcdsaSigningKey::from_bytes(fb)
                        .map_err(|_| anyhow!("invalid secp256k1 private key bytes"))?;
                    RosterSigningKey::Secp256k1(sk)
                }
                "ed25519" => {
                    let mut sk_bytes = [0u8; 32];
                    sk_bytes.copy_from_slice(&bytes);
                    RosterSigningKey::Ed25519(sk_bytes)
                }
                _ => return Err(anyhow!("Unsupported ROSTER_KEY_TYPE: {}", ty)),
            };
            Ok(Some(key))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_roster_key_secp256k1_sign_verify() {
        let mut rng = OsRng;
        let sk_ecdsa = EcdsaSigningKey::random(&mut rng);
        let pk_ecdsa = RosterPublicKey::from_secp256k1_vk(&sk_ecdsa.verifying_key());
        let roster_sk = RosterSigningKey::Secp256k1(sk_ecdsa);

        let payload = b"test message for secp256k1";
        let signature_hex = roster_sk.sign(payload);

        pk_ecdsa
            .verify(payload, &signature_hex)
            .expect("Secp256k1 verification failed");
    }

    #[test]
    fn test_roster_key_ed25519_sign_verify() {
        let mut rng = thread_rng();
        let sk_bytes: [u8; 32] = rng.gen();
        let roster_sk = RosterSigningKey::Ed25519(sk_bytes);
        let pk_eddsa = roster_sk.public_key();

        let payload = b"test message for ed25519";
        let signature_hex = roster_sk.sign(payload);

        pk_eddsa
            .verify(payload, &signature_hex)
            .expect("Ed25519 verification failed");
    }

    #[test]
    fn test_roster_key_secp256k1_ecies_encrypt_decrypt() {
        let mut rng = OsRng;
        let sk_ecdsa = EcdsaSigningKey::random(&mut rng);
        let pk_ecdsa = RosterPublicKey::from_secp256k1_vk(&sk_ecdsa.verifying_key());
        let roster_sk = RosterSigningKey::Secp256k1(sk_ecdsa);

        let plaintext = b"secret message for secp256k1";
        let encrypted_payload = pk_ecdsa.encrypt_for(plaintext, &mut rng).unwrap();
        let decrypted = roster_sk.decrypt_with(&encrypted_payload).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_roster_key_ed25519_ecies_encrypt_decrypt() {
        let mut rng = thread_rng();
        let sk_bytes: [u8; 32] = rng.gen();
        let roster_sk = RosterSigningKey::Ed25519(sk_bytes);
        let pk_eddsa = roster_sk.public_key();

        let plaintext = b"secret message for ed25519";
        let mut os_rng = OsRng;
        let encrypted_payload = pk_eddsa.encrypt_for(plaintext, &mut os_rng).unwrap();
        let decrypted = roster_sk.decrypt_with(&encrypted_payload).unwrap();

        assert_eq!(plaintext.to_vec(), decrypted);
    }

    #[test]
    fn test_mismatched_decryption_fails() {
        let mut rng = OsRng;
        let sk_ecdsa = EcdsaSigningKey::random(&mut rng);
        let pk_ecdsa = RosterPublicKey::from_secp256k1_vk(&sk_ecdsa.verifying_key());
        let roster_sk_ecdsa = RosterSigningKey::Secp256k1(sk_ecdsa);

        let mut thread_rng = thread_rng();
        let sk_bytes_eddsa: [u8; 32] = thread_rng.gen();
        let roster_sk_eddsa = RosterSigningKey::Ed25519(sk_bytes_eddsa);
        let pk_eddsa = roster_sk_eddsa.public_key();

        let plaintext = b"secret message";

        // Encrypt with ECDSA public key
        let encrypted_with_ecdsa = pk_ecdsa.encrypt_for(plaintext, &mut rng).unwrap();
        // Try to decrypt with EdDSA private key - should fail
        assert!(roster_sk_eddsa.decrypt_with(&encrypted_with_ecdsa).is_err());

        // Encrypt with EdDSA public key
        let encrypted_with_eddsa = pk_eddsa.encrypt_for(plaintext, &mut rng).unwrap();
        // Try to decrypt with ECDSA private key - should fail
        assert!(roster_sk_ecdsa.decrypt_with(&encrypted_with_eddsa).is_err());
    }

    #[test]
    fn test_convert_group_vk1_to_uncompressed_ed25519() {
        let mut rng = thread_rng();

         let max_signers = 5;
        let min_signers = 3;
        let (shares, pubkey_package) = frost::keys::generate_with_dealer(
            max_signers,
            min_signers,
            frost::keys::IdentifierList::Default,
            &mut rng,
        ).expect("failed to generate group");

        let vk = pubkey_package.verifying_key();
        let vk_bytes = vk.serialize().unwrap();
        let vk_hex = hex::encode(vk_bytes);

        let uncompressed_hex = convert_group_vk1_to_uncompressed(&vk_hex).unwrap();
        let uncompressed_bytes = hex::decode(uncompressed_hex).unwrap();

        assert_eq!(uncompressed_bytes.len(), 65); // Uncompressed keys are 65 bytes
        assert_eq!(uncompressed_bytes[0], 0x04); // Uncompressed keys start with 0x04
    }
}
