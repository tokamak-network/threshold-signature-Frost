mod lib_test;

use aes_gcm::aead::{Aead, AeadCore};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use anyhow::Result;
use k256::ecdsa::{Signature as EcdsaSignature, SigningKey as EcdsaSigningKey};
use k256::{EncodedPoint, SecretKey as K256SecretKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha512;
use sha3::{Digest, Keccak256};
use signature::DigestSigner;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

// Use Secp256k1 FROST only (Threshold Key is always Secp256k1)
use frost_secp256k1 as frost;

// Custom EdDSA crate
use eddsa::EdDSAPrivateKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use helper::{encrypt_with_edwards_curve, decrypt_with_edwards_curve};
// ====================================================================
// region: Custom Structs
// ====================================================================

#[derive(Serialize, Deserialize)]
struct KeyPackageWithMetadata {
    key_package: frost::keys::KeyPackage,
    threshold: u16,
    group_id: String,
    roster: BTreeMap<u32, String>,
    roster_key_type: String,
}

#[derive(Serialize, Deserialize)]
struct EncryptedShare {
    ciphertext_hex: String,
    nonce_hex: String,
}

// ====================================================================
// region: Initialization
// ====================================================================

#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}
// ====================================================================
// region: convert Utilities
// ====================================================================

#[wasm_bindgen]
pub fn group_vk1_to_uncompressed(group_vk_sec1_hex: &str) -> String {
    let vk_bytes = hex::decode(group_vk_sec1_hex).unwrap();
    let group_vk = frost::VerifyingKey::deserialize(&vk_bytes).unwrap();
    let hex = hex::encode(
        group_vk
            .to_element()
            .to_affine()
            .to_encoded_point(false)
            .as_bytes(),
    );
    hex
}
// ====================================================================
// region: Hashing Utilities
// ====================================================================

#[wasm_bindgen]
pub fn keccak256(message: &str) -> String {
    let clean = message.strip_prefix("0x").unwrap_or(message);
    let bytes = hex::decode(clean).expect("keccak256 input must be valid hex");
    let mut hasher = Keccak256::new();
    hasher.update(&bytes);
    let result = hasher.finalize();
    hex::encode(result)
}

// ====================================================================
// region: Key Generation & Signing Utilities
// ====================================================================

#[wasm_bindgen]
pub fn generate_ecdsa_keypair() -> String {
    let sk = K256SecretKey::random(&mut OsRng);
    let pk = sk.public_key();
    let response = serde_json::json!({
        "private_key_hex": hex::encode(sk.to_bytes()),
        "public_key_hex": hex::encode(pk.to_sec1_bytes()),
    });
    response.to_string()
}

#[wasm_bindgen]
pub fn generate_eddsa_keypair() -> String {
    let mut rng = OsRng;
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let sk_obj = EdDSAPrivateKey::from_bytes(sk_bytes);
    let pk_obj = sk_obj.public();
    let pk_bytes = pk_obj.to_compressed_bytes().unwrap();

    let response = serde_json::json!({
        "private_key_hex": hex::encode(sk_bytes),
        "public_key_hex": hex::encode(pk_bytes),
    });
    response.to_string()
}

#[wasm_bindgen]
pub fn derive_keys_from_signature(signature_hex: &str, key_type: &str) -> Result<String, JsError> {
    let sig_bytes = hex::decode(signature_hex.trim_start_matches("0x"))
        .map_err(|e| JsError::new(&e.to_string()))?;

    let mut sha512_hasher = Sha512::new();
    sha512_hasher.update(&sig_bytes);
    let sha512_result = sha512_hasher.finalize();
    let (first_32, second_32) = sha512_result.split_at(32);

    let mut keccak_hasher_sk = Keccak256::new();
    keccak_hasher_sk.update(first_32);
    let private_key_bytes = keccak_hasher_sk.finalize();

    let mut keccak_hasher_aes = Keccak256::new();
    keccak_hasher_aes.update(second_32);
    let aes_key_bytes = keccak_hasher_aes.finalize();

    if key_type == "edwards_on_bls12381" {
        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(&private_key_bytes);
        let sk = EdDSAPrivateKey::from_bytes(sk_bytes);
        let pk = sk.public();
        let pk_bytes = pk.to_compressed_bytes().unwrap();

        let response = serde_json::json!({
            "private_key_hex": hex::encode(sk_bytes),
            "public_key_hex": hex::encode(pk_bytes),
            "aes_key_hex": hex::encode(aes_key_bytes),
        });
        Ok(response.to_string())
    } else {
        // Default to Secp256k1
        let sk = K256SecretKey::from_slice(&private_key_bytes)
            .map_err(|e| JsError::new(&e.to_string()))?;
        let pk = sk.public_key();

        let response = serde_json::json!({
            "private_key_hex": hex::encode(sk.to_bytes()),
            "public_key_hex": hex::encode(pk.to_sec1_bytes()),
            "aes_key_hex": hex::encode(aes_key_bytes),
        });
        Ok(response.to_string())
    }
}

#[wasm_bindgen]
pub fn sign_challenge(private_key_hex: &str, challenge: &str) -> Result<String, JsError> {
    // Legacy support or Secp default
    sign_challenge_ecdsa(private_key_hex, challenge)
}

#[wasm_bindgen]
pub fn sign_challenge_ecdsa(private_key_hex: &str, challenge: &str) -> Result<String, JsError> {
    let sk_bytes = hex::decode(private_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let sk = K256SecretKey::from_slice(&sk_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let signing_key =
        EcdsaSigningKey::from_bytes(&sk.to_bytes()).map_err(|e| JsError::new(&e.to_string()))?;

    let challenge_uuid =
        uuid::Uuid::parse_str(challenge).map_err(|e| JsError::new(&e.to_string()))?;
    let challenge_bytes = challenge_uuid.as_bytes();

    let sig: EcdsaSignature =
        signing_key.sign_digest(Keccak256::new().chain_update(challenge_bytes));
    Ok(hex::encode(sig.to_der().as_bytes()))
}

#[wasm_bindgen]
pub fn sign_challenge_eddsa(private_key_hex: &str, challenge: &str) -> Result<String, JsError> {
    let sk_bytes_vec = hex::decode(private_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let mut sk_bytes = [0u8; 32];
    if sk_bytes_vec.len() != 32 {
        return Err(JsError::new("Invalid EdDSA key length"));
    }
    sk_bytes.copy_from_slice(&sk_bytes_vec);

    let sk = EdDSAPrivateKey::from_bytes(sk_bytes);

    let challenge_uuid =
        uuid::Uuid::parse_str(challenge).map_err(|e| JsError::new(&e.to_string()))?;
    let payload = challenge_uuid.as_bytes();

    let message = Keccak256::digest(payload).to_vec();
    let sig = sk.sign_bytes(&message);
    let sig_bytes = sig.to_compressed_bytes().unwrap();

    Ok(hex::encode(sig_bytes))
}

#[wasm_bindgen]
pub fn sign_message(private_key_hex: &str, message_hex: &str) -> Result<String, JsError> {
    sign_message_ecdsa(private_key_hex, message_hex)
}

#[wasm_bindgen]
pub fn sign_message_ecdsa(private_key_hex: &str, message_hex: &str) -> Result<String, JsError> {
    let sk_bytes = hex::decode(private_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let sk = K256SecretKey::from_slice(&sk_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let signing_key =
        EcdsaSigningKey::from_bytes(&sk.to_bytes()).map_err(|e| JsError::new(&e.to_string()))?;
    let message_bytes = hex::decode(message_hex).map_err(|e| JsError::new(&e.to_string()))?;

    let sig: EcdsaSignature =
        signing_key.sign_digest(Keccak256::new().chain_update(&message_bytes));
    Ok(hex::encode(sig.to_der().as_bytes()))
}

#[wasm_bindgen]
pub fn sign_message_eddsa(private_key_hex: &str, message_hex: &str) -> Result<String, JsError> {
    let sk_bytes_vec = hex::decode(private_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let mut sk_bytes = [0u8; 32];
    if sk_bytes_vec.len() != 32 {
        return Err(JsError::new("Invalid EdDSA key length"));
    }
    sk_bytes.copy_from_slice(&sk_bytes_vec);

    let sk = EdDSAPrivateKey::from_bytes(sk_bytes);
    let message_bytes = hex::decode(message_hex).map_err(|e| JsError::new(&e.to_string()))?;

    let message_hash = Keccak256::digest(&message_bytes).to_vec();
    let sig = sk.sign_bytes(&message_hash);

    Ok(hex::encode(sig.to_compressed_bytes().unwrap()))
}

#[wasm_bindgen]
pub fn get_identifier_hex(id: u16) -> Result<String, JsError> {
    let scalar = k256::Scalar::from(id as u64);
    let identifier = frost::Identifier::new(scalar).map_err(|e| JsError::new(&e.to_string()))?;
    let identifier_bytes = identifier.serialize();
    Ok(hex::encode(identifier_bytes))
}

// ====================================================================
// region: Auth Payload Construction
// ====================================================================

#[wasm_bindgen]
pub fn get_auth_payload_round1(
    session_id: &str,
    id_hex: &str,
    pkg_hex: &str,
) -> Result<String, JsError> {
    let id: frost::Identifier =
        bincode::deserialize(&hex::decode(id_hex).map_err(|e| JsError::new(&e.to_string()))?)
            .map_err(|e| JsError::new(&e.to_string()))?;
    let pkg: frost::keys::dkg::round1::Package =
        bincode::deserialize(&hex::decode(pkg_hex).map_err(|e| JsError::new(&e.to_string()))?)
            .map_err(|e| JsError::new(&e.to_string()))?;

    let mut v = b"TOKAMAK_FROST_DKG_R1|".to_vec();
    v.extend_from_slice(session_id.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(&id).unwrap());
    v.extend_from_slice(&bincode::serialize(&pkg).unwrap());

    Ok(hex::encode(v))
}

#[wasm_bindgen]
pub fn get_auth_payload_round2(
    session_id: &str,
    from_id_hex: &str,
    to_id_hex: &str,
    eph_pub_hex: &str,
    nonce_hex: &str,
    ct_hex: &str,
) -> Result<String, JsError> {
    let from_id: frost::Identifier =
        bincode::deserialize(&hex::decode(from_id_hex).map_err(|e| JsError::new(&e.to_string()))?)
            .map_err(|e| JsError::new(&e.to_string()))?;
    let to_id: frost::Identifier =
        bincode::deserialize(&hex::decode(to_id_hex).map_err(|e| JsError::new(&e.to_string()))?)
            .map_err(|e| JsError::new(&e.to_string()))?;
    let eph_pub_bytes = hex::decode(eph_pub_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let ct_bytes = hex::decode(ct_hex).map_err(|e| JsError::new(&e.to_string()))?;

    let mut v = b"TOKAMAK_FROST_DKG_R2|".to_vec();
    v.extend_from_slice(session_id.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(&from_id).unwrap());
    v.extend_from_slice(&bincode::serialize(&to_id).unwrap());
    v.extend_from_slice(&eph_pub_bytes);
    v.extend_from_slice(&nonce_bytes);
    v.extend_from_slice(&ct_bytes);

    Ok(hex::encode(v))
}

#[wasm_bindgen]
pub fn get_auth_payload_finalize(
    session_id: &str,
    id_hex: &str,
    group_vk_hex: &str,
) -> Result<String, JsError> {
    let id: frost::Identifier =
        bincode::deserialize(&hex::decode(id_hex).map_err(|e| JsError::new(&e.to_string()))?)
            .map_err(|e| JsError::new(&e.to_string()))?;
    let group_vk_bytes = hex::decode(group_vk_hex).map_err(|e| JsError::new(&e.to_string()))?;

    let mut v = b"TOKAMAK_FROST_DKG_FIN|".to_vec();
    v.extend_from_slice(session_id.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(&id).unwrap());
    v.extend_from_slice(&group_vk_bytes);

    Ok(hex::encode(v))
}

#[wasm_bindgen]
pub fn get_auth_payload_sign_r1(
    session_id: &str,
    group_id: &str,
    id_hex: &str,
    commits_hex: &str,
) -> Result<String, JsError> {
    let payload = format!(
        "SIGN_WS_R1|{}|{}|{}|{}",
        session_id, group_id, id_hex, commits_hex
    );
    Ok(hex::encode(payload.into_bytes()))
}

#[wasm_bindgen]
pub fn get_auth_payload_sign_r2(
    session_id: &str,
    group_id: &str,
    id_hex: &str,
    sigshare_hex: &str,
    msg32_hex: &str,
) -> Result<String, JsError> {
    let payload = format!(
        "SIGN_WS_R2|{}|{}|{}|{}|{}",
        session_id, group_id, id_hex, sigshare_hex, msg32_hex
    );
    Ok(hex::encode(payload.into_bytes()))
}

// ====================================================================
// region: DKG Round Logic
// ====================================================================

#[wasm_bindgen]
pub fn dkg_part1(
    identifier_hex: &str,
    max_signers: u16,
    min_signers: u16,
) -> Result<String, JsError> {
    let identifier_bytes = hex::decode(identifier_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let identifier_array: [u8; 32] = identifier_bytes
        .try_into()
        .map_err(|_| JsError::new("Identifier hex must be 32 bytes"))?;
    let identifier = frost::Identifier::deserialize(&identifier_array)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let (secret_pkg, public_pkg) =
        frost::keys::dkg::part1(identifier, max_signers, min_signers, OsRng)
            .map_err(|e| JsError::new(&e.to_string()))?;

    let response = serde_json::json!({
        "secret_package_hex": hex::encode(bincode::serialize(&secret_pkg).unwrap()),
        "public_package_hex": hex::encode(bincode::serialize(&public_pkg).unwrap()),
    });
    Ok(response.to_string())
}

#[wasm_bindgen]
pub fn dkg_part2(
    secret_package_hex: &str,
    round1_packages_hex: JsValue,
) -> Result<String, JsError> {
    let secret_pkg: frost::keys::dkg::round1::SecretPackage = bincode::deserialize(
        &hex::decode(secret_package_hex).map_err(|e| JsError::new(&e.to_string()))?,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    let round1_packages_str: BTreeMap<String, String> =
        serde_wasm_bindgen::from_value(round1_packages_hex)?;

    let mut round1_packages = BTreeMap::new();
    for (id_hex, pkg_hex) in round1_packages_str {
        let id_bytes = hex::decode(id_hex).map_err(|e| JsError::new(&e.to_string()))?;
        let id_array: [u8; 32] = id_bytes
            .try_into()
            .map_err(|_| JsError::new("Identifier hex must be 32 bytes"))?;
        let id =
            frost::Identifier::deserialize(&id_array).map_err(|e| JsError::new(&e.to_string()))?;
        let pkg: frost::keys::dkg::round1::Package =
            bincode::deserialize(&hex::decode(pkg_hex).map_err(|e| JsError::new(&e.to_string()))?)
                .map_err(|e| JsError::new(&e.to_string()))?;
        round1_packages.insert(id, pkg);
    }

    let (secret_pkg_r2, public_pkgs_r2) = frost::keys::dkg::part2(secret_pkg, &round1_packages)
        .map_err(|e| JsError::new(&e.to_string()))?;

    let mut outgoing_packages_hex = BTreeMap::new();
    for (id, pkg) in public_pkgs_r2 {
        let id_bytes = id.serialize();
        let pkg_hex = hex::encode(bincode::serialize(&pkg).unwrap());
        outgoing_packages_hex.insert(hex::encode(id_bytes), pkg_hex);
    }

    let response = serde_json::json!({
        "secret_package_hex": hex::encode(bincode::serialize(&secret_pkg_r2).unwrap()),
        "outgoing_packages": outgoing_packages_hex,
    });
    Ok(response.to_string())
}

#[wasm_bindgen]
pub fn dkg_part3(
    secret_package_hex: &str,
    round1_packages_hex: JsValue,
    round2_packages_hex: JsValue,
    group_id: &str,
    roster_js: JsValue,
    key_type: &str,
) -> Result<String, JsError> {
    let secret_pkg: frost::keys::dkg::round2::SecretPackage = bincode::deserialize(
        &hex::decode(secret_package_hex).map_err(|e| JsError::new(&e.to_string()))?,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    let round1_packages_str: BTreeMap<String, String> =
        serde_wasm_bindgen::from_value(round1_packages_hex)?;
    let round2_packages_str: BTreeMap<String, String> =
        serde_wasm_bindgen::from_value(round2_packages_hex)?;
    let roster: BTreeMap<u32, String> = serde_wasm_bindgen::from_value(roster_js)?;

    let mut round1_packages = BTreeMap::new();
    for (id_hex, pkg_hex) in round1_packages_str {
        let id_bytes = hex::decode(id_hex).map_err(|e| JsError::new(&e.to_string()))?;
        let id_array: [u8; 32] = id_bytes
            .try_into()
            .map_err(|_| JsError::new("Identifier hex must be 32 bytes"))?;
        let id =
            frost::Identifier::deserialize(&id_array).map_err(|e| JsError::new(&e.to_string()))?;
        let pkg: frost::keys::dkg::round1::Package =
            bincode::deserialize(&hex::decode(pkg_hex).map_err(|e| JsError::new(&e.to_string()))?)
                .map_err(|e| JsError::new(&e.to_string()))?;
        round1_packages.insert(id, pkg);
    }

    let mut round2_packages = BTreeMap::new();
    for (id_hex, pkg_hex) in round2_packages_str {
        let id_bytes = hex::decode(id_hex).map_err(|e| JsError::new(&e.to_string()))?;
        let id_array: [u8; 32] = id_bytes
            .try_into()
            .map_err(|_| JsError::new("Identifier hex must be 32 bytes"))?;
        let id =
            frost::Identifier::deserialize(&id_array).map_err(|e| JsError::new(&e.to_string()))?;
        let pkg: frost::keys::dkg::round2::Package =
            bincode::deserialize(&hex::decode(pkg_hex).map_err(|e| JsError::new(&e.to_string()))?)
                .map_err(|e| JsError::new(&e.to_string()))?;
        round2_packages.insert(id, pkg);
    }

    let (key_package, public_key_package) =
        frost::keys::dkg::part3(&secret_pkg, &round1_packages, &round2_packages)
            .map_err(|e| JsError::new(&e.to_string()))?;

    let key_package_with_metadata = KeyPackageWithMetadata {
        key_package,
        threshold: *secret_pkg.min_signers(),
        group_id: group_id.to_string(),
        roster,
        roster_key_type: key_type.to_string(),
    };

    let response = serde_json::json!({
        "key_package_hex": hex::encode(bincode::serialize(&key_package_with_metadata).unwrap()),
        "group_public_key_hex": hex::encode(public_key_package.verifying_key().serialize().unwrap()),
    });
    Ok(response.to_string())
}

// ... Additional helper functions from original file ...

#[wasm_bindgen]
pub fn get_key_package_metadata(key_package_hex: &str) -> Result<String, JsError> {
    let key_package_with_metadata: KeyPackageWithMetadata = bincode::deserialize(
        &hex::decode(key_package_hex).map_err(|e| JsError::new(&e.to_string()))?,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    let response = serde_json::json!({
        "group_id": key_package_with_metadata.group_id,
        "threshold": key_package_with_metadata.threshold,
        "roster": key_package_with_metadata.roster,
        "roster_key_type": key_package_with_metadata.roster_key_type,
        "group_public_key": hex::encode(key_package_with_metadata.key_package.verifying_key().serialize().map_err(|e| JsError::new(&e.to_string()))?),
    });
    Ok(response.to_string())
}

#[wasm_bindgen]
pub fn get_signing_prerequisites(key_package_hex: &str) -> Result<String, JsError> {
    let key_package_with_metadata: KeyPackageWithMetadata = bincode::deserialize(
        &hex::decode(key_package_hex).map_err(|e| JsError::new(&e.to_string()))?,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    let key_package = key_package_with_metadata.key_package;

    let response = serde_json::json!({
        "signer_id_bincode_hex": hex::encode(bincode::serialize(key_package.identifier()).unwrap()),
        "verifying_share_bincode_hex": hex::encode(bincode::serialize(key_package.verifying_share()).unwrap()),
    });
    Ok(response.to_string())
}

#[wasm_bindgen]
pub fn sign_part1_commit(key_package_hex: &str) -> Result<String, JsError> {
    let key_package_with_metadata: KeyPackageWithMetadata = bincode::deserialize(
        &hex::decode(key_package_hex).map_err(|e| JsError::new(&e.to_string()))?,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    let key_package = key_package_with_metadata.key_package;
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut OsRng);

    let response = serde_json::json!({
        "nonces_hex": hex::encode(bincode::serialize(&nonces).unwrap()),
        "commitments_hex": hex::encode(bincode::serialize(&commitments).unwrap()),
    });
    Ok(response.to_string())
}

#[wasm_bindgen]
pub fn sign_part2_sign(
    key_package_hex: &str,
    nonces_hex: &str,
    signing_package_hex: &str,
) -> Result<String, JsError> {
    let key_package_with_metadata: KeyPackageWithMetadata = bincode::deserialize(
        &hex::decode(key_package_hex).map_err(|e| JsError::new(&e.to_string()))?,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;
    let key_package = key_package_with_metadata.key_package;
    let nonces: frost::round1::SigningNonces =
        bincode::deserialize(&hex::decode(nonces_hex).map_err(|e| JsError::new(&e.to_string()))?)
            .map_err(|e| JsError::new(&e.to_string()))?;
    let signing_package: frost::SigningPackage = bincode::deserialize(
        &hex::decode(signing_package_hex).map_err(|e| JsError::new(&e.to_string()))?,
    )
    .map_err(|e| JsError::new(&e.to_string()))?;

    let signature_share = frost::round2::sign(&signing_package, &nonces, &key_package)
        .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(hex::encode(bincode::serialize(&signature_share).unwrap()))
}

// ====================================================================
// region: Share Encryption/Decryption
// ====================================================================

#[wasm_bindgen]
pub fn encrypt_share(aes_key_hex: &str, share_plaintext_hex: &str) -> Result<String, JsError> {
    let key_bytes = hex::decode(aes_key_hex)
        .map_err(|e| JsError::new(&format!("Invalid AES key hex: {}", e)))?;
    let plaintext = hex::decode(share_plaintext_hex)
        .map_err(|e| JsError::new(&format!("Invalid plaintext hex: {}", e)))?;

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| JsError::new(&format!("Failed to create cipher: {}", e)))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|e| JsError::new(&format!("Encryption failed: {}", e)))?;

    let encrypted_share = EncryptedShare {
        ciphertext_hex: hex::encode(ciphertext),
        nonce_hex: hex::encode(nonce),
    };

    serde_json::to_string(&encrypted_share)
        .map_err(|e| JsError::new(&format!("Failed to serialize encrypted share: {}", e)))
}

#[wasm_bindgen]
pub fn decrypt_share(aes_key_hex: &str, encrypted_share_json: &str) -> Result<String, JsError> {
    let key_bytes = hex::decode(aes_key_hex)
        .map_err(|e| JsError::new(&format!("Invalid AES key hex: {}", e)))?;
    let encrypted_share: EncryptedShare = serde_json::from_str(encrypted_share_json)
        .map_err(|e| JsError::new(&format!("Failed to parse encrypted share JSON: {}", e)))?;

    let ciphertext = hex::decode(encrypted_share.ciphertext_hex)
        .map_err(|e| JsError::new(&format!("Invalid ciphertext hex: {}", e)))?;
    let nonce_bytes = hex::decode(encrypted_share.nonce_hex)
        .map_err(|e| JsError::new(&format!("Invalid nonce hex: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .map_err(|e| JsError::new(&format!("Failed to create cipher: {}", e)))?;
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| JsError::new(&format!("Decryption failed: {}", e)))?;

    Ok(hex::encode(plaintext))
}

// ====================================================================
// region: ECIES Encryption (Dual support)
// ====================================================================

#[wasm_bindgen]
pub fn ecies_encrypt(recipient_pubkey_hex: &str, plaintext_hex: &str) -> Result<String, JsError> {
    // Default or Secp? user provided function renamed to ecies_encrypt_ecdsa?
    // Let's call ecies_encrypt_ecdsa
    ecies_encrypt_ecdsa(recipient_pubkey_hex, plaintext_hex)
}

#[wasm_bindgen]
pub fn ecies_encrypt_ecdsa(
    recipient_pubkey_hex: &str,
    plaintext_hex: &str,
) -> Result<String, JsError> {
    let recipient_pk_bytes =
        hex::decode(recipient_pubkey_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let recipient_pk = k256::PublicKey::from_sec1_bytes(&recipient_pk_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let plaintext = hex::decode(plaintext_hex).map_err(|e| JsError::new(&e.to_string()))?;

    let ephemeral_sk = k256::ecdh::EphemeralSecret::random(&mut OsRng);
    let ephemeral_pk_bytes = ephemeral_sk.public_key().to_sec1_bytes();

    let shared_secret = ephemeral_sk.diffie_hellman(&recipient_pk);
    let salt = Keccak256::digest(shared_secret.raw_secret_bytes());

    let cipher = Aes256Gcm::new_from_slice(&salt).map_err(|e| JsError::new(&e.to_string()))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_slice())
        .map_err(|e| JsError::new(&e.to_string()))?;

    let response = serde_json::json!({
        "ephemeral_public_key_hex": hex::encode(ephemeral_pk_bytes),
        "nonce_hex": hex::encode(nonce),
        "ciphertext_hex": hex::encode(ciphertext),
    });
    Ok(response.to_string())
}

// Ported from helper/lib.rs: encrypt_with_edwards_curve
#[wasm_bindgen]
pub fn ecies_encrypt_eddsa(
    recipient_pubkey_hex: &str,
    plaintext_hex: &str,
) -> Result<String, JsError> {
    let receiver_pk_bytes =
        hex::decode(recipient_pubkey_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let message = hex::decode(plaintext_hex).map_err(|e| JsError::new(&e.to_string()))?;

    let (ephemeral_pk_bytes, encrypted_msg) =
        encrypt_with_edwards_curve(&receiver_pk_bytes, &message)
            .map_err(|e| JsError::new(&e.to_string()))?;

    // helper returns (ephemeral_pk_bytes, nonce || ciphertext)
    // We need to split nonce and ciphertext for the JSON response
    if encrypted_msg.len() < 12 {
        return Err(JsError::new("Encrypted message too short"));
    }
    let nonce_bytes = &encrypted_msg[0..12];
    let ciphertext = &encrypted_msg[12..];

    let response = serde_json::json!({
        "ephemeral_public_key_hex": hex::encode(ephemeral_pk_bytes),
        "nonce_hex": hex::encode(nonce_bytes),
        "ciphertext_hex": hex::encode(ciphertext),
    });
    Ok(response.to_string())
}

#[wasm_bindgen]
pub fn ecies_decrypt(
    recipient_private_key_hex: &str,
    ephemeral_public_key_hex: &str,
    nonce_hex: &str,
    ciphertext_hex: &str,
) -> Result<String, JsError> {
    ecies_decrypt_ecdsa(
        recipient_private_key_hex,
        ephemeral_public_key_hex,
        nonce_hex,
        ciphertext_hex,
    )
}

#[wasm_bindgen]
pub fn ecies_decrypt_ecdsa(
    recipient_private_key_hex: &str,
    ephemeral_public_key_hex: &str,
    nonce_hex: &str,
    ciphertext_hex: &str,
) -> Result<String, JsError> {
    let recipient_sk_bytes =
        hex::decode(recipient_private_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let recipient_sk =
        K256SecretKey::from_slice(&recipient_sk_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let ephemeral_pk_bytes =
        hex::decode(ephemeral_public_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let ephemeral_pk = k256::PublicKey::from_sec1_bytes(&ephemeral_pk_bytes)
        .map_err(|e| JsError::new(&e.to_string()))?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let ciphertext = hex::decode(ciphertext_hex).map_err(|e| JsError::new(&e.to_string()))?;

    let shared_secret =
        k256::ecdh::diffie_hellman(recipient_sk.to_nonzero_scalar(), ephemeral_pk.as_affine());
    let salt = Keccak256::digest(shared_secret.raw_secret_bytes());

    let cipher = Aes256Gcm::new_from_slice(&salt).map_err(|e| JsError::new(&e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(hex::encode(plaintext))
}

// Ported from helper/lib.rs: decrypt_with_edwards_curve
// Ported from helper/lib.rs: decrypt_with_edwards_curve
#[wasm_bindgen]
pub fn ecies_decrypt_eddsa(
    recipient_private_key_hex: &str,
    ephemeral_public_key_hex: &str,
    nonce_hex: &str,
    ciphertext_hex: &str,
) -> Result<String, JsError> {
    let sk_bytes_vec =
        hex::decode(recipient_private_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let mut sk_bytes = [0u8; 32];
    if sk_bytes_vec.len() != 32 {
        return Err(JsError::new("Invalid EdDSA SK length"));
    }
    sk_bytes.copy_from_slice(&sk_bytes_vec);

    let ephemeral_pk_bytes =
        hex::decode(ephemeral_public_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let ciphertext = hex::decode(ciphertext_hex).map_err(|e| JsError::new(&e.to_string()))?;

    // helper expects nonce || ciphertext
    let mut encrypted_msg = nonce_bytes;
    encrypted_msg.extend(ciphertext);

    let plaintext = decrypt_with_edwards_curve(&sk_bytes, &ephemeral_pk_bytes, &encrypted_msg)
        .map_err(|e| JsError::new(&e.to_string()))?;

    Ok(hex::encode(plaintext))
}

#[wasm_bindgen]
pub fn to_compressed_point(uncompressed_point_hex: &str) -> Result<String, JsError> {
    let buffer = hex::decode(uncompressed_point_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let point = EncodedPoint::from_bytes(buffer.as_slice()).unwrap();
    let response = serde_json::json!({
       "point": hex::encode(point.compress().as_bytes()),
    });
    Ok(response.to_string())
}
