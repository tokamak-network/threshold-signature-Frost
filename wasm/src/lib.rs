use wasm_bindgen::prelude::*;
use rand::rngs::OsRng;
use k256::ecdsa::{
    Signature as EcdsaSignature,
    SigningKey as EcdsaSigningKey,
    VerifyingKey as EcdsaVerifyingKey,
};
use k256::SecretKey as K256SecretKey;
use sha3::{Digest, Keccak256};
use signature::{DigestSigner, DigestVerifier};
use frost_secp256k1 as frost;
use std::collections::BTreeMap;
use anyhow::Result;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, AeadCore};

// ====================================================================
// region: Initialization
// ====================================================================

#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
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
pub fn sign_challenge(private_key_hex: &str, challenge: &str) -> Result<String, JsError> {
    let sk_bytes = hex::decode(private_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let sk = K256SecretKey::from_slice(&sk_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let signing_key = EcdsaSigningKey::from_bytes(&sk.to_bytes()).expect("dd");
    let challenge_uuid = uuid::Uuid::parse_str(challenge).map_err(|e| JsError::new(&e.to_string()))?;
    let challenge_bytes = challenge_uuid.as_bytes();

    let sig: EcdsaSignature = signing_key.sign_digest(Keccak256::new().chain_update(challenge_bytes));
    Ok(hex::encode(sig.to_der().as_bytes()))
}

#[wasm_bindgen]
pub fn sign_message(private_key_hex: &str, message_hex: &str) -> Result<String, JsError> {
    let sk_bytes = hex::decode(private_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let sk = K256SecretKey::from_slice(&sk_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let signing_key = EcdsaSigningKey::from_bytes(&sk.to_bytes()).expect("dd");
    let message_bytes = hex::decode(message_hex).map_err(|e| JsError::new(&e.to_string()))?;

    let sig: EcdsaSignature = signing_key.sign_digest(Keccak256::new().chain_update(&message_bytes));
    Ok(hex::encode(sig.to_der().as_bytes()))
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
pub fn get_auth_payload_round1(session_id: &str, id_hex: &str, pkg_hex: &str) -> Result<String, JsError> {
    let id: frost::Identifier = bincode::deserialize(&hex::decode(id_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
    let pkg: frost::keys::dkg::round1::Package = bincode::deserialize(&hex::decode(pkg_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;

    let mut v = b"TOKAMAK_FROST_DKG_R1|".to_vec();
    v.extend_from_slice(session_id.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(&id).unwrap());
    v.extend_from_slice(&bincode::serialize(&pkg).unwrap());

    Ok(hex::encode(v))
}

#[wasm_bindgen]
pub fn get_auth_payload_round2(session_id: &str, from_id_hex: &str, to_id_hex: &str, eph_pub_hex: &str, nonce_hex: &str, ct_hex: &str) -> Result<String, JsError> {
    let from_id: frost::Identifier = bincode::deserialize(&hex::decode(from_id_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
    let to_id: frost::Identifier = bincode::deserialize(&hex::decode(to_id_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
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
pub fn get_auth_payload_finalize(session_id: &str, id_hex: &str, group_vk_hex: &str) -> Result<String, JsError> {
    let id: frost::Identifier = bincode::deserialize(&hex::decode(id_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
    let group_vk_bytes = hex::decode(group_vk_hex).map_err(|e| JsError::new(&e.to_string()))?;

    let mut v = b"TOKAMAK_FROST_DKG_FIN|".to_vec();
    v.extend_from_slice(session_id.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(&id).unwrap());
    v.extend_from_slice(&group_vk_bytes);

    Ok(hex::encode(v))
}

// ====================================================================
// region: DKG Round Logic
// ====================================================================

#[wasm_bindgen]
pub fn dkg_part1(identifier_hex: &str, max_signers: u16, min_signers: u16) -> Result<String, JsError> {
    let identifier_bytes = hex::decode(identifier_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let identifier_array: [u8; 32] = identifier_bytes.try_into().map_err(|_| JsError::new("Identifier hex must be 32 bytes"))?;
    let identifier = frost::Identifier::deserialize(&identifier_array).map_err(|e| JsError::new(&e.to_string()))?;

    let (secret_pkg, public_pkg) = frost::keys::dkg::part1(identifier, max_signers, min_signers, &mut OsRng).map_err(|e| JsError::new(&e.to_string()))?;

    let response = serde_json::json!({
        "secret_package_hex": hex::encode(bincode::serialize(&secret_pkg).unwrap()),
        "public_package_hex": hex::encode(bincode::serialize(&public_pkg).unwrap()),
    });
    Ok(response.to_string())
}

#[wasm_bindgen]
pub fn dkg_part2(secret_package_hex: &str, round1_packages_hex: JsValue) -> Result<String, JsError> {
    let secret_pkg: frost::keys::dkg::round1::SecretPackage = bincode::deserialize(&hex::decode(secret_package_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
    let round1_packages_str: BTreeMap<String, String> = serde_wasm_bindgen::from_value(round1_packages_hex)?;

    let mut round1_packages = BTreeMap::new();
    for (id_hex, pkg_hex) in round1_packages_str {
        let id_bytes = hex::decode(id_hex).map_err(|e| JsError::new(&e.to_string()))?;
        let id_array: [u8; 32] = id_bytes.try_into().map_err(|_| JsError::new("Identifier hex must be 32 bytes"))?;
        let id = frost::Identifier::deserialize(&id_array).map_err(|e| JsError::new(&e.to_string()))?;
        let pkg: frost::keys::dkg::round1::Package = bincode::deserialize(&hex::decode(pkg_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
        round1_packages.insert(id, pkg);
    }

    let (secret_pkg_r2, public_pkgs_r2) = frost::keys::dkg::part2(secret_pkg, &round1_packages).map_err(|e| JsError::new(&e.to_string()))?;

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
pub fn dkg_part3(secret_package_hex: &str, round1_packages_hex: JsValue, round2_packages_hex: JsValue) -> Result<String, JsError> {
    let secret_pkg: frost::keys::dkg::round2::SecretPackage = bincode::deserialize(&hex::decode(secret_package_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
    let round1_packages_str: BTreeMap<String, String> = serde_wasm_bindgen::from_value(round1_packages_hex)?;
    let round2_packages_str: BTreeMap<String, String> = serde_wasm_bindgen::from_value(round2_packages_hex)?;

    let mut round1_packages = BTreeMap::new();
    for (id_hex, pkg_hex) in round1_packages_str {
        let id_bytes = hex::decode(id_hex).map_err(|e| JsError::new(&e.to_string()))?;
        let id_array: [u8; 32] = id_bytes.try_into().map_err(|_| JsError::new("Identifier hex must be 32 bytes"))?;
        let id = frost::Identifier::deserialize(&id_array).map_err(|e| JsError::new(&e.to_string()))?;
        let pkg: frost::keys::dkg::round1::Package = bincode::deserialize(&hex::decode(pkg_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
        round1_packages.insert(id, pkg);
    }

    let mut round2_packages = BTreeMap::new();
    for (id_hex, pkg_hex) in round2_packages_str {
        let id_bytes = hex::decode(id_hex).map_err(|e| JsError::new(&e.to_string()))?;
        let id_array: [u8; 32] = id_bytes.try_into().map_err(|_| JsError::new("Identifier hex must be 32 bytes"))?;
        let id = frost::Identifier::deserialize(&id_array).map_err(|e| JsError::new(&e.to_string()))?;
        let pkg: frost::keys::dkg::round2::Package = bincode::deserialize(&hex::decode(pkg_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
        round2_packages.insert(id, pkg);
    }

    let (key_package, public_key_package) = frost::keys::dkg::part3(&secret_pkg, &round1_packages, &round2_packages).map_err(|e| JsError::new(&e.to_string()))?;

    let response = serde_json::json!({
        "key_package_hex": hex::encode(bincode::serialize(&key_package).unwrap()),
        "group_public_key_hex": hex::encode(public_key_package.verifying_key().serialize().unwrap()),
    });
    Ok(response.to_string())
}

// ====================================================================
// region: ECIES Encryption
// ====================================================================

#[wasm_bindgen]
pub fn ecies_encrypt(recipient_pubkey_hex: &str, plaintext_hex: &str) -> Result<String, JsError> {
    let recipient_pk_bytes = hex::decode(recipient_pubkey_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let recipient_pk = k256::PublicKey::from_sec1_bytes(&recipient_pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let plaintext = hex::decode(plaintext_hex).map_err(|e| JsError::new(&e.to_string()))?;

    let ephemeral_sk = k256::ecdh::EphemeralSecret::random(&mut OsRng);
    let ephemeral_pk_bytes = ephemeral_sk.public_key().to_sec1_bytes();

    let shared_secret = ephemeral_sk.diffie_hellman(&recipient_pk);
    let salt = Keccak256::digest(shared_secret.raw_secret_bytes());

    let cipher = Aes256Gcm::new_from_slice(&salt).map_err(|e| JsError::new(&e.to_string()))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_slice()).map_err(|e| JsError::new(&e.to_string()))?;

    let response = serde_json::json!({
        "ephemeral_public_key_hex": hex::encode(ephemeral_pk_bytes),
        "nonce_hex": hex::encode(nonce),
        "ciphertext_hex": hex::encode(ciphertext),
    });
    Ok(response.to_string())
}

#[wasm_bindgen]
pub fn ecies_decrypt(recipient_private_key_hex: &str, ephemeral_public_key_hex: &str, nonce_hex: &str, ciphertext_hex: &str) -> Result<String, JsError> {
    let recipient_sk_bytes = hex::decode(recipient_private_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let recipient_sk = K256SecretKey::from_slice(&recipient_sk_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let ephemeral_pk_bytes = hex::decode(ephemeral_public_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let ephemeral_pk = k256::PublicKey::from_sec1_bytes(&ephemeral_pk_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let nonce_bytes = hex::decode(nonce_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let ciphertext = hex::decode(ciphertext_hex).map_err(|e| JsError::new(&e.to_string()))?;

    let shared_secret = k256::ecdh::diffie_hellman(recipient_sk.to_nonzero_scalar(), ephemeral_pk.as_affine());
    let salt = Keccak256::digest(shared_secret.raw_secret_bytes());

    let cipher = Aes256Gcm::new_from_slice(&salt).map_err(|e| JsError::new(&e.to_string()))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|e| JsError::new(&e.to_string()))?;

    Ok(hex::encode(plaintext))
}
