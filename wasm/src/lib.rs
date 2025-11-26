use wasm_bindgen::prelude::*;
use rand::rngs::OsRng;
use k256::ecdsa::{
    Signature as EcdsaSignature,
    SigningKey as EcdsaSigningKey,
    VerifyingKey as EcdsaVerifyingKey,
};
use k256::SecretKey as K256SecretKey;
use sha2::Sha512;
use sha3::{Digest, Keccak256};
use signature::{DigestSigner, DigestVerifier};
use frost_secp256k1 as frost;
use std::collections::BTreeMap;
use anyhow::Result;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::{Aead, AeadCore};
use serde::{Serialize, Deserialize};

// ====================================================================
// region: Custom Structs
// ====================================================================

#[derive(Serialize, Deserialize)]
struct KeyPackageWithMetadata {
    key_package: frost::keys::KeyPackage,
    threshold: u16,
    group_id: String,
    roster: BTreeMap<u32, String>,
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
// region: Hashing Utilities
// ====================================================================

#[wasm_bindgen]
pub fn keccak256(message: &str) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(message.as_bytes());
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
pub fn derive_keys_from_signature(signature_hex: &str) -> Result<String, JsError> {
    let sig_bytes = hex::decode(signature_hex.trim_start_matches("0x")).map_err(|e| JsError::new(&e.to_string()))?;

    // Hash the signature with SHA-512
    let mut sha512_hasher = Sha512::new();
    sha512_hasher.update(&sig_bytes);
    let sha512_result = sha512_hasher.finalize();

    // Split the 64-byte hash into two 32-byte chunks
    let (first_32, second_32) = sha512_result.split_at(32);

    // Derive the roster private key
    let mut keccak_hasher_sk = Keccak256::new();
    keccak_hasher_sk.update(first_32);
    let private_key_bytes = keccak_hasher_sk.finalize();
    let sk = K256SecretKey::from_slice(&private_key_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let pk = sk.public_key();

    // Derive the AES key
    let mut keccak_hasher_aes = Keccak256::new();
    keccak_hasher_aes.update(second_32);
    let aes_key_bytes = keccak_hasher_aes.finalize();

    let response = serde_json::json!({
        "private_key_hex": hex::encode(sk.to_bytes()),
        "public_key_hex": hex::encode(pk.to_sec1_bytes()),
        "aes_key_hex": hex::encode(aes_key_bytes),
    });
    Ok(response.to_string())
}

#[wasm_bindgen]
pub fn sign_challenge(private_key_hex: &str, challenge: &str) -> Result<String, JsError> {
    let sk_bytes = hex::decode(private_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let sk = K256SecretKey::from_slice(&sk_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let signing_key = EcdsaSigningKey::from_bytes(&sk.to_bytes()).map_err(|e| JsError::new(&e.to_string()))?;

    let challenge_uuid = uuid::Uuid::parse_str(challenge).map_err(|e| JsError::new(&e.to_string()))?;
    let challenge_bytes = challenge_uuid.as_bytes();

    let sig: EcdsaSignature = signing_key.sign_digest(Keccak256::new().chain_update(challenge_bytes));
    Ok(hex::encode(sig.to_der().as_bytes()))
}

#[wasm_bindgen]
pub fn sign_message(private_key_hex: &str, message_hex: &str) -> Result<String, JsError> {
    let sk_bytes = hex::decode(private_key_hex).map_err(|e| JsError::new(&e.to_string()))?;
    let sk = K256SecretKey::from_slice(&sk_bytes).map_err(|e| JsError::new(&e.to_string()))?;
    let signing_key = EcdsaSigningKey::from_bytes(&sk.to_bytes()).map_err(|e| JsError::new(&e.to_string()))?;
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

#[wasm_bindgen]
pub fn get_auth_payload_sign_r1(session_id: &str, group_id: &str, id_hex: &str, commits_hex: &str) -> Result<String, JsError> {
    let payload = format!("SIGN_WS_R1|{}|{}|{}|{}", session_id, group_id, id_hex, commits_hex);
    Ok(hex::encode(payload.into_bytes()))
}

#[wasm_bindgen]
pub fn get_auth_payload_sign_r2(session_id: &str, group_id: &str, id_hex: &str, sigshare_hex: &str, msg32_hex: &str) -> Result<String, JsError> {
    let payload = format!("SIGN_WS_R2|{}|{}|{}|{}|{}", session_id, group_id, id_hex, sigshare_hex, msg32_hex);
    Ok(hex::encode(payload.into_bytes()))
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
pub fn dkg_part3(secret_package_hex: &str, round1_packages_hex: JsValue, round2_packages_hex: JsValue, group_id: &str, roster_js: JsValue) -> Result<String, JsError> {
    let secret_pkg: frost::keys::dkg::round2::SecretPackage = bincode::deserialize(&hex::decode(secret_package_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
    let round1_packages_str: BTreeMap<String, String> = serde_wasm_bindgen::from_value(round1_packages_hex)?;
    let round2_packages_str: BTreeMap<String, String> = serde_wasm_bindgen::from_value(round2_packages_hex)?;
    let roster: BTreeMap<u32, String> = serde_wasm_bindgen::from_value(roster_js)?;

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

    let key_package_with_metadata = KeyPackageWithMetadata {
        key_package,
        threshold: *secret_pkg.min_signers(),
        group_id: group_id.to_string(),
        roster,
    };

    let response = serde_json::json!({
        "key_package_hex": hex::encode(bincode::serialize(&key_package_with_metadata).unwrap()),
        "group_public_key_hex": hex::encode(public_key_package.verifying_key().serialize().unwrap()),
    });
    Ok(response.to_string())
}

// ====================================================================
// region: Interactive Signing Logic
// ====================================================================

#[wasm_bindgen]
pub fn get_key_package_metadata(key_package_hex: &str) -> Result<String, JsError> {
    let key_package_with_metadata: KeyPackageWithMetadata = bincode::deserialize(&hex::decode(key_package_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;

    let response = serde_json::json!({
        "group_id": key_package_with_metadata.group_id,
        "threshold": key_package_with_metadata.threshold,
        "roster": key_package_with_metadata.roster,
        "group_public_key": hex::encode(key_package_with_metadata.key_package.verifying_key().serialize().map_err(|e| JsError::new(&e.to_string()))?),
    });
    Ok(response.to_string())
}

#[wasm_bindgen]
pub fn get_signing_prerequisites(key_package_hex: &str) -> Result<String, JsError> {
    let key_package_with_metadata: KeyPackageWithMetadata = bincode::deserialize(&hex::decode(key_package_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
    let key_package = key_package_with_metadata.key_package;

    let response = serde_json::json!({
        "signer_id_bincode_hex": hex::encode(bincode::serialize(key_package.identifier()).unwrap()),
        "verifying_share_bincode_hex": hex::encode(bincode::serialize(key_package.verifying_share()).unwrap()),
    });
    Ok(response.to_string())
}

#[wasm_bindgen]
pub fn sign_part1_commit(key_package_hex: &str) -> Result<String, JsError> {
    let key_package_with_metadata: KeyPackageWithMetadata = bincode::deserialize(&hex::decode(key_package_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
    let key_package = key_package_with_metadata.key_package;
    let (nonces, commitments) = frost::round1::commit(key_package.signing_share(), &mut OsRng);

    let response = serde_json::json!({
        "nonces_hex": hex::encode(bincode::serialize(&nonces).unwrap()),
        "commitments_hex": hex::encode(bincode::serialize(&commitments).unwrap()),
    });
    Ok(response.to_string())
}

#[wasm_bindgen]
pub fn sign_part2_sign(key_package_hex: &str, nonces_hex: &str, signing_package_hex: &str) -> Result<String, JsError> {
    let key_package_with_metadata: KeyPackageWithMetadata = bincode::deserialize(&hex::decode(key_package_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
    let key_package = key_package_with_metadata.key_package;
    let nonces: frost::round1::SigningNonces = bincode::deserialize(&hex::decode(nonces_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;
    let signing_package: frost::SigningPackage = bincode::deserialize(&hex::decode(signing_package_hex).map_err(|e| JsError::new(&e.to_string()))?).map_err(|e| JsError::new(&e.to_string()))?;

    let signature_share = frost::round2::sign(&signing_package, &nonces, &key_package).map_err(|e| JsError::new(&e.to_string()))?;

    Ok(hex::encode(bincode::serialize(&signature_share).unwrap()))
}

// ====================================================================
// region: Share Encryption/Decryption
// ====================================================================

#[wasm_bindgen]
pub fn encrypt_share(aes_key_hex: &str, share_plaintext_hex: &str) -> Result<String, JsError> {
    let key_bytes = hex::decode(aes_key_hex).map_err(|e| JsError::new(&format!("Invalid AES key hex: {}", e)))?;
    let plaintext = hex::decode(share_plaintext_hex).map_err(|e| JsError::new(&format!("Invalid plaintext hex: {}", e)))?;

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| JsError::new(&format!("Failed to create cipher: {}", e)))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_slice()).map_err(|e| JsError::new(&format!("Encryption failed: {}", e)))?;

    let encrypted_share = EncryptedShare {
        ciphertext_hex: hex::encode(ciphertext),
        nonce_hex: hex::encode(nonce),
    };

    serde_json::to_string(&encrypted_share).map_err(|e| JsError::new(&format!("Failed to serialize encrypted share: {}", e)))
}

#[wasm_bindgen]
pub fn decrypt_share(aes_key_hex: &str, encrypted_share_json: &str) -> Result<String, JsError> {
    let key_bytes = hex::decode(aes_key_hex).map_err(|e| JsError::new(&format!("Invalid AES key hex: {}", e)))?;
    let encrypted_share: EncryptedShare = serde_json::from_str(encrypted_share_json).map_err(|e| JsError::new(&format!("Failed to parse encrypted share JSON: {}", e)))?;

    let ciphertext = hex::decode(encrypted_share.ciphertext_hex).map_err(|e| JsError::new(&format!("Invalid ciphertext hex: {}", e)))?;
    let nonce_bytes = hex::decode(encrypted_share.nonce_hex).map_err(|e| JsError::new(&format!("Invalid nonce hex: {}", e)))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes).map_err(|e| JsError::new(&format!("Failed to create cipher: {}", e)))?;
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|e| JsError::new(&format!("Decryption failed: {}", e)))?;

    Ok(hex::encode(plaintext))
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
