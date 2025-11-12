#![cfg(test)]
use super::*;
use wasm_bindgen_test::*;
use k256::ecdsa::VerifyingKey;
use signature::Verifier;

wasm_bindgen_test_configure!(run_in_browser);

// Helper to create a dummy JsValue BTreeMap<String, String>
fn create_js_map(entries: Vec<(&str, &str)>) -> JsValue {
    let map: BTreeMap<String, String> = entries
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    serde_wasm_bindgen::to_value(&map).expect("Failed to create JsValue map")
}

#[wasm_bindgen_test]
fn test_generate_and_derive_keys() {
    // Test random key generation
    let keypair_json = generate_ecdsa_keypair();
    let keypair: serde_json::Value = serde_json::from_str(&keypair_json).expect("Failed to parse keypair JSON");
    let priv_key_hex = keypair["private_key_hex"].as_str().expect("Missing private_key_hex");
    let pub_key_hex = keypair["public_key_hex"].as_str().expect("Missing public_key_hex");

    let sk_bytes = hex::decode(priv_key_hex).expect("Failed to decode private key hex");
    let sk = K256SecretKey::from_slice(&sk_bytes).expect("Failed to create SecretKey from slice");
    let pk = VerifyingKey::from_sec1_bytes(&hex::decode(pub_key_hex).expect("Failed to decode public key hex")).expect("Failed to create VerifyingKey from SEC1 bytes");
    assert_eq!(&VerifyingKey::from(&sk.public_key()), &pk, "Public key does not match private key");

    // Test deterministic key derivation
    let dummy_signature = hex::encode([1; 64]);
    let derived_json = derive_key_from_signature(&dummy_signature).expect("derive_key_from_signature failed");
    let derived_keypair: serde_json::Value = serde_json::from_str(&derived_json).expect("Failed to parse derived keypair JSON");
    let derived_priv_hex = derived_keypair["private_key_hex"].as_str().expect("Missing derived private_key_hex");
    let derived_pub_hex = derived_keypair["public_key_hex"].as_str().expect("Missing derived public_key_hex");

    let derived_sk_bytes = hex::decode(derived_priv_hex).expect("Failed to decode derived private key hex");
    let derived_sk = K256SecretKey::from_slice(&derived_sk_bytes).expect("Failed to create SecretKey from derived slice");
    let derived_pk = VerifyingKey::from_sec1_bytes(&hex::decode(derived_pub_hex).expect("Failed to decode derived public key hex")).expect("Failed to create VerifyingKey from derived SEC1 bytes");
    assert_eq!(&VerifyingKey::from(&derived_sk.public_key()), &derived_pk, "Derived public key does not match derived private key");

    // Ensure it's deterministic
    let derived_json_2 = derive_key_from_signature(&dummy_signature).expect("Second derive_key_from_signature failed");
    assert_eq!(derived_json, derived_json_2, "Key derivation is not deterministic");
}

#[wasm_bindgen_test]
fn test_sign_and_verify() {
    let keypair_json = generate_ecdsa_keypair();
    let keypair: serde_json::Value = serde_json::from_str(&keypair_json).unwrap();
    let priv_key_hex = keypair["private_key_hex"].as_str().unwrap();
    let pub_key_hex = keypair["public_key_hex"].as_str().unwrap();
    let pk = VerifyingKey::from_sec1_bytes(&hex::decode(pub_key_hex).unwrap()).unwrap();

    // Test sign_challenge
    let challenge = uuid::Uuid::new_v4().to_string();
    let signature_hex = sign_challenge(priv_key_hex, &challenge).unwrap();
    let sig_bytes = hex::decode(signature_hex).unwrap();
    let signature = EcdsaSignature::from_der(&sig_bytes).unwrap();
    let challenge_bytes = uuid::Uuid::parse_str(&challenge).unwrap().as_bytes().to_vec();
    let mut hasher = Keccak256::new();
    hasher.update(&challenge_bytes);
    assert!(pk.verify_digest(hasher, &signature).is_ok(), "Challenge signature verification failed");

    // Test sign_message
    let message = "hello world";
    let message_hex = hex::encode(message);
    let signature_hex_2 = sign_message(priv_key_hex, &message_hex).unwrap();
    let sig_bytes_2 = hex::decode(signature_hex_2).unwrap();
    let signature_2 = EcdsaSignature::from_der(&sig_bytes_2).unwrap();
    let mut hasher_2 = Keccak256::new();
    hasher_2.update(message.as_bytes());
    assert!(pk.verify_digest(hasher_2, &signature_2).is_ok(), "Message signature verification failed");
}

#[wasm_bindgen_test]
fn test_auth_payloads() {
    let session_id = "test-session";
    let id_hex = get_identifier_hex(1).unwrap();
    let part1_json = dkg_part1(&id_hex, 2, 2).unwrap();
    let part1: serde_json::Value = serde_json::from_str(&part1_json).unwrap();
    let pkg_hex = part1["public_package_hex"].as_str().unwrap();

    assert!(get_auth_payload_round1(session_id, &id_hex, pkg_hex).is_ok());
    assert!(get_auth_payload_round2(session_id, &id_hex, &id_hex, "0303", "0404", "0505").is_ok());
    assert!(get_auth_payload_finalize(session_id, &id_hex, "0606").is_ok());
    assert!(get_auth_payload_sign_r1(session_id, "group1", &id_hex, "0707").is_ok());
    assert!(get_auth_payload_sign_r2(session_id, "group1", &id_hex, "0808", "0909").is_ok());
}

#[wasm_bindgen_test]
fn test_ecies_round_trip() {
    let keypair_json = generate_ecdsa_keypair();
    let keypair: serde_json::Value = serde_json::from_str(&keypair_json).unwrap();
    let priv_key_hex = keypair["private_key_hex"].as_str().unwrap();
    let pub_key_hex = keypair["public_key_hex"].as_str().unwrap();
    let plaintext = "this is a secret message";
    let plaintext_hex = hex::encode(plaintext);

    let encrypted_json = ecies_encrypt(pub_key_hex, &plaintext_hex).unwrap();
    let encrypted: serde_json::Value = serde_json::from_str(&encrypted_json).unwrap();
    let eph_pub_hex = encrypted["ephemeral_public_key_hex"].as_str().unwrap();
    let nonce_hex = encrypted["nonce_hex"].as_str().unwrap();
    let ct_hex = encrypted["ciphertext_hex"].as_str().unwrap();

    let decrypted_hex = ecies_decrypt(priv_key_hex, eph_pub_hex, nonce_hex, ct_hex).unwrap();
    let decrypted_plaintext = String::from_utf8(hex::decode(decrypted_hex).unwrap()).unwrap();

    assert_eq!(plaintext, decrypted_plaintext, "ECIES decrypted text does not match original plaintext");
}

#[wasm_bindgen_test]
fn test_dkg_and_signing_round_trip() {
    // ==================================
    // DKG Ceremony Simulation (2-of-2)
    // ==================================
    let max_signers = 2;
    let min_signers = 2;

    // --- Participant 1 Setup ---
    let p1_id_hex = get_identifier_hex(1).unwrap();
    let p1_part1_json = dkg_part1(&p1_id_hex, max_signers, min_signers).unwrap();
    let p1_part1: serde_json::Value = serde_json::from_str(&p1_part1_json).unwrap();
    let p1_secret1_hex = p1_part1["secret_package_hex"].as_str().unwrap();
    let p1_public1_hex = p1_part1["public_package_hex"].as_str().unwrap();

    // --- Participant 2 Setup ---
    let p2_id_hex = get_identifier_hex(2).unwrap();
    let p2_part1_json = dkg_part1(&p2_id_hex, max_signers, min_signers).unwrap();
    let p2_part1: serde_json::Value = serde_json::from_str(&p2_part1_json).unwrap();
    let p2_secret1_hex = p2_part1["secret_package_hex"].as_str().unwrap();
    let p2_public1_hex = p2_part1["public_package_hex"].as_str().unwrap();

    // --- Round 2 ---
    // P1 creates packages for P2
    let p1_r1_map = create_js_map(vec![(&p2_id_hex, p2_public1_hex)]);
    let p1_part2_json = dkg_part2(p1_secret1_hex, p1_r1_map).unwrap();
    let p1_part2: serde_json::Value = serde_json::from_str(&p1_part2_json).unwrap();
    let p1_secret2_hex = p1_part2["secret_package_hex"].as_str().unwrap();
    let p1_outgoing: BTreeMap<String, String> = serde_json::from_value(p1_part2["outgoing_packages"].clone()).unwrap();
    let p1_to_p2_pkg_hex = p1_outgoing.get(&p2_id_hex).expect("P1 should have a package for P2");

    // P2 creates packages for P1
    let p2_r1_map = create_js_map(vec![(&p1_id_hex, p1_public1_hex)]);
    let p2_part2_json = dkg_part2(p2_secret1_hex, p2_r1_map).unwrap();
    let p2_part2: serde_json::Value = serde_json::from_str(&p2_part2_json).unwrap();
    let p2_secret2_hex = p2_part2["secret_package_hex"].as_str().unwrap();
    let p2_outgoing: BTreeMap<String, String> = serde_json::from_value(p2_part2["outgoing_packages"].clone()).unwrap();
    let p2_to_p1_pkg_hex = p2_outgoing.get(&p1_id_hex).expect("P2 should have a package for P1");

    // --- Round 3 (Finalize for P1) ---
    let p1_r1_map_part3 = create_js_map(vec![(&p2_id_hex, p2_public1_hex)]);
    let p1_r2_map_part3 = create_js_map(vec![(&p2_id_hex, p2_to_p1_pkg_hex)]);
    let p1_part3_json = dkg_part3(p1_secret2_hex, p1_r1_map_part3, p1_r2_map_part3).unwrap();
    let p1_part3: serde_json::Value = serde_json::from_str(&p1_part3_json).unwrap();
    let p1_key_package_hex = p1_part3["key_package_hex"].as_str().unwrap();
    let group_public_key_hex = p1_part3["group_public_key_hex"].as_str().unwrap();

    // --- Round 3 (Finalize for P2) ---
    let p2_r1_map_part3 = create_js_map(vec![(&p1_id_hex, p1_public1_hex)]);
    let p2_r2_map_part3 = create_js_map(vec![(&p1_id_hex, p1_to_p2_pkg_hex)]);
    let p2_part3_json = dkg_part3(p2_secret2_hex, p2_r1_map_part3, p2_r2_map_part3).unwrap();
    let p2_part3: serde_json::Value = serde_json::from_str(&p2_part3_json).unwrap();
    let p2_key_package_hex = p2_part3["key_package_hex"].as_str().unwrap();

    assert!(!p1_key_package_hex.is_empty(), "P1 key package should not be empty");
    assert!(!p2_key_package_hex.is_empty(), "P2 key package should not be empty");
    assert!(!group_public_key_hex.is_empty(), "Group public key should not be empty");

    // ==================================
    // Signing Ceremony Simulation
    // ==================================

    // --- Round 1: Commit ---
    let p1_sign_part1_json = sign_part1_commit(p1_key_package_hex).unwrap();
    let p1_sign_part1: serde_json::Value = serde_json::from_str(&p1_sign_part1_json).unwrap();
    let p1_nonces_hex = p1_sign_part1["nonces_hex"].as_str().unwrap();
    let p1_commitments_hex = p1_sign_part1["commitments_hex"].as_str().unwrap();

    let p2_sign_part1_json = sign_part1_commit(p2_key_package_hex).unwrap();
    let p2_sign_part1: serde_json::Value = serde_json::from_str(&p2_sign_part1_json).unwrap();
    let p2_commitments_hex = p2_sign_part1["commitments_hex"].as_str().unwrap();

    // --- Round 2: Sign ---
    let message = "message to be signed";
    let msg_hash = Keccak256::digest(message.as_bytes());
    let mut msg_hash_bytes = [0u8; 32];
    msg_hash_bytes.copy_from_slice(msg_hash.as_slice());

    let p1_commitments: frost::round1::SigningCommitments = bincode::deserialize(&hex::decode(p1_commitments_hex).unwrap()).unwrap();
    let p2_commitments: frost::round1::SigningCommitments = bincode::deserialize(&hex::decode(p2_commitments_hex).unwrap()).unwrap();

    let mut commitments_map = BTreeMap::new();
    let p1_id: frost::Identifier = bincode::deserialize(&hex::decode(p1_id_hex).unwrap()).unwrap();
    let p2_id: frost::Identifier = bincode::deserialize(&hex::decode(p2_id_hex).unwrap()).unwrap();
    commitments_map.insert(p1_id, p1_commitments);
    commitments_map.insert(p2_id, p2_commitments);

    let signing_package = frost::SigningPackage::new(commitments_map, &msg_hash_bytes);
    let signing_package_hex = hex::encode(bincode::serialize(&signing_package).unwrap());

    let p1_sig_share_hex = sign_part2_sign(p1_key_package_hex, p1_nonces_hex, &signing_package_hex).unwrap();
    assert!(!p1_sig_share_hex.is_empty(), "P1 Signature share should not be empty");
}
