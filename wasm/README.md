# Tokamak-FROST WASM Module

This directory contains the core cryptographic library for the Tokamak-FROST client, compiled to WebAssembly (WASM). It exposes a suite of functions to JavaScript, enabling web applications to perform complex cryptographic operations for Distributed Key Generation (DKG) and interactive threshold signing using the FROST protocol.

The library handles both ECDSA (secp256k1) and EdDSA (EdwardsOnBls12381) key management, message signing, ECIES encryption/decryption, and the multi-round protocols required for FROST.

## How to Build

The WASM module is built using `wasm-pack`.

### Prerequisites

- **Rust:** Ensure you have a recent version of Rust installed.
- **`wasm-pack`:** Install it if you haven't already:
  ```sh
  cargo install wasm-pack
  ```

### Build Command

To compile the Rust code into a WASM module suitable for web environments, run the following command from this directory (`/wasm`):

```sh
wasm-pack build --target web
```

This command compiles the `lib.rs` file and its dependencies, generating the final WASM module and the corresponding JavaScript bindings in the `pkg/` directory. The output is optimized for use in web browsers and can be imported directly into JavaScript or TypeScript projects.

### Testing

To run the included tests in a headless browser environment, use:

```sh
wasm-pack test --firefox --headless -- -- --nocapture
```

## `lib.rs` API Reference

This section details the functions exposed by the WASM module. All functions are accessible from JavaScript after the module is imported.

---

### Initialization

#### `init_panic_hook()`
Sets up a panic hook to forward Rust panics to the browser's developer console. This should be called once when the application starts.

- **Inputs:** None
- **Output:** `void`

---

### Hashing & Conversion Utilities

#### `keccak256(message: string)`
Computes the Keccak-256 hash of a given string message.

- **Inputs:**
  - `message`: `string` - The input message to hash.
- **Output:** `string` - The 32-byte hash, returned as a hex-encoded string.

#### `to_compressed_point(uncompressed_point_hex: string)`
Converts an uncompressed secp256k1 public key point to its compressed form.

- **Inputs:**
  - `uncompressed_point_hex`: `string` - The uncompressed public key, hex-encoded.
- **Output:** `string` - A JSON string containing the `point` in compressed hex format.

---

### Key Generation & Signing Utilities

#### `generate_ecdsa_keypair()`
Generates a new random secp256k1 (ECDSA) key pair.

- **Inputs:** None
- **Output:** `string` - A JSON string containing:
  - `private_key_hex`: The 32-byte private key, hex-encoded.
  - `public_key_hex`: The 33-byte compressed public key, hex-encoded.

#### `generate_eddsa_keypair()`
Generates a new random EdwardsOnBls12381 (EdDSA) key pair.

- **Inputs:** None
- **Output:** `string` - A JSON string containing:
  - `private_key_hex`: The 32-byte private key, hex-encoded.
  - `public_key_hex`: The 32-byte compressed public key, hex-encoded.

#### `derive_keys_from_signature(signature_hex: string, key_type: string)`
Deterministically derives a key pair (ECDSA or EdDSA) and a symmetric AES key from a given signature.

- **Inputs:**
  - `signature_hex`: `string` - An ECDSA signature, hex-encoded.
  - `key_type`: `string` - The desired key type. Use `"edwards_on_bls12381"` for EdDSA or any other string for the default (ECDSA).
- **Output:** `string` - A JSON string containing the derived `private_key_hex`, `public_key_hex`, and `aes_key_hex`.

#### `sign_challenge(private_key_hex: string, challenge: string)`
Signs a server-provided UUID challenge for authentication. **Note:** This is a legacy function that defaults to `sign_challenge_ecdsa`.

- **Inputs:**
  - `private_key_hex`: `string` - The user's private key.
  - `challenge`: `string` - The UUID string received from the server.
- **Output:** `string` - The DER-encoded ECDSA signature, returned as a hex string.

#### `sign_challenge_ecdsa(private_key_hex: string, challenge: string)`
Signs a UUID challenge using ECDSA. The function hashes the UUID bytes with Keccak-256 and signs the digest.

- **Inputs:**
  - `private_key_hex`: `string` - The user's secp256k1 private key.
  - `challenge`: `string` - The UUID string.
- **Output:** `string` - The DER-encoded ECDSA signature, hex-encoded.

#### `sign_challenge_eddsa(private_key_hex: string, challenge: string)`
Signs a UUID challenge using EdDSA. The function hashes the UUID bytes with Keccak-256 and signs the digest.

- **Inputs:**
  - `private_key_hex`: `string` - The user's EdwardsOnBls12381 private key.
  - `challenge`: `string` - The UUID string.
- **Output:** `string` - The compressed EdDSA signature, hex-encoded.

#### `sign_message(private_key_hex: string, message_hex: string)`
Signs an arbitrary message hash. **Note:** This is a legacy function that defaults to `sign_message_ecdsa`.

- **Inputs:**
  - `private_key_hex`: `string` - The user's private key.
  - `message_hex`: `string` - The message to sign, hex-encoded.
- **Output:** `string` - The DER-encoded ECDSA signature, returned as a hex string.

#### `sign_message_ecdsa(private_key_hex: string, message_hex: string)`
Signs a message using ECDSA. The function hashes the message bytes with Keccak-256 and signs the digest.

- **Inputs:**
  - `private_key_hex`: `string` - The user's secp256k1 private key.
  - `message_hex`: `string` - The message to sign, hex-encoded.
- **Output:** `string` - The DER-encoded ECDSA signature, hex-encoded.

#### `sign_message_eddsa(private_key_hex: string, message_hex: string)`
Signs a message using EdDSA. The function hashes the message bytes with Keccak-256 and signs the digest.

- **Inputs:**
  - `private_key_hex`: `string` - The user's EdwardsOnBls12381 private key.
  - `message_hex`: `string` - The message to sign, hex-encoded.
- **Output:** `string` - The compressed EdDSA signature, hex-encoded.

#### `get_identifier_hex(id: number)`
Converts a numeric user ID into a FROST identifier.

- **Inputs:**
  - `id`: `number` (u16) - The user's session-local ID.
- **Output:** `string` - The hex-encoded FROST identifier.

---

### Auth Payload Construction

These functions construct the exact byte payloads that need to be signed to authenticate messages sent to the `fserver`.

#### `get_auth_payload_round1(session_id: string, id_hex: string, pkg_hex: string)`
- **Output:** `string` - The hex-encoded payload for a DKG Round 1 submission.

#### `get_auth_payload_round2(session_id: string, from_id_hex: string, to_id_hex: string, eph_pub_hex: string, nonce_hex: string, ct_hex: string)`
- **Output:** `string` - The hex-encoded payload for a DKG Round 2 submission.

#### `get_auth_payload_finalize(session_id: string, id_hex: string, group_vk_hex: string)`
- **Output:** `string` - The hex-encoded payload for a DKG Finalize submission.

#### `get_auth_payload_sign_r1(session_id: string, group_id: string, id_hex: string, commits_hex: string)`
- **Output:** `string` - The hex-encoded payload for a Signing Round 1 submission.

#### `get_auth_payload_sign_r2(session_id: string, group_id: string, id_hex: string, sigshare_hex: string, msg32_hex: string)`
- **Output:** `string` - The hex-encoded payload for a Signing Round 2 submission.

---

### DKG Round Logic

#### `dkg_part1(identifier_hex: string, max_signers: number, min_signers: number)`
Performs the first step of the FROST DKG, generating secret commitments and a public package.

- **Inputs:**
  - `identifier_hex`: `string` - The participant's FROST identifier.
  - `max_signers`: `number` (u16) - The total number of participants.
  - `min_signers`: `number` (u16) - The threshold required for signing.
- **Output:** `string` - A JSON string containing:
  - `secret_package_hex`: The secret data to be used in the next round.
  - `public_package_hex`: The public data to be broadcast to other participants.

#### `dkg_part2(secret_package_hex: string, round1_packages_hex: JsValue)`
Performs the second DKG step, generating encrypted shares for other participants.

- **Inputs:**
  - `secret_package_hex`: `string` - The secret package from `dkg_part1`.
  - `round1_packages_hex`: `JsValue` - A `Map<string, string>` of `identifier_hex` to `public_package_hex` from all participants.
- **Output:** `string` - A JSON string containing:
  - `secret_package_hex`: The secret data for the final round.
  - `outgoing_packages`: A `Map<string, string>` of recipient `identifier_hex` to their encrypted Round 2 package.

#### `dkg_part3(secret_package_hex: string, round1_packages_hex: JsValue, round2_packages_hex: JsValue, group_id: string, roster_js: JsValue, key_type: string)`
Performs the final DKG step, processing shares to compute the participant's long-lived secret key share and the group's public key.

- **Inputs:**
  - `secret_package_hex`: `string` - The secret package from `dkg_part2`.
  - `round1_packages_hex`: `JsValue` - All Round 1 public packages.
  - `round2_packages_hex`: `JsValue` - The participant's received Round 2 packages.
  - `group_id`: `string` - A unique identifier for the key group.
  - `roster_js`: `JsValue` - A `Map<number, string>` of `uid` to `public_key_hex`.
  - `key_type`: `string` - The key type of the roster, e.g., `"ecdsa"` or `"eddsa"`.
- **Output:** `string` - A JSON string containing:
  - `key_package_hex`: The final, persistent key package containing the user's secret share and metadata.
  - `group_public_key_hex`: The group's aggregated public key.

---

### Interactive Signing Logic

#### `get_key_package_metadata(key_package_hex: string)`
Extracts and returns metadata from a key package created during DKG.

- **Inputs:**
  - `key_package_hex`: `string` - The key package from `dkg_part3`.
- **Output:** `string` - A JSON string containing `group_id`, `threshold`, `roster`, `roster_key_type`, and `group_public_key`.

#### `get_signing_prerequisites(key_package_hex: string)`
Extracts the necessary identifiers from a key package required to join a signing session.

- **Inputs:**
  - `key_package_hex`: `string` - The key package.
- **Output:** `string` - A JSON string containing:
  - `signer_id_bincode_hex`: The user's FROST identifier, bincode- and hex-encoded.
  - `verifying_share_bincode_hex`: The user's public verifying share, bincode- and hex-encoded.

#### `sign_part1_commit(key_package_hex: string)`
Performs the first step of a FROST signing ceremony, generating nonces and commitments.

- **Inputs:**
  - `key_package_hex`: `string` - The user's key package.
- **Output:** `string` - A JSON string containing:
  - `nonces_hex`: The secret nonces to be used in the final step.
  - `commitments_hex`: The public commitments to be broadcast to other participants.

#### `sign_part2_sign(key_package_hex: string, nonces_hex: string, signing_package_hex: string)`
Performs the second and final step of signing, generating a signature share.

- **Inputs:**
  - `key_package_hex`: `string` - The user's key package.
  - `nonces_hex`: `string` - The secret nonces from `sign_part1_commit`.
  - `signing_package_hex`: `string` - The signing package received from the server, which includes the message and all participants' commitments.
- **Output:** `string` - The user's hex-encoded signature share.

---

### Share Encryption/Decryption

#### `encrypt_share(aes_key_hex: string, share_plaintext_hex: string)`
Encrypts a secret share using a symmetric AES-256-GCM key.

- **Inputs:**
  - `aes_key_hex`: `string` - The 32-byte AES key, hex-encoded.
  - `share_plaintext_hex`: `string` - The secret share data to encrypt, hex-encoded.
- **Output:** `string` - A JSON string containing the `ciphertext_hex` and `nonce_hex`.

#### `decrypt_share(aes_key_hex: string, encrypted_share_json: string)`
Decrypts a secret share using a symmetric AES-256-GCM key.

- **Inputs:**
  - `aes_key_hex`: `string` - The 32-byte AES key, hex-encoded.
  - `encrypted_share_json`: `string` - A JSON string containing `ciphertext_hex` and `nonce_hex`.
- **Output:** `string` - The decrypted plaintext share, hex-encoded.

---

### ECIES Encryption

#### `ecies_encrypt(recipient_pubkey_hex: string, plaintext_hex: string)`
Encrypts a plaintext using ECIES. **Note:** This is a legacy function that defaults to `ecies_encrypt_ecdsa`.

- **Inputs:**
  - `recipient_pubkey_hex`: `string` - The recipient's public key.
  - `plaintext_hex`: `string` - The data to encrypt, hex-encoded.
- **Output:** `string` - A JSON string containing the encrypted payload.

#### `ecies_encrypt_ecdsa(recipient_pubkey_hex: string, plaintext_hex: string)`
Encrypts a plaintext for a secp256k1 recipient using ECIES with AES-256-GCM.

- **Inputs:**
  - `recipient_pubkey_hex`: `string` - The recipient's 33-byte compressed secp256k1 public key.
  - `plaintext_hex`: `string` - The data to encrypt, hex-encoded.
- **Output:** `string` - A JSON string containing `ephemeral_public_key_hex`, `nonce_hex`, and `ciphertext_hex`.

#### `ecies_encrypt_eddsa(recipient_pubkey_hex: string, plaintext_hex: string)`
Encrypts a plaintext for an EdwardsOnBls12381 recipient using an ECIES-like scheme with AES-256-GCM.

- **Inputs:**
  - `recipient_pubkey_hex`: `string` - The recipient's 32-byte compressed EdwardsOnBls12381 public key.
  - `plaintext_hex`: `string` - The data to encrypt, hex-encoded.
- **Output:** `string` - A JSON string containing `ephemeral_public_key_hex`, `nonce_hex`, and `ciphertext_hex`.

#### `ecies_decrypt(recipient_private_key_hex: string, ...)`
Decrypts a ciphertext using ECIES. **Note:** This is a legacy function that defaults to `ecies_decrypt_ecdsa`.

- **Inputs:**
  - `recipient_private_key_hex`: `string` - The recipient's private key.
  - `ephemeral_public_key_hex`: `string` - The ephemeral public key from the payload.
  - `nonce_hex`: `string` - The nonce from the payload.
  - `ciphertext_hex`: `string` - The ciphertext from the payload.
- **Output:** `string` - The decrypted plaintext, hex-encoded.

#### `ecies_decrypt_ecdsa(recipient_private_key_hex: string, ...)`
Decrypts a ciphertext encrypted for a secp256k1 key.

- **Inputs:** (Same as `ecies_decrypt`)
- **Output:** `string` - The decrypted plaintext, hex-encoded.

#### `ecies_decrypt_eddsa(recipient_private_key_hex: string, ...)`
Decrypts a ciphertext encrypted for an EdwardsOnBls12381 key.

- **Inputs:** (Same as `ecies_decrypt`)
- **Output:** `string` - The decrypted plaintext, hex-encoded.
