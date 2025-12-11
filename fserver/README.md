# F-Server (FROST Coordinator)

`fserver` is a high-performance WebSocket coordinator written in Rust. It manages the communication rounds for Distributed Key Generation (DKG) and Threshold Signing ceremonies without ever having access to the secret keys.

## Running the Server

```bash
# Run on default port 9000
./fserver server

# Run on specific address
./fserver server --bind 127.0.0.1:9034
```

## WebSocket API Reference

The server communicates via JSON messages over WebSocket.
**Endpoint**: `ws://<host>:<port>/ws` (e.g., `ws://127.0.0.1:9034/ws`)

### Data Types

-   **`hex`**: Hexadecimal string representation of binary data (e.g., `"a1b2..."`).
-   **`bincode_hex`**: Binary data serialized with `bincode` (Rust) and then hex-encoded.
-   **`RosterPublicKey`**: JSON object `{ "type": "Secp256k1" | "EdwardsOnBls12381", "key": "HEX_STRING" }`.

---

### 1. Authentication

All protocol actions require a signed login.

#### A. Request Challenge
**Client** sends:
```json
{ "type": "RequestChallenge" }
```

**Server** responds:
```json
{
  "type": "Challenge",
  "payload": { "challenge": "UUID_STRING" }
}
```

#### B. Login
User signs the challenge UUID (bytes) with their Roster Key.

**Client** sends:
```json
{
  "type": "Login",
  "payload": {
    "challenge": "UUID_STRING",
    "public_key": { "type": "...", "key": "..." }, // RosterPublicKey
    "signature_hex": "HEX_STRING"
  }
}
```

**Server** responds (Success):
```json
{
  "type": "LoginOk",
  "payload": {
    "principal": "CANONICAL_JSON_STRING",
    "suid": 1, // Session-Unique ID for this connection
    "access_token": "UUID_STRING"
  }
}
```

---

### 2. Distributed Key Generation (DKG)

#### A. Announce Session (Round 0)
**Client** (Creator) sends:
```json
{
  "type": "AnnounceDKGSession",
  "payload": {
    "min_signers": 2,
    "max_signers": 3,
    "group_id": "optional_string",
    "participants": [1, 2, 3], // List of SUIDs
    "participants_pubs": [[1, { "type": "...", "key": "..." }], ...]
  }
}
```

**Server** broadcasts to participants:
```json
{
  "type": "ReadyRound1",
  "payload": {
    "session": "UUID",
    "id_hex": "HEX", // Your FROST Identifier
    "roster": [[1, "ID_HEX", { "type": "...", "key": "..." }], ...]
  }
}
```

#### B. Round 1 (Commitments)
**Client** sends:
```json
{
  "type": "Round1Submit",
  "payload": {
    "session": "UUID",
    "id_hex": "HEX",
    "pkg_bincode_hex": "HEX", // Round 1 Package
    "signature_hex": "HEX"    // Auth signature
  }
}
```

**Server** broadcasts (after all submitted):
```json
{
  "type": "Round1All",
  "payload": {
    "session": "UUID",
    "packages": [["ID_HEX", "PKG_BINCODE_HEX", "SIG_HEX"], ...]
  }
}
```

#### C. Round 2 (Secret Shares)
**Client** sends:
```json
{
  "type": "Round2Submit",
  "payload": {
    "session": "UUID",
    "pkgs_cipher": [["RECIPIENT_ID_HEX", { "ciphertext_hex": "...", "nonce_hex": "..." }, "SIG_HEX"], ...]
  }
}
```

**Server** sends personal inbox to each participant (after all submitted):
```json
{
  "type": "Round2All",
  "payload": {
    "session": "UUID",
    // Packages encrypted FOR YOU
    "packages": [["SENDER_ID_HEX", { "ciphertext_hex": "...", "nonce_hex": "..." }, "SIG_HEX"], ...]
  }
}
```

#### D. Finalize
**Client** sends:
```json
{
  "type": "FinalizeSubmit",
  "payload": {
    "session": "UUID",
    "group_vk_sec1_hex": "HEX", // Calculated Group Public Key
    "signature_hex": "HEX"
  }
}
```

---

### 3. Signing Ceremony

#### A. Announce Signing
**Client** sends:
```json
{
  "type": "AnnounceSignSession",
  "payload": {
    "group_id": "...",
    "threshold": 2,
    "participants": [1, 2, 3],
    "message_hex": "HEX" // The hash to sign
  }
}
```

**Server** broadcasts:
```json
{
  "type": "SignReadyRound1",
  "payload": {
    "session": "UUID",
    "msg_keccak32_hex": "HEX"
    // ... roster details
  }
}
```

#### B. Join & Round 1
Participants upload their key share to calculate coefficients.
**Client** sends `JoinSignSession`, then `SignRound1Submit`.

**Server** broadcasts `SignSigningPackage`.

#### C. Round 2 (Signature Shares)
**Client** sends:
```json
{
  "type": "SignRound2Submit",
  "payload": { "signature_share_bincode_hex": "..." }
}
```

**Server** aggregates and broadcasts final result:
```json
{
  "type": "SignatureReady",
  "payload": {
    "signature_bincode_hex": "HEX", // The final aggregated signature
    // ... r and s values
  }
}
---

### 4. Signature Payload Details

For every API call requiring `signature_hex`, the client signs a specific payload constructed as follows.

**A. Authentication (Login)**
-   **Payload**: The UTF-8 bytes of the challenge UUID string.
-   `uuid_bytes`

**B. DKG Round 1**
-   **Payload**: `b"TOKAMAK_FROST_DKG_R1|" + session_bytes + b"|" + bincode(id) + bincode(pkg)`
-   Where `pkg` is the `frost::keys::dkg::round1::Package` struct.

**C. DKG Round 2**
-   **Payload**: `b"TOKAMAK_FROST_DKG_R2|" + session_bytes + b"|" + bincode(from_id) + bincode(to_id) + eph_pub_bytes + nonce + ciphertext`

**D. DKG Finalize**
-   **Payload**: `b"TOKAMAK_FROST_DKG_FIN|" + session_bytes + b"|" + bincode(id) + group_vk_sec1_bytes`

**E. Signing Round 1**
-   **Payload**: `format!("SIGN_WS_R1|{}|{}|{}|{}", session, group_id, id_hex, commits_hex).into_bytes()`

**F. Signing Round 2**
-   **Payload**: `format!("SIGN_WS_R2|{}|{}|{}|{}|{}", session, group_id, id_hex, sigshare_hex, msg32_hex).into_bytes()`
