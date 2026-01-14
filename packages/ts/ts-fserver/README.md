# ts-fserver

TypeScript implementation of the FROST WebSocket coordinator server.

## Project Structure

```
ts-fserver/
├── src/
│   ├── index.ts      # Server entry point
│   ├── server.ts     # WebSocket server logic & message handlers
│   └── types.ts      # TypeScript type definitions
├── test/
│   ├── signing_test.ts       # End-to-end signing flow tests
│   └── compatibility_test.ts # WASM compatibility tests
├── package.json
└── tsconfig.json
```

## Getting Started

This package depends on `tokamak-frost-wasm` from the `shared-wasm` workspace.

### From Project Root (Recommended)

```bash
# Build WASM to shared-wasm/pkg/
npm run build:wasm

# Install all workspace dependencies
npm install

# Start server (development with watch mode)
npm run dev:server

# Or start without watch
npm run start:server
```

### From ts-fserver Directory

```bash
# Start development server with watch mode
npm run dev

# Start server (production)
npm start

# Build TypeScript
npm run build
```

## Available Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Start server with ts-node and watch mode |
| `npm start` | Start server with ts-node |
| `npm run build` | Compile TypeScript to `dist/` |

### Root Workspace Commands

| Script | Description |
|--------|-------------|
| `npm run build:wasm` | Build WASM from `packages/rust/wasm` → `packages/ts/shared-wasm/pkg` |
| `npm run dev:server` | Start ts-fserver in development mode |
| `npm run start:server` | Start ts-fserver |

## Configuration

Server binds to `0.0.0.0:9034` by default (see `src/index.ts`).

---

## WebSocket API

Connect to `ws://host:port` (or specify `/ws` path based on your setup).

### Message Format

All messages are JSON with `{ type, payload }` structure.

---

## Client → Server Messages

### Authentication

#### `RequestChallenge`
Request a challenge for login.
```json
{ "type": "RequestChallenge", "payload": null }
```

#### `Login`
Authenticate with signed challenge.
```json
{
  "type": "Login",
  "payload": {
    "challenge": "<uuid>",
    "public_key": { "type": "Secp256k1", "key": "<hex>" },
    "signature_hex": "<signature>"
  }
}
```

#### `Logout`
```json
{ "type": "Logout", "payload": null }
```

---

### DKG Session

#### `AnnounceDKGSession`
Create a new DKG session (creator only).
```json
{
  "type": "AnnounceDKGSession",
  "payload": {
    "min_signers": 2,
    "max_signers": 3,
    "group_id": "my-group",
    "participants": [1, 2, 3],
    "participants_pubs": [
      [1, { "type": "Secp256k1", "key": "<pubkey1_hex>" }],
      [2, { "type": "Secp256k1", "key": "<pubkey2_hex>" }],
      [3, { "type": "Secp256k1", "key": "<pubkey3_hex>" }]
    ]
  }
}
```

#### `JoinDKGSession`
```json
{ "type": "JoinDKGSession", "payload": { "session": "<session_id>" } }
```

#### `ListPendingDKGSessions`
```json
{ "type": "ListPendingDKGSessions", "payload": null }
```

#### `ListCompletedDKGSessions`
```json
{ "type": "ListCompletedDKGSessions", "payload": null }
```

#### `Round1Submit`
Submit Round 1 DKG package.
```json
{
  "type": "Round1Submit",
  "payload": {
    "session": "<session_id>",
    "id_hex": "<participant_id_hex>",
    "pkg_bincode_hex": "<round1_package_hex>",
    "signature_hex": "<signature>"
  }
}
```

#### `Round2Submit`
Submit Round 2 encrypted packages.
```json
{
  "type": "Round2Submit",
  "payload": {
    "session": "<session_id>",
    "id_hex": "<participant_id_hex>",
    "pkgs_cipher": [
      ["<recipient_id>", {
        "ephemeral_public_key": { "type": "Secp256k1", "key": "<hex>" },
        "nonce": "<hex>",
        "ciphertext": "<hex>"
      }, "<signature>"]
    ]
  }
}
```

#### `FinalizeSubmit`
```json
{
  "type": "FinalizeSubmit",
  "payload": {
    "session": "<session_id>",
    "id_hex": "<participant_id_hex>",
    "group_vk_sec1_hex": "<group_verifying_key>",
    "signature_hex": "<signature>"
  }
}
```

---

### Signing Session

#### `AnnounceSignSession`
Create a new signing session.
```json
{
  "type": "AnnounceSignSession",
  "payload": {
    "group_id": "my-group",
    "threshold": 2,
    "participants": [1, 2],
    "participants_pubs": [[1, {...}], [2, {...}]],
    "group_vk_sec1_hex": "<group_key>",
    "message": "hello",
    "message_hex": "<keccak256_hash>"
  }
}
```

#### `JoinSignSession`
```json
{
  "type": "JoinSignSession",
  "payload": {
    "session": "<session_id>",
    "signer_id_bincode_hex": "<signer_id>",
    "verifying_share_bincode_hex": "<verifying_share>"
  }
}
```

#### `ListPendingSigningSessions`
```json
{ "type": "ListPendingSigningSessions", "payload": null }
```

#### `ListCompletedSigningSessions`
```json
{ "type": "ListCompletedSigningSessions", "payload": null }
```

#### `SignRound1Submit`
```json
{
  "type": "SignRound1Submit",
  "payload": {
    "session": "<session_id>",
    "id_hex": "<signer_id>",
    "commitments_bincode_hex": "<commitments>",
    "signature_hex": "<signature>"
  }
}
```

#### `SignRound2Submit`
```json
{
  "type": "SignRound2Submit",
  "payload": {
    "session": "<session_id>",
    "id_hex": "<signer_id>",
    "signature_share_bincode_hex": "<share>",
    "signature_hex": "<signature>"
  }
}
```

---

## Server → Client Messages

### Authentication
- `Challenge` - `{ challenge: "<uuid>" }`
- `LoginOk` - `{ principal, suid, access_token }`

### DKG Protocol
- `DKGSessionCreated` - `{ session: "<id>" }`
- `PendingDKGSessions` - `{ sessions: [...] }`
- `CompletedDKGSessions` - `{ sessions: [...] }`
- `ReadyRound1` - `{ session, group_id, min_signers, max_signers, roster, id_hex }`
- `Round1All` - `{ session, packages: [[id, pkg, sig], ...] }`
- `ReadyRound2` - `{ session, participants }`
- `Round2All` - `{ session, packages }`
- `Finalized` - `{ session, group_vk_sec1_hex }`

### Signing Protocol
- `SignSessionCreated` - `{ session: "<id>" }`
- `PendingSigningSessions` - `{ sessions: [...] }`
- `CompletedSigningSessions` - `{ sessions: [...] }`
- `SignReadyRound1` - `{ session, group_id, threshold, participants, roster, msg_keccak32_hex }`
- `SignSigningPackage` - `{ session, signing_package_bincode_hex }`
- `SignatureReady` - `{ session, signature_bincode_hex, message, rx, ry, s, px, py }`

### General
- `Error` - `{ message: "<error>" }`
- `Info` - `{ message: "<info>" }`
