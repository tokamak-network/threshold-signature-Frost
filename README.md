# Tokamak FROST (secp256k1) — DKG, Signing & Verification

> **Status:** Experimental / dev-only. Do **not** use in production.

This workspace demonstrates a complete FROST (secp256k1) flow:

1. **Interactive DKG** over WebSocket via a coordinator (`fserver`) and multiple clients (`dkg`).
2. **Interactive threshold signing** (2‑round) via the same coordinator (`fserver`) and clients (`signing`).
3. **Verification** off‑chain (Rust) and on‑chain (Solidity/Hardhat).

For a deeper architecture overview, see `docs/ARCHITECTURE.md`.

**Key properties**
- All DKG and signing packets are **authenticated** with ECDSA (secp256k1) using **Keccak‑256** digests.
- DKG **Round‑2** payloads are **per‑recipient encrypted** (ECIES: secp256k1 ECDH → AES‑256‑GCM).
- The coordinator exposes `/ws` for WebSocket and `/close` for graceful shutdown.

---

## Requirements

- Rust (stable) & Cargo
- Node.js ≥ 18 (for Hardhat scripts & helper tooling)
- A package manager (npm / pnpm / yarn)
- bash + curl

First time (for the on‑chain verifier):
```bash
cd onchain-verify
npm i
cd ..
```

---

## Repository layout

```
./
├─ fserver/               # DKG and Signing coordinator (server-only, WebSocket)
├─ keygen/
│  └─ dkg/                # DKG client (speaks to fserver)
├─ signing/               # Interactive signing client (speaks to fserver)
├─ offchain-verify/       # Verifies signature.json off‑chain
├─ onchain-verify/        # Hardhat project (ZecFrost.sol + scripts)
├─ scripts/
│  └─ make_users.js       # Generates users/user*.json (uids + ECDSA keys)
├─ users/                 # Auto‑generated users (created by scripts)
├─ Makefile               # End-to-end drivers
└─ README.md
```

---

## Quickstart (end‑to‑end, 2‑of‑3)

Runs the full demo (DKG, signing, verification, and server management):

```bash
make all out=run_dkg t=2 n=3 gid=mygroup topic=tok1 bind=127.0.0.1:9043 msg="frosty"
```

What happens:
1.  **DKG**: `fserver` starts, `dkg` clients run the distributed key generation, and artifacts (`group.json`, `share_*.json`) are saved to `run_dkg/`.
2.  **Signing**: `fserver` restarts, and `signing` clients perform a 2-round interactive signing ceremony for the given message. The final signature is saved to `run_dkg/signature.json`.
3.  **Verification**: Off‑chain and on‑chain verifiers confirm the signature is valid.
4.  **Shutdown**: The server is closed gracefully.

---

## How it works (high‑level)

### DKG Flow
1. **Coordinator** listens on `ws://<bind>/ws`.
2. **Authentication:** Clients authenticate with the server using a challenge-response mechanism with ECDSA signatures.
3. **Topic Creation (Creator):** One `dkg` client acts as the creator, announcing a new DKG topic with a list of participants and their public keys.
4. **Join:** Other `dkg` clients join the topic. Once all participants are present, the server signals the start of Round 1.
5. **Round 1 (Commitments):** Each client generates and submits its Round 1 package. The server broadcasts all packages to all participants.
6. **Round 2 (Secret Shares):** Each client generates encrypted, per-recipient secret shares and sends them to the server, which forwards them to the correct recipients.
7. **Finalize:** Each client computes its own secret key share and the group's public key, writing the results to `share_*.json` and `group.json`.

### Interactive Signing Flow
1. **Coordinator** listens on `ws://<bind>/ws`.
2. **Authentication:** `signing` clients authenticate just like `dkg` clients.
3. **Topic Creation (Creator):** One `signing` client announces a new signing topic, providing the message to be signed and the list of signing participants.
4. **Join:** Other `signing` clients join the topic. Once enough participants are present (matching the threshold `t`), the server signals the start of Round 1.
5. **Round 1 (Nonces):** Each client generates and submits nonces and commitments. The server broadcasts these to all participants.
6. **Round 2 (Signature Shares):** Each client uses the commitments from others to create and submit its partial signature share.
7. **Aggregation:** The server collects enough signature shares to meet the threshold, aggregates them into a final signature, and broadcasts the result to all participants.
8. **Artifact:** Each client writes the final `signature.json`.

---

## Manual run (advanced)

### 1) Start the coordinator
```bash
cargo run -p fserver -- server --bind 127.0.0.1:9043
```

### 2) Generate user keys
```bash
# This creates users/user1.json, user2.json, etc.
node scripts/make_users.js users 3
```

### 3) Run DKG
Run the creator and follower `dkg` clients as described in the `dkg` CLI help (`cargo run -p dkg -- --help`). Use the `Makefile` for the simplest experience.

### 4) Run Interactive Signing
After DKG is complete, you can perform a signing ceremony.

**Creator (announces the signing topic):**
```bash
# Set the creator's private key for auth
export DKG_ECDSA_PRIV_HEX=$(node -e 'console.log(JSON.parse(require("fs").readFileSync("users/user1.json")).ecdsa_priv_hex)')

# Run the signing creator client
cargo run -p signing -- \
  --url ws://127.0.0.1:9043/ws \
  --create \
  --topic "my-signing-topic" \
  --share run_dkg/share_ID_of_user1.json \
  --message "Hello, FROST!" \
  --participants "1,2" \
  --group-file run_dkg/group.json \
  --out-dir run_dkg
```

**Follower(s) (join the signing topic):**
```bash
# Set the follower's private key for auth
export DKG_ECDSA_PRIV_HEX=$(node -e 'console.log(JSON.parse(require("fs").readFileSync("users/user2.json")).ecdsa_priv_hex)')

# Run the signing follower client
cargo run -p signing -- \
  --url ws://127.0.0.1:9043/ws \
  --topic "my-signing-topic" \
  --share run_dkg/share_ID_of_user2.json \
  --message "Hello, FROST!" \
  --out-dir run_dkg
```

Upon success, all clients will write `run_dkg/signature.json`.

### 5) Verify the signature
```bash
# Verify off-chain
cargo run -p offchain-verify -- --signature run_dkg/signature.json

# Verify on-chain
cd onchain-verify
SIG=../run_dkg/signature.json npx hardhat run scripts/verify-signature.ts
```

---

## Makefile Targets

- `make all`: Runs the full `dkg` → `signing` → `offchain` → `onchain` flow.
- `make dkg`: Runs only the DKG ceremony to generate key shares.
- `make signing`: Runs only the interactive signing ceremony.
- `make offchain`: Runs the off-chain Rust verifier.
- `make onchain`: Runs the on-chain Solidity/Hardhat verifier.
- `make clean`: Removes generated artifacts.
- `make close`: Shuts down the `fserver`.

---

## Security

- `share_*.json` and `users/user*.json` contain **secret material**. Do not commit or share.
- Demo code: no TLS, in‑memory state only, minimal replay protection.