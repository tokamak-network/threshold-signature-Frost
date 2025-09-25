# Tokamak FROST (secp256k1) — DKG, Signing & Verification

> **Status:** Experimental / dev-only. Do **not** use in production.

This workspace demonstrates a complete FROST (secp256k1) flow:

1. **Interactive DKG** over WebSocket via a coordinator (`fserver`) and multiple clients (`dkg`).
2. **Threshold signing** (2‑round) using artifacts produced by DKG (`signing`).
3. **Verification** off‑chain (Rust) and on‑chain (Solidity/Hardhat).

**Key properties**
- All DKG packets are **authenticated** with ECDSA (secp256k1) using **Keccak‑256** digests.
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
├─ fserver/               # DKG coordinator (server-only, WebSocket)
├─ keygen/
│  └─ dkg/                # DKG client (speaks to fserver)
├─ signing/               # Round1 / Round2 / aggregate
├─ offchain-verify/       # Verifies signature.json off‑chain
├─ onchain-verify/        # Hardhat project (ZecFrost.sol + scripts)
├─ scripts/
│  └─ make_users.js       # Generates users/user*.json (uids + ECDSA keys)
├─ users/                 # Auto‑generated users (created by scripts)
├─ Makefile               # End‑to‑end drivers
└─ README.md
```

> Older “trusted keygen” flows are **not** used by the Makefile. Use **DKG**.

---

## Quickstart (end‑to‑end, 2‑of‑3)

Runs the full demo (server, DKG clients, signing, verification, shutdown):

```bash
make all out=run_dkg t=2 n=3 gid=mygroup topic=tok1 bind=127.0.0.1:9043
```

What happens:
- `fserver` starts at `ws://127.0.0.1:9043/ws` and exposes `GET /close`.
- `users/user1.json .. user3.json` are (re)generated if missing/mismatched.
- A creator `dkg` client announces the topic; two followers join.
- DKG rounds 1→2→finalize complete and write `run_dkg/group.json` and `run_dkg/share_*.json`.
- `signing` produces partials and aggregates them into `run_dkg/signature.json`.
- Off‑chain and on‑chain verifiers confirm the signature.
- `GET /close` shuts the server down gracefully (~3s).

---

## How it works (high‑level)

1. **Coordinator** listens on `ws://<bind>/ws` and also provides `GET /close`.
2. **Authentication:** clients request a challenge; server returns UUIDv4; client signs `Keccak256(UUID_bytes)` with its ECDSA key; server verifies.
3. **Topic creation:** the creator supplies `min_signers (t)`, `max_signers (n)`, `group_id`, and a **roster** mapping `uid → ECDSA pub (compressed SEC1)`.
4. **Join:** when all `n` participants have joined, server emits `ReadyRound1` and each participant receives their **FROST Identifier**.
5. **Round‑1:** each client runs `dkg::part1`, **signs** its package, and submits. Server verifies and **broadcasts** all Round‑1 packages.
6. **Round‑2:** each client runs `dkg::part2` and produces **(n‑1)** per‑recipient packages. Each is **ECIES‑encrypted** and **ECDSA‑signed (over the encrypted envelope)**. Server verifies and delivers **only** the recipient’s packages.
7. **Finalize:** clients run `dkg::part3` → obtain their `KeyPackage` and the **group verifying key (VK)**. First valid finalize fixes the VK; all others must match. Server emits `Finalized`.
8. **Artifacts:** each client writes `share_<ID>.json`; any client can aggregate signatures later using the `signing` tool.

**ECDSA signing domains** (Keccak‑256 over the bytes shown):
- Round‑1: `"TOKAMAK_FROST_DKG_R1|" || topic || "|" || bincode(id) || bincode(round1_pkg)`
- Round‑2: `"TOKAMAK_FROST_DKG_R2|" || topic || "|" || bincode(from_id) || bincode(to_id) || eph_pub_sec1 || nonce12 || ciphertext`
- Finalize: `"TOKAMAK_FROST_DKG_FIN|" || topic || "|" || bincode(id) || group_vk_sec1`

---

## Manual run (advanced)

### 1) Start the coordinator
```bash
cargo run -p fserver -- server --bind 127.0.0.1:9043
# WS endpoint: ws://127.0.0.1:9043/ws
# Shutdown:    curl -s http://127.0.0.1:9043/close   # → "server closing in 3s"
```

### 2) Create users and roster (dev only)
```bash
node scripts/make_users.js users 3
ls users/
# user1.json user2.json user3.json
```
Each `user*.json` contains:
```json
{
  "uid": 1,
  "ecdsa_priv_hex": "<32-byte hex>",
  "ecdsa_pub_sec1_hex": "<33-byte compressed SEC1 pubkey>"
}
```

### 3) Run the **creator** client
```bash
export DKG_ECDSA_PRIV_HEX=$(node -e 'const fs=require("fs");console.log(JSON.parse(fs.readFileSync("users/user1.json","utf8")).ecdsa_priv_hex)')
PARTS=1,2,3
PUBS=$(node -e 'const fs=require("fs"); const dir="users"; const files=fs.readdirSync(dir).filter(n=>n.startsWith("user")&&n.endsWith(".json")).sort((a,b)=>parseInt(a.replace(/\D+/g,""))-parseInt(b.replace(/\D+/g,""))); console.log(files.map(n=>{const u=JSON.parse(fs.readFileSync(dir+"/"+n,"utf8")); return `${u.uid}:${u.ecdsa_pub_sec1_hex}`}).join(","))')

cargo run -p dkg -- \
  --url ws://127.0.0.1:9043/ws \
  --topic tok1 \
  --create --min-signers 2 --max-signers 3 \
  --group-id mygroup \
  --participants "$PARTS" \
  --participants-pubs "$PUBS" \
  --out-dir run_dkg
```

### 4) Run **followers**
```bash
for i in 2 3; do 
  DKG_ECDSA_PRIV_HEX=$(node -e "const fs=require('fs');console.log(JSON.parse(fs.readFileSync('users/user'+$i+'.json','utf8')).ecdsa_priv_hex)") \
  cargo run -p dkg -- --url ws://127.0.0.1:9043/ws --topic tok1 --out-dir run_dkg &
done; wait
```

You should now have `run_dkg/group.json` and one `share_<ID>.json` per participant.

---

## Artifacts & formats

### `group.json`
```json
{
  "group_id": "mygroup",
  "threshold": 2,
  "participants": 3,
  "group_vk_sec1_hex": "02..."
}
```

### `share_<ID>.json`
```json
{
  "group_id": "mygroup",
  "threshold": 2,
  "participants": 3,
  "signer_id_bincode_hex": "...",
  "secret_share_bincode_hex": "...",
  "verifying_share_bincode_hex": "...",
  "group_vk_sec1_hex": "02..."
}
```

### `signature.json` (produced by `signing aggregate`)
```json
{
  "group_id": "mygroup",
  "signature_bincode_hex": "...",  
  "px": "0x...", "py": "0x...",  
  "rx": "0x...", "ry": "0x...",  
  "s":  "0x...",                   
  "message": "0x..."               
}
```

---

## Threshold signing & verification

Round‑1 (per selected signer):
```bash
cargo run -p signing -- round1 --share run_dkg/share_<ID>.json
```
Round‑2 (per selected signer):
```bash
cargo run -p signing -- round2 \
  --share run_dkg/share_<ID>.json \
  --round1-dir run_dkg \
  --message 'tokamak message to sign' \
  --participants-pubs "<uid:pubhex,uid:pubhex,...>"
```
Aggregate:
```bash
cargo run -p signing -- aggregate \
  --group run_dkg/group.json \
  --round1-dir run_dkg \
  --round2-dir run_dkg \
  --out run_dkg/signature.json \
  --participants-pubs "<uid:pubhex,uid:pubhex,...>"
```
Verify off‑chain:
```bash
cargo run -p offchain-verify -- --signature run_dkg/signature.json
# → Signature valid: true
```
Verify on‑chain (Hardhat):
```bash
cd onchain-verify
SIG=../run_dkg/signature.json npx hardhat run scripts/verify-signature.ts --network hardhat
# → On-chain verify: ✅ valid
```

---

## CLI reference

### `fserver`
```
USAGE:
  fserver server [--bind <IP:PORT>]

FLAGS:
  --bind    Bind address for the WebSocket/HTTP server (default: 127.0.0.1:9000)

Endpoints:
  GET /ws     WebSocket upgrade
  GET /close  Graceful shutdown in ~3 seconds
```

### `dkg`
```
USAGE:
  dkg --url <WS_URL> --topic <STRING> [--create --min-signers <T> --max-signers <N> \
       --group-id <ID> --participants <"1,2,..."> --participants-pubs <"uid:pubhex,...">] \
      --out-dir <DIR> --ecdsa-priv-hex <HEX>

ENV:
  DKG_ECDSA_PRIV_HEX   32-byte ECDSA privkey hex (secp256k1) used to sign/authenticate DKG packets

Notes:
- `--create` is only used by the topic creator. Followers omit it.
- `participants_pubs` entries are 33‑byte **compressed** SEC1 pubkeys in hex.
```

---

## Troubleshooting

- **`participants length must equal max_signers`** – The roster doesn’t match `n`. Regenerate `users/` or fix the inputs.
- **`invalid or reused challenge`** – Request a fresh challenge before `Login`.
- **`user X is already logged in`** – That `uid` already has a session.
- **`ECDSA verify failed`** – Check `participants_pubs` and signature formation.
- **Stuck before Round‑2 dispatch** – Wait for server log: *“All R2 ready: dispatching targeted Round2All”*.

---

## Security

- `share_*.json` contains **secret material**. Do not commit or share.
- Demo code: no TLS, in‑memory state only, minimal replay protection.
- The same long‑term ECDSA key authenticates DKG packets **and** decrypts Round‑2 ECIES; do not reuse in production.

---

## License

MIT/Apache‑2.0 (choose your preference). Provided **as is**, without warranty.
