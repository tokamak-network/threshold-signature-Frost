# tokamak-frost-trusted

A minimal end-to-end demo of **threshold Schnorr** with **FROST** over **secp256k1** (Zcash implementation).

> **Note:** This README covers the Rust workspace (`keygen`, `signing`, `verify`) **and** the on-chain Hardhat project in `onchain/` used to verify `signature.json` with `ZecFrost.sol`.

---

## Workspace layout

```
./
├─ keygen/
│  └─ trusted/         # Rust crate: `keygen` (dealer-style key generation)
├─ signing/            # Rust crate: `signing` (round1, round2, aggregate)
├─ offchain-verify/    # Rust crate: `offchain-verify` (verifies signature.json only)
├─ onchain-verify/     # Hardhat project with ZecFrost + scripts/verify-signature.ts
├─ scripts/            # run_e2e.sh convenience script(s)
├─ Makefile            # quick e2e targets (optional)
└─ README.md
```

### Artifacts per run
```
- `group.json` – group metadata + **group verifying key** (compressed SEC1)
- `share_*.json` – one per participant: **secret share** (private), **verifying share** (public), signer id, and copy of the group VK
- `round1_*.json` – one per selected signer (commitments)
- `round2_*.json` – one per selected signer (signature share, message Keccak-256 digest, and binding to the Round‑1 commitments set/root)
- `signature.json` – aggregate result with fields:
  - `group_id`, `px`, `py`, `rx`, `ry`, `s`, `message` (Keccak‑256 digest hex)
  - `signature_bincode_hex` (raw FROST signature bytes; useful for interop/debug)
- `participants.txt` *(optional)* – helper list of selected `share_*.json` when using `scripts/run_e2e.sh`; otherwise the selection is printed to stdout only
```

---

## Requirements

- Rust (stable) & Cargo
- Node.js ≥ 18 (for on-chain verify)
- bash (for the script)
- `shuf`/`gshuf` optional (script falls back to `awk` if missing)

---

## Build

```bash
cargo build --workspace
```

---

## Quick start (single command)

Runs: keygen → random pick T signers → round1 → round2 → aggregate → verify.

```bash
bash scripts/run_e2e.sh -t 3 -n 5 -g mygroup -o run1 -m "hello tokamak delo"
```

Flags:
- `-t` — threshold (min signers)
- `-n` — total participants
- `-g` — group id
- `-o` — output directory
- `-m` — message (ASCII or `0x…` hex). The pipeline hashes this with **Keccak-256** before signing.

Expected tail output:
```
Signature valid: true
```

---

## Manual flow

### 1) Key generation
```bash
cargo run -p keygen --   --min-signers 3   --max-signers 5   --group-id mygroup   --out-dir run1
```
Outputs: `run1/group.json`, `run1/share_*.json`.

**Schemas** (abridged):
```jsonc
// group.json
{
  "group_id": "mygroup",
  "threshold": 3,
  "participants": 5,
  "group_vk_sec1_hex": "02…33 bytes…"
}

// share_….json  (keep secret)
{
  "group_id": "mygroup",
  "threshold": 3,
  "participants": 5,
  "signer_id_bincode_hex": "…",          // bincode(Identifier)
  "secret_share_bincode_hex": "…",       // bincode(SecretShare)
  "verifying_share_bincode_hex": "…",    // bincode(VerifyingShare)
  "group_vk_sec1_hex": "02…33 bytes…"
}
```

### 2) Round 1 (per selected signer)
```bash
cargo run -p signing -- round1 --share run1/share_…json
```
Writes `run1/round1_<id>.json`.

### 3) Round 2 (per selected signer)
Provide the signer’s share and the directory containing the **matching** Round‑1 files. Message is hashed with Keccak‑256.
```bash
cargo run -p signing -- round2   --share run1/share_…json   --round1-dir run1   --message "hello tokamak delo"
```
Writes `run1/round2_<id>.json` and binds to one Round‑1 commitments set.

### 4) Aggregate (single call)
```bash
cargo run -p signing -- aggregate   --group run1/group.json   --round1-dir run1   --round2-dir run1   --out run1/signature.json
```
Checks: all Round‑2 files agree on **same message digest** and **same Round‑1 commitments root**. Reconstructs the public key package from `group.json` + the verifying shares in selected `share_*.json`, then aggregates.

### 5) Verify (no group.json needed)
```bash
cargo run -p verify -- --signature run1/signature.json
```
Rebuilds the verifying key from `(px,py)`, converts the FROST signature as `serialize_element(R) || serialize_scalar(s)` (compressed `R` || `s`), and verifies via `frost_secp256k1::verify`.

---

## On-chain verification (Hardhat)

Verify `signature.json` against `ZecFrost.sol` on a Hardhat network.

### Script variant (env-driven)
From `onchain/`:
```bash
SIG=../run1/signature.json npx hardhat run scripts/verify-signature.ts --network hardhat
```
Attach to an existing deployment:
```bash
SIG=../run1/signature.json ADDRESS=0xYourZecFrost npx hardhat run scripts/verify-signature.ts --network hardhat
```


### Hardhat task (optional)
If you enabled the task in `hardhat.config.ts`:
```bash
npx hardhat verify-signature --network hardhat --sig ../run1/signature.json
# attach instead of deploy:
npx hardhat verify-signature --network hardhat --sig ../run1/signature.json --address 0xYourZecFrost
```

### On-chain tests (Hardhat)

Run the Hardhat tests for the on-chain verifier.

From `onchain-verify/`:
```bash
npx hardhat test test/ZecFrost.ts
```


> If you see `HHE22` (non-local Hardhat), install dependencies first:
```bash
cd onchain-verify && npm ci
```

### Via Makefile
After an off-chain run you can verify on-chain via:
```bash
make onchain-verify out=run1 net=hardhat
```
Run the full pipeline **plus** on-chain verification in one go:
```bash
make all-onchain t=3 n=5 gid=mygroup out=run1 msg="hello tokamak delo" net=hardhat
```

---

## Troubleshooting

- **`unexpected argument '--shares-dir'`**  
  Round 1 operates **per share**: use `--share <file>` (no `--shares-dir`).

- **`Invalid signature share.` or `Signature valid: false`**  
  Usually mixing files across runs or signer sets. Ensure `round1_dir` and `round2_dir` contain only files from the **same** selected set. Clean the output dir and re-run.

- **`Malformed scalar encoding` (verify)**  
  Indicates point/scalar decoding mismatch. Re-aggregate cleanly. Verifier expects compressed SEC1 points and signature bytes `33(R) || 32(s)`.

- **Random selection**  
  `scripts/run_e2e.sh` writes chosen signers to `participants.txt`. Edit it if you want a specific set.

---

## Security

- `share_*.json` contains **secret material**. Do not commit or share.
- This is a **demo**; not production-hardened.

---

## License

MIT or Apache-2.0
