# Tokamak‑FROST

Session‑based Distributed Key Generation (DKG) and Schnorr (secp256k1) threshold signing.

> **What changed (Oct 2, 2025):** We **removed `topic`** everywhere. The flow is now **session‑based**: a **creator** initiates a **session** and the **fserver** generates a unique `session_id`. All clients use that `session_id` to join and proceed through keygen/signing. The `fserver` and `signing` crates have been updated accordingly.

---

## Contents
- [Overview](#overview)
- [Architecture](#architecture)
- [Install & Build](#install--build)
- [Quick Start (local 2-of-3 demo)](#quick-start-local-2-of-3-demo)
- [Session Lifecycle](#session-lifecycle)
- [Artifacts & Folder Layout](#artifacts--folder-layout)
- [Authentication (ECDSA challenge)](#authentication-ecdsa-challenge)
- [Commands Reference](#commands-reference)
- [Troubleshooting](#troubleshooting)

---

## Overview
**Tokamak‑FROST** implements:
- A lightweight **coordinator** (`fserver`) that manages **sessions** over WebSocket.
- CLI participants for **key generation** and **signing** using **FROST(secp256k1)** Schnorr.
- Deterministic, reproducible **artifacts** (group info, shares, verifying keys, signatures) written to disk.

## Architecture
```
 +----------+         ws://host:port/ws          +-----------+
 | Creator  |  ─────────────────────────────────▶|           |
 | (client) |   CreateSession → session_id       |           |
 +----------+                                     |  fserver  |
       ▲     JoinSession(session_id)              | (coord.)  |
       │     …                                    |           |
       │                                          +-----------+
       │                                               ▲  ▲
       │   JoinSession(session_id)                     │  │
 +-----┴---+                                      Join/Msgs │
 | Party B |                                              │
 +---------+                                      +-------┴--+
 | Party C |                                      | Signing  |
 +---------+                                      | clients  |
                                                  +----------+
```
- The **first** client to connect (or an explicit creator CLI) sends **CreateSession**. The **fserver** replies with a **`session_id`** and persists minimal metadata.
- All parties **JoinSession(session_id)** and proceed through the DKG and signing rounds coordinated by `fserver`.

## Install & Build
Prerequisites:
- **Rust** (stable). `rustup default stable` is fine.
- (Optional) **Node.js** if you run TS examples.
- macOS / Linux supported. Windows via WSL.

Build everything:
```bash
cargo build --workspace
```

## Quick Start (local 2‑of‑3 demo)
This starts an in‑process demo that spawns the server and 3 local clients writing outputs under `run_dkg/`.

```bash
# Clean previous run and start fresh demo (2-of-3)
make all out=run_dkg t=2 n=3 gid=mygroup bind=127.0.0.1:9054
```
What happens now:
1. `fserver` starts and listens on **`ws://127.0.0.1:9054/ws`**.
2. The **creator** client connects and sends **CreateSession**. The server emits a **`session_id`** (also saved to `run_dkg/session.txt`).
3. Remaining participants **join** using that `session_id`.
4. DKG completes → `group.json`, `users/*/share.json` written.
5. A sample **signing** run is executed to produce `signature.json`.


## Session Lifecycle
1. **Start server** (standalone):
   ```bash
   cargo run -p fserver -- server --bind 127.0.0.1:9054
   # logs: "DKG coordinator listening on ws://127.0.0.1:9054/ws"
   ```
2. **Create a session** (creator):
    - When using the demo `make all …`, the **creator** step is automated.
    - If running manually, the creator client issues **CreateSession** over WS; the server replies with `session_id`.
3. **Join session** (participants):
    - Each participant connects to `/ws` and sends **JoinSession { session_id, … }**.
4. **Run DKG**:
    - The coordinator advances rounds; on completion, clients write **shares** and the server (or clients) write **group verifying key**.
5. **Sign**:
    - A subset of **t** parties run the signing protocol for a message.
    - `signature.json` (R.x, R.y, s, challenge, msg) is produced.

## Artifacts & Folder Layout
A typical run directory (e.g., `run_dkg/`) contains:
```
run_dkg/
  session.txt              # the session_id assigned by fserver
  session.json             # (optional) minimal session metadata
  group.json               # group verifying key (x,y), parameters (t,n,gid)
  users/
    user_1/
      share.json           # signing share for participant 1
      vk.json              # participant verifying key (optional)
    user_2/
      share.json
    user_3/
      share.json
  signing/
    message.txt            # the message that was signed
    signature.json         # R.x, R.y, s, challenge (hex), signer indexes
```
> Paths/filenames are stable across runs; content differs. If a file already exists, the demo overwrites the directory unless you change `out=`.

## Authentication (ECDSA challenge)
- We removed password‑based CLI auth. **Clients authenticate** to the coordinator via **ECDSA challenge/response**.
- The server issues a random challenge; clients respond with `secp256k1` signature. The server uses `ecrecover` semantics to check ownership of the declared address.
- This keeps the enrollment stateless and automatable.

## Commands Reference
### Makefile (local demo)
```bash
# 2-of-3 demo to ./run_dkg
make all out=run_dkg t=2 n=3 gid=mygroup bind=127.0.0.1:9054

# Customize output directory
make all out=demo1 t=3 n=5 gid=teamA bind=0.0.0.0:9054
```

### Start only the server
```bash
cargo run -p fserver -- server --bind 127.0.0.1:9054
```

### Run creator/participants manually (example)
```bash
# Creator: create a new session (prints session_id)
cargo run -p signing -- create-session \
  --gid mygroup --t 2 --n 3 \
  --server ws://127.0.0.1:9054/ws \
  --out run_dkg

# Joiners: join the printed session_id
cargo run -p signing -- join-session \
  --session $(cat run_dkg/session.txt) \
  --server ws://127.0.0.1:9054/ws \
  --out run_dkg/users/user_2

cargo run -p signing -- join-session \
  --session $(cat run_dkg/session.txt) \
  --server ws://127.0.0.1:9054/ws \
  --out run_dkg/users/user_3

# Signing (any t participants)
MESSAGE_HEX="48656c6c6f20546f6b616d616b21" # "Hello Tokamak!"
cargo run -p signing -- sign \
  --session $(cat run_dkg/session.txt) \
  --message-hex $MESSAGE_HEX \
  --server ws://127.0.0.1:9054/ws \
  --out run_dkg/signing
```

## Troubleshooting
- **`no such file or directory: emsdk_env.sh`**: This repo doesn’t require Emscripten. Remove stray `source …/emsdk_env.sh` lines from your shell rc files if you see this warning.
- **Port already in use**: pick another `--bind` or stop the previous server.
- **Firewall/WSS**: for remote clients use `wss://` with proper TLS termination.
- **Artifacts missing**: ensure the `out/` directory is writable; the demo wipes it before each run.

---
 
