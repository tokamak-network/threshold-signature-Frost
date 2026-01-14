# Tokamak‑FROST

Session‑based Distributed Key Generation (DKG) and Schnorr threshold signing with support for **secp256k1** (ECDSA) and **EdwardsOnBls12381** (EdDSA) curves.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [TypeScript Development](#typescript-development)
- [CLI Commands Reference](#cli-commands-reference)
- [Makefile Reference](#makefile-reference)
- [Session Lifecycle](#session-lifecycle)
- [Artifacts & Folder Layout](#artifacts--folder-layout)
- [Authentication](#authentication)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

---

## Overview

**Tokamak‑FROST** implements:
- A lightweight **coordinator** (`fserver`) that manages **sessions** over WebSocket
- CLI participants for **key generation** and **signing** using **FROST** Schnorr
- A **React web frontend** for interactive DKG and signing ceremonies
- A **TypeScript server** (`ts-fserver`) as an alternative coordinator
- Deterministic, reproducible **artifacts** (group info, shares, verifying keys, signatures)

### Supported Curves
| Curve | Key Type | Use Case |
|-------|----------|----------|
| `secp256k1` | ECDSA | Ethereum-compatible signatures |
| `edwards_on_bls12381` | EdDSA | EdDSA-compatible signatures |

---

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

---

## Project Structure

```
packages/
├── rust/                    # Rust crates
│   ├── dkg/                 # DKG protocol CLI
│   ├── signing/             # Signing protocol CLI
│   ├── fserver/             # WebSocket coordinator server (Rust)
│   ├── helper/              # Shared crypto utilities
│   ├── offchain-verify/     # Offchain signature verification
│   └── wasm/                # WASM bindings source
│
└── ts/                      # TypeScript packages
    ├── shared-wasm/         # Universal WASM package (browser + Node.js)
    ├── web/                 # React frontend (Vite)
    ├── ts-fserver/          # TypeScript coordinator server
    └── onchain-verify/      # Hardhat contracts for on-chain verification
```

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Rust** | stable | `rustup default stable` |
| **wasm-pack** | latest | `cargo install wasm-pack` |
| **Node.js** | 18+ | For TypeScript packages |
| **npm** | 8+ | Comes with Node.js |

**Supported platforms:** macOS, Linux, Windows (via WSL)

---

## Installation

### 1. Clone and Install Dependencies

```bash
git clone <repository-url>
cd threshold-signature-Frost

# Install Node.js dependencies
npm install
```

### 2. Build Rust Workspace

```bash
cargo build --workspace
```

### 3. Build WASM (Universal)

Build WASM once for both web and server:

```bash
npm run build:wasm
```

This builds to `packages/ts/shared-wasm/pkg/` and works in both browser and Node.js environments.

---

## Quick Start

### Option 1: Web UI (Recommended)

Start the integrated development environment:

```bash
npm run dev:web
```

This single command starts a **unified server** at http://localhost:5173 that includes:
- **Vite frontend** serving the React web application
- **TypeScript coordinator server** (ts-fserver) on the same port via WebSocket at `/frost-ws`

The ts-fserver is automatically embedded via a Vite plugin, providing a complete development environment with one command and a single port.

Open **http://localhost:5173** in your browser to access the DKG and Signing pages.

### Option 2: CLI Demo (2-of-3)

Run a full end-to-end demo with the Makefile:

```bash
# Clean previous run and start fresh DKG (2-of-3 threshold)
make dkg out=run_dkg t=2 n=3 gid=mygroup KEY_TYPE=secp256k1

# Run signing ceremony
make ws-sign out=run_dkg t=2 n=3 msg="hello frost" KEY_TYPE=secp256k1

# Clean up artifacts
make clean out=run_dkg
```

---

## TypeScript Development

### NPM Scripts

| Command | Description |
|---------|-------------|
| `npm run build:wasm` | Build WASM to `shared-wasm/pkg/` (universal) |
| `npm run dev:web` | Start Vite + embedded ts-fserver (recommended for development) |
| `npm run dev:server` | Start TypeScript coordinator server only (dev mode) |
| `npm run start:server` | Start TypeScript coordinator server only (production) |

> **Note:** `npm run dev:web` runs everything on a single port (5173). The ts-fserver is attached to Vite's HTTP server at the `/frost-ws` WebSocket path. You don't need to run `dev:server` separately when using the web UI.

### Web Frontend

The React web frontend provides:
- **DKG Page** (`/dkg`) - Distributed Key Generation ceremony
- **Signing Page** (`/signing`) - Threshold signing ceremony

Features:
- MetaMask integration for key derivation
- Upload/download encrypted key packages
- Real-time ceremony progress

### TypeScript Server (Standalone)

If you need to run the ts-fserver separately (without the web UI):

```bash
# Development (with hot reload)
npm run dev:server

# Production
npm run start:server

# Custom port
PORT=9034 npm run start:server
```

---

## CLI Commands Reference

### Start Rust Coordinator Server

```bash
cargo run -p fserver -- server --bind 127.0.0.1:9034
```

### DKG (Distributed Key Generation)

**Creator (initiates session):**
```bash
cargo run -p dkg -- \
  --key-type secp256k1 \
  --private-key <PRIVATE_KEY_HEX> \
  --url ws://127.0.0.1:9034/ws \
  --create \
  --min-signers 2 \
  --max-signers 3 \
  --group-id my-frost-group \
  --participants "1,2,3" \
  --participants-pubs "<PARTICIPANT_PUBS>" \
  --out-dir run_dkg \
  --session-file run_dkg/session.txt
```

**Joiner (joins existing session):**
```bash
cargo run -p dkg -- \
  --key-type secp256k1 \
  --private-key <PRIVATE_KEY_HEX> \
  --url ws://127.0.0.1:9034/ws \
  --out-dir run_dkg \
  --session-file run_dkg/session.txt
```

### Signing

**WebSocket-based signing:**
```bash
cargo run -p signing -- \
  --key-type secp256k1 \
  --private-key <PRIVATE_KEY_HEX> \
  ws \
  --url ws://127.0.0.1:9034/ws \
  --create \
  --group-id my-frost-group \
  --threshold 2 \
  --participants "1,2,3" \
  --participants-pubs "<PARTICIPANT_PUBS>" \
  --group-vk-sec1-hex <GROUP_VK_HEX> \
  --message "hello frost" \
  --share run_dkg/share_1.json \
  --session-file run_dkg/sign_session.txt \
  --out-dir run_dkg
```

### Verification

**Offchain verification (Rust):**
```bash
cargo run -p offchain-verify -- --signature run_dkg/signature.json
```

**Onchain verification (Hardhat):**
```bash
cd packages/ts/onchain-verify
SIG="../../../run_dkg/signature.json" npx hardhat run scripts/verify-signature.ts --network hardhat
```

---

## Makefile Reference

### Targets

| Target | Description |
|--------|-------------|
| `make help` | Show available targets and variables |
| `make build` | Build entire Rust workspace |
| `make dkg` | Run DKG ceremony (creates group.json, shares) |
| `make ws-sign` | Run signing ceremony over WebSocket |
| `make offchain` | Verify signature offchain (Rust) |
| `make onchain` | Verify signature onchain (Hardhat) |
| `make all` | Run full demo: DKG → Sign → Verify |
| `make clean` | Remove output directory |
| `make close` | Shutdown the fserver |

### Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `t` | `2` | Threshold (minimum signers required) |
| `n` | `2` | Total number of participants |
| `gid` | `mygroup` | Group identifier string |
| `out` | `run_dkg` | Output directory for artifacts |
| `bind` | `127.0.0.1:9034` | Server host:port |
| `msg` | `tokamak message to sign` | Message to sign |
| `KEY_TYPE` | `secp256k1` | Key type: `secp256k1` or `edwards_on_bls12381` |

### Examples

```bash
# 2-of-3 ECDSA (secp256k1) DKG
make dkg t=2 n=3 gid=my-secp-group KEY_TYPE=secp256k1

# 3-of-5 EdDSA DKG
make dkg t=3 n=5 gid=my-ed-group KEY_TYPE=edwards_on_bls12381

# Sign a message
make ws-sign t=2 n=3 out=run_dkg msg="hello frost" KEY_TYPE=secp256k1

# Full end-to-end demo
make all t=2 n=3 gid=demo-group msg="test message"

# Clean up and start fresh
make clean out=run_dkg
```

---

## Session Lifecycle

1. **Start server:**
   ```bash
   cargo run -p fserver -- server --bind 127.0.0.1:9034
   # or
   npm run dev:server
   ```

2. **Create session (creator):**
   - Creator connects and sends `CreateSession`
   - Server replies with `session_id`

3. **Join session (participants):**
   - Each participant sends `JoinSession { session_id, ... }`
   - Server tracks who has joined

4. **DKG Rounds:**
   - Round 1: Participants exchange commitments
   - Round 2: Participants exchange encrypted shares
   - Finalize: Each participant derives their key share

5. **Signing:**
   - Subset of `t` parties create a signing session
   - Round 1: Exchange commitments
   - Round 2: Exchange signature shares
   - Aggregate: Final signature produced

---

## Artifacts & Folder Layout

A typical run directory contains:

```
run_dkg/
├── session.txt              # DKG session ID
├── group.json               # Group verifying key (x,y), parameters (t,n,gid)
├── share_1.json             # Signing share for participant 1
├── share_2.json             # Signing share for participant 2
├── share_3.json             # Signing share for participant 3
├── sign_session.txt         # Signing session ID
└── signature.json           # Final signature (R.x, R.y, s, message hash)

users/                       # Participant identity files (created by make)
├── user1.json               # Participant 1 keys
├── user2.json               # Participant 2 keys
└── user3.json               # Participant 3 keys
```

---

## Authentication

Clients authenticate to the coordinator via **ECDSA/EdDSA challenge-response**:

1. Server issues a random challenge (UUID)
2. Client signs the challenge with their roster private key
3. Server verifies the signature against the declared public key

This keeps enrollment stateless and automatable.

---

## Testing

### Run All Tests

Execute the comprehensive test suite:

```bash
bash test_all.sh
```

**Cross-platform support:** Works on macOS, Linux, and Windows WSL.

The test script runs:

| Test | Description |
|------|-------------|
| **Rust Unit Tests** | `cargo test --workspace` |
| **WASM Build** | Verifies `npm run build:wasm` works |
| **Makefile DKG (secp256k1)** | 2-of-2 DKG with ECDSA keys |
| **Makefile DKG (EdDSA)** | 2-of-2 DKG with EdwardsOnBls12381 keys |
| **TypeScript Integration** | Full DKG + Signing flow via ts-fserver |
| **Web Dev Server** | Verifies Vite starts with embedded ts-fserver |

### Individual Tests

```bash
# Rust tests only
cargo test --workspace

# TypeScript integration test (requires server running)
npm run start:server &
cd packages/ts/ts-fserver
node --loader ts-node/esm test/signing_test.ts

# Makefile DKG test
make dkg t=2 n=2 gid=test KEY_TYPE=secp256k1 out=test_run
make clean out=test_run
```

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| **Port already in use** | Run `make close` or choose different `--bind` port |
| **WASM not found** | Run `npm run build:wasm` first |
| **No share_*.json** | Run `make dkg` before signing |
| **Session not found** | Ensure session.txt exists and contains valid session ID |
| **Firewall/WSS** | For remote clients, use `wss://` with TLS termination |
| **Artifacts missing** | Ensure the output directory is writable |

### Debug Commands

```bash
# Check if server is running
curl http://127.0.0.1:9034/health

# Close running server
curl http://127.0.0.1:9034/close
make close

# Check port usage
lsof -i :9034
```

---

## License

[Add your license information here]
