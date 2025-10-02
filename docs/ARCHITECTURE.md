# Tokamak FROST (secp256k1) – Architecture Overview

Status: Experimental/dev-only. Not for production use.

This repository demonstrates a complete FROST threshold flow on secp256k1:

- Interactive DKG over WebSocket, coordinated by a server (fserver) and multiple clients (dkg)
- Threshold Signing (round1/round2 + aggregate) with artifacts written by DKG
- Verification off-chain (Rust) and on-chain (Solidity/Hardhat)

## Crates and Projects

- fserver (Rust): Axum-based WebSocket coordinator for DKG and interactive signing
- keygen/dkg (Rust): DKG client that speaks to fserver; produces group.json + share_*.json
- keygen/trusted (Rust): Dealer-based one-shot keygen (legacy/demo)
- signing (Rust): CLI for Round1/2/aggregate and an optional interactive WS sign client
- offchain-verify (Rust): Verifies signature.json without requiring any other context
- onchain-verify (Hardhat): Solidity contracts (ZecFrost.sol) + scripts for on-chain verification

## Protocols and Crypto

- FROST (secp256k1 ciphersuite) from Zcash Foundation.
- DKG Messages: Authenticated via ECDSA (secp256k1) over a Keccak256 digest.
- DKG Round 2 payloads: Per-recipient ECIES (secp256k1 ECDH -> AES-256-GCM), then ECDSA-signed over the encrypted envelope.
- Signing: 2-round FROST; message domain is Keccak256(message bytes) throughout the demo.

### ECDSA Signing Domains (Keccak256 over the bytes shown)
- DKG Round1: "TOKAMAK_FROST_DKG_R1|" || session || "|" || bincode(id) || bincode(round1_pkg)
- DKG Round2: "TOKAMAK_FROST_DKG_R2|" || session || "|" || bincode(from) || bincode(to) || eph_pub || nonce || ct
- DKG Finalize: "TOKAMAK_FROST_DKG_FIN|" || session || "|" || bincode(id) || group_vk_sec1
- Interactive Sign R1: "SIGN_WS_R1|" || session || "|" || group_id || "|" || id_hex || "|" || commits_hex
- Interactive Sign R2: "SIGN_WS_R2|" || session || "|" || group_id || "|" || id_hex || "|" || sigshare_hex || "|" || msg32_hex

## Artifacts

- group.json: { group_id, threshold, participants, group_vk_sec1_hex, session? }
- share_<ID>.json: { group_id, threshold, participants, signer_id_bincode_hex, secret_share_bincode_hex, verifying_share_bincode_hex, group_vk_sec1_hex, session? }
- signature.json: { group_id, signature_bincode_hex, px,py, rx,ry, s, message, session? }

## End-to-end Flow

1) Start server (fserver) and create users (scripts/make_users.js)
2) Creator runs DKG client in create mode; followers join using the server-issued session id
3) After all three DKG rounds, each participant has a private share file; group.json is agreed
4) Signing: either offline (Round1/2 + aggregate) or interactive WebSocket with fserver
5) Verify off-chain (Rust) and on-chain (Hardhat) using signature.json

## Ports and Endpoints

- WS endpoint: ws://<bind>/ws
- HTTP shutdown: GET /close (server shuts down in ~3 seconds)

## Security Notes

- Demo only: no TLS, in-memory state, minimal replay protection
- Long-term ECDSA key authenticates DKG packets and decrypts ECIES – do not reuse in production
- share_*.json contains secret material; never commit or share

## Build & Run (short)

- Rust stable & Cargo required; Node >= 18 for onchain-verify
- Build all Rust crates: `cargo build`
- Quick demo via Makefile: `make all out=run_dkg t=2 n=3 gid=mygroup bind=127.0.0.1:9043`

See the top-level README.md for detailed commands and troubleshooting.

