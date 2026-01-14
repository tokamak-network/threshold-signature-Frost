# Tokamak-FROST Web Client

React-based web client for FROST Distributed Key Generation (DKG) and threshold signing ceremonies.

## Features

- **Multi-Curve Support**: Secp256k1 (Ethereum/FROST) and EdwardsOnBls12381 curves
- **Deterministic Key Derivation**: Derives keys from MetaMask wallet signature
- **Secure Key Storage**: DKG shares encrypted with AES-256-GCM
- **Interactive Ceremonies**: Real-time WebSocket communication for DKG and Signing
- **Unified Port Architecture**: Frontend and WebSocket server run on the same port
- **Security Headers**: CSP, X-Content-Type-Options, and Referrer-Policy

## Project Structure

```
web/
├── src/
│   ├── pages/
│   │   ├── MainPage.tsx      # Home/landing page
│   │   ├── MainPage.css      # Landing page styles
│   │   ├── DkgPage.tsx       # DKG ceremony UI
│   │   └── SigningPage.tsx   # Signing ceremony UI
│   ├── lib.ts                # WASM bindings and crypto utilities
│   ├── types.ts              # TypeScript type definitions
│   ├── useModal.ts           # Modal hook for key management
│   ├── App.tsx               # React router setup
│   ├── App.css               # Application styles
│   └── main.tsx              # React entry point
├── vite.config.ts            # Vite configuration
└── package.json
```

## Getting Started

This package depends on `tokamak-frost-wasm` from the `shared-wasm` workspace.

### From Project Root (Recommended)

```bash
# Build WASM to shared-wasm/pkg/
npm run build:wasm

# Install all workspace dependencies
npm install

# Start unified development server (Vite + ts-fserver on same port)
npm run dev:web
```

This starts a unified server at **http://localhost:5173** with:
- Frontend served by Vite
- WebSocket server (ts-fserver) at `/frost-ws` on the same port

### From web Directory

```bash
# Start integrated development server (Vite + ts-fserver on single port)
npm run dev

# Production build
npm run build

# Preview production build
npm run preview
```

## Available Scripts

| Script | Description |
|--------|-------------|
| `npm run dev` | Start Vite development server |
| `npm run build` | Production build (TypeScript + Vite) |
| `npm run preview` | Preview production build locally |
| `npm run start-server` | Start Rust fserver coordinator on `0.0.0.0:9034` |
| `npm run lint` | Run ESLint |

### Root Workspace Commands

| Script | Description |
|--------|-------------|
| `npm run build:wasm` | Build WASM from `packages/rust/wasm` → `packages/ts/shared-wasm/pkg` |
| `npm run dev:web` | Start unified web client + ts-fserver (single port) |

## Security

The web client implements several security measures:

### Content Security Policy (CSP)
Restricts resource loading to prevent XSS attacks:
- Scripts: Only from same origin and WASM
- Connections: Same origin WebSocket (ws/wss)
- Styles: Same origin and inline (for React)

### WebSocket Origin Validation
The ts-fserver validates WebSocket connection origins:
- Allows same-origin connections
- Allows localhost for development
- Rejects cross-origin connections from unknown origins

### HTTPS Support
The client automatically uses `wss://` (secure WebSocket) when served over HTTPS.

## Cryptographic Key Types

The client supports two modes for the **Roster KeyKeyPair** (the key used to identify the participant and sign messages):

1.  **Secp256k1**: Standard for Bitcoin and Ethereum. Used for standard FROST operations.
2.  **EdwardsOnBls12381**: Edwards curve on BLS12-381.

**Note**: The choice of key type also determines the structure of the keys generated during DKG.

## Workflows

### 1. Distributed Key Generation (DKG)

The DKG ceremony generates a shared group secret distributed among participants.

1.  **Announce**: The coordinator sets the number of participants, threshold, and **Key Type**.
2.  **Key Generation**:
    *   **MetaMask Connected**: Users can deterministically derive their Roster Key from a MetaMask signature.
    *   **Manual/Random**: Users can opt to generate a fresh random key pair (useful for testing or non-MetaMask usage).
3.  **Completion**: Once finalized, the client generates a secret key package.
4.  **Download**: The user downloads a `frost-key-{GroupPrefix}-{UserPrefix}.json` file.
    *   **Encrypted**: If the user derived their keys from MetaMask, this file is encrypted with their derived AES Key.
    *   **Structure**:
        ```json
        {
          "key_type": "secp256k1", // or "edwards_on_bls12381"
          "finalShare": { "ciphertext_hex": "...", "nonce_hex": "..." },
          "finalGroupKey": "..."
        }
        ```

### 2. Signing Ceremony

The signing ceremony uses the DKG credentials to sign a message as a group.

1.  **Upload Key File**:
    *   Users just upload their `frost-key-....json` file.
    *   The application **automatically detects** the Key Type (Secp256k1 or EdwardsOnBls12381) from the file.
2.  **Derive Roster Key**:
    *   The user clicks "Derive Roster Key".
    *   They sign a message with MetaMask to regenerate their AES Key and Roster Key.
    *   The application **automatically decrypts** the uploaded key package using the derived AES Key.
3.  **Connect & Sign**:
    *   Once keys are ready, the "Connect & Login" button becomes enabled.
    *   Users join the session and produce a partial signature.
    *   The coordinator aggregates these into a final signature.

## Key Derivation Mechanism

To eliminate the need for storing unsecured private keys, we derive them *deterministically* on-the-fly from a wallet signature. This allows a user to recover their identity and data solely from their Ethereum wallet.

### Protocol Specification

The keys are derived from a signature of the message:  
`M = "Tokamak-Frost-Seed V1 with salt of {salt}"`
where `{salt}` is a user-supplied numeric value (default "2026").

#### 1. Entropy Generation
User signs `M` using their Ethereum wallet (Secp256k1):
`Sig = Sign_Ethereum(Wallet_Private_Key, M)`
*(Result is a 65-byte ECDSA signature)*

#### 2. Primary Hashing
The signature is hashed using SHA-512 to ensure uniform distribution and sufficient length:
`H = SHA512(Sig)`
*(Result is 64 bytes)*

#### 3. Domain Separation
The 64-byte hash `H` is split into two 32-byte chunks:
- `H1 = H[0..32]` (Used for Roster Identity)
- `H2 = H[32..64]` (Used for Data Encryption)

#### 4. Key Derivation

**A. Roster Key (Identity)**
The specific derivation depends on the chosen curve:

-   **Secp256k1 (FROST/ETH)**:
    -   `Seed = Keccak256(H1)`
    -   `Private_Key = Secp256k1_Scalar(Seed)`
-   **EdwardsOnBls12381**:
    -   `Seed = Keccak256(H1)`
    -   `Private_Key = EdwardsOnBls12381_Scalar(Seed)` (Using `EdDSAPrivateKey::from_bytes`)

**B. AES Key (Encryption)**
Used to encrypt/decrypt the DKG secret share.
-   `AES_Key = Keccak256(H2)`
-   Algorithm: **AES-256-GCM**
-   This ensures that even if the Roster Key is compromised (or used publicly), the encryption key for the DKG share remains mathematically distinct.
