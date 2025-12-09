# Tokamak-FROST Web Client

This directory contains the source code for the React-based web client that interacts with the `tokamak-frost-wasm` package and the `f-server` coordinator. It provides a user interface for performing FROST Distributed Key Generation (DKG) and signing ceremonies.

## Features

-   **Multi-Curve Support**: Supports both **Secp256k1** (Ethereum/FROST) and **Ed25519** (Solana/ZCash) elliptic curves.
-   **Deterministic Key Derivation**: Derives consistent Roster and AES keys directly from a MetaMask wallet signature, ensuring users don't need to manage separate backup files for their identities.
-   **Secure Key Storage**: Detailed DKG secret shares are encrypted at rest using AES-256-GCM derived from the user's wallet.
-   **Interactive Ceremonies**: Real-time WebSocket communication for multi-party DKG and Signing sessions.

## Available Scripts

In the project directory, you can run:

-   `npm run dev`: Runs the app in development mode.
-   `npm run start-server`: Starts the `f-server` coordinator on `127.0.0.1:9034`.
-   `npm run build-wasm`: Builds the WASM package from the parent directory.
-   `npm run build`: Builds the app for production, including the WASM package.
-   `npm run lint`: Lints the project files.

## Cryptographic Key Types

The client supports two modes for the **Roster KeyKeyPair** (the key used to identify the participant and sign messages):

1.  **Secp256k1**: Standard for Bitcoin and Ethereum. Used for standard FROST operations.
2.  **Ed25519**: Standard for Solana and Cosmos.

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
          "key_type": "secp256k1", // or "ed25519"
          "finalShare": { "ciphertext_hex": "...", "nonce_hex": "..." },
          "finalGroupKey": "..."
        }
        ```

### 2. Signing Ceremony

The signing ceremony uses the DKG credentials to sign a message as a group.

1.  **Upload Key File**:
    *   Users just upload their `frost-key-....json` file.
    *   The application **automatically detects** the Key Type (Secp256k1 or Ed25519) from the file.
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

The keys are derived from a signature of the static message:  
`M = "Tokamak-Frost-Seed V1"`

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
-   **Ed25519 (Solana/ZCash)**:
    -   `Seed = Keccak256(H1)`
    -   `Private_Key = Ed25519_Scalar(Seed)` (Using `EdDSAPrivateKey::from_bytes`)

**B. AES Key (Encryption)**
Used to encrypt/decrypt the DKG secret share.
-   `AES_Key = Keccak256(H2)`
-   Algorithm: **AES-256-GCM**
-   This ensures that even if the Roster Key is compromised (or used publicly), the encryption key for the DKG share remains mathematically distinct.
