# Tokamak-FROST Web Client

This directory contains the source code for the React-based web client that interacts with the `tokamak-frost-wasm` package and the `f-server` coordinator. It provides a user interface for performing FROST Distributed Key Generation (DKG) and signing ceremonies.

## Available Scripts

In the project directory, you can run:

-   `npm run dev`: Runs the app in development mode.
-   `npm run start-server`: Starts the `f-server` coordinator on `127.0.0.1:9034`.
-   `npm run build-wasm`: Builds the WASM package from the parent directory.
-   `npm run build`: Builds the app for production, including the WASM package.
-   `npm run lint`: Lints the project files.
-   `npm run preview`: Serves the production build locally for preview.

## Key Derivation and Management

A core security feature of this client is its key derivation mechanism, which generates the necessary cryptographic keys from a single signature provided by a user's MetaMask wallet. This process creates two distinct keys for different purposes: a **Roster Keypair** for on-chain identity and session authentication, and a symmetric **AES Key** for encrypting the user's secret share.

### Derivation Process

The keys are derived from a signature of the static message `M = "Tokamak-Frost-Seed V1"`.

1.  **Signature Generation:** The user signs the message `M` with their MetaMask private key (`SK_metamask`).
    
    `Sig = Sign(SK_metamask, M)`

2.  **Primary Hashing (SHA-512):** The resulting signature `Sig` is hashed using SHA-512 to produce a 64-byte output, `H_512`.
    
    `H_512 = SHA512(Sig)`

3.  **Hash Splitting:** The 64-byte hash is split into two 32-byte chunks, `H_1` and `H_2`.
    
    `H_512 = H_1 || H_2`

4.  **Key Derivation (Keccak-256):** The two chunks are hashed separately using Keccak-256 to produce the final keys.
    
    -   The **Roster Private Key** (`SK_roster`) is derived from the first chunk:
        
        `SK_roster = Keccak256(H_1)`
    
    -   The **AES Key** (`K_aes`) is derived from the second chunk:
        
        `K_aes = Keccak256(H_2)`

The Roster Public Key (`PK_roster`) is then derived from `SK_roster` using standard elliptic curve operations.

## Secret Share Encryption

To protect the user's sensitive DKG secret share, it is encrypted at rest using the derived AES key.

-   **Encryption:** After a successful DKG ceremony, the resulting secret share (the `KeyPackage`) is encrypted using **AES-256-GCM** with the derived key `K_aes`.
-   **Storage:** The output of the encryption is a JSON object containing the `ciphertext` and a unique `nonce`. This object is what is displayed to the user and saved in the `frost-key.json` file. The plaintext secret share is never stored in the browser's local storage or displayed directly.
-   **Decryption:** When the user uploads the `frost-key.json` file for a signing ceremony, the application uses the same derived `K_aes` to decrypt the share in the browser's memory just before it is needed for the signing operation.

This ensures that the secret share remains confidential and protected against tampering, even if the user's downloaded key file is exposed.
