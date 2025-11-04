# Tokamak-FROST DKG Web Client

This directory contains a modern web-based client for participating in a FROST (Flexible Round-Optimized Schnorr Threshold) Distributed Key Generation (DKG) ceremony. The application is built using Vite, React, and TypeScript, and it interacts with a Rust-based `fserver` coordinator via WebSockets.

It provides a user-friendly interface for creating and joining DKG sessions, deriving cryptographic keys, and monitoring the progress of the ceremony in real-time.

## Features

- **Two User Roles:** A toggle switch allows users to seamlessly switch between a **Creator** role to initiate new DKG sessions and a **Participant** role to join existing ones.
- **Dynamic UI:** The interface is context-aware, showing relevant controls based on the user's selected role and the current state of the DKG ceremony.
- **Context-Aware Key Generation:**
  - A master **Wallet Switch** in the header controls the key generation method.
  - **MetaMask Mode:** When the switch is on, users can derive a secure roster key by signing a fixed message (`"Tokamak-Frost-Seed V1"`).
  - **Local Mode:** When the switch is off, users can generate a new random key pair locally.
- **Session Lobby:** Participants can see a list of pending DKG sessions available on the server, view their status, and join with a single click.
- **Deterministic UID Generation:** The creator provides a list of participant public keys. The application automatically sorts these keys and assigns UIDs (`1, 2, 3,...`) based on that sorted order, ensuring all clients and the server derive the same UIDs for the same set of participants.
- **Real-Time Feedback:**
  - A live log view streams all client-side actions and server messages, with a button to clear the view.
  - A status panel with animated indicators shows the current round of the DKG ceremony (Round 1, Round 2, Finalized).
  - A live-updating table shows which participants have successfully joined a session.
- **Graceful Disconnection Handling:** The UI updates in real-time if a participant disconnects from a session, and users are provided with a "Disconnect" button.

## Technology Stack

- **Frontend Framework:** React with TypeScript
- **Build Tool:** Vite
- **Web3 Integration:** `wagmi` & `viem` for connecting to MetaMask and signing messages.
- **Cryptography:** A Rust-based WASM module (`tokamak_frost_wasm`) handles all cryptographic operations, including key generation, signing, and the FROST DKG protocol logic.
- **Communication:** Secure WebSockets for real-time communication with the `fserver`.

## Setup and Usage

To run the full system, you will need two separate terminal windows: one for the `fserver` and one for the web client.

### 1. Run the Server

First, start the `fserver` coordinator.

```sh
# Navigate to the project root
cd /path/to/tokamak-frost

# Run the server (e.g., on port 9034)
cargo run -p fserver -- server --bind 127.0.0.1:9034
```

### 2. Run the Web Client (Development)

In a second terminal, navigate to this directory (`wasm/web`) to set up and run the client.

```sh
# Navigate to the web client directory
cd /path/to/tokamak-frost/wasm/web

# Install dependencies (only needs to be done once)
npm install
# or
yarn install

# Run the development server
npm run dev
```

Vite will start the development server (usually on a port like `5173`) and automatically open the application in your web browser.

### 3. Building for Production

To create a production-ready build of the application, which includes compiling the WASM module and optimizing the React code, run the following command from the `wasm/web` directory:

```sh
npm run build
```

This command will:
1.  Execute the `build-wasm` script to compile the Rust code into a WASM module using `wasm-pack`.
2.  Build and bundle the React application for production using Vite.

The optimized static files will be placed in the `dist/` directory.

## WebSocket Messaging Protocol

This section details the WebSocket messages exchanged between the web client and the `fserver`.

### Client to Server (Outgoing)

- **`AnnounceSession`**: Sent by a creator to initiate a new DKG session.
  - `payload`: `{ group_id: string, min_signers: number, max_signers: number, participants: number[], participants_pubs: [number, string][] }`
- **`RequestChallenge`**: Sent by any client to request a unique challenge for login.
- **`Login`**: Sent by a client after signing the challenge.
  - `payload`: `{ challenge: string, pubkey_hex: string, signature_hex: string }`
- **`ListPendingDKGSessions`**: Sent by a participant to get a list of available sessions to join.
- **`JoinSession`**: Sent by a participant to join a specific session from the lobby.
  - `payload`: `{ session: string }`
- **`Round1Submit`**: Sent by each participant to submit their public DKG share for Round 1.
  - `payload`: `{ session: string, id_hex: string, pkg_bincode_hex: string, sig_ecdsa_hex: string }`
- **`Round2Submit`**: Sent by each participant to submit their encrypted shares for Round 2.
  - `payload`: `{ session: string, id_hex: string, pkgs_cipher_hex: [string, string, string, string, string][] }`
- **`FinalizeSubmit`**: Sent by each participant after successfully calculating their long-lived secret share.
  - `payload`: `{ session: string, id_hex: string, group_vk_sec1_hex: string, sig_ecdsa_hex: string }`

### Server to Client (Incoming)

- **`SessionCreated`**: Sent to the creator after they successfully announce a new session.
  - `payload`: `{ session: string }`
- **`Challenge`**: Sent to a client in response to `RequestChallenge`.
  - `payload`: `{ challenge: string }`
- **`LoginOk`**: Sent to a client after a successful login.
  - `payload`: `{ user_id: number, access_token: string }`
- **`PendingDKGSessions`**: Sent to a participant in response to `ListPendingDKGSessions`.
  - `payload`: `{ sessions: { session: string, group_id: string, min_signers: number, max_signers: number, participants: number[], joined: number[] }[] }`
- **`Info`**: A general-purpose message used to provide feedback.
  - `payload`: `{ message: string }` (e.g., `"user 2 joined..."`, `"user 1 disconnected..."`)
- **`Error`**: Sent when an operation fails or a message is invalid.
  - `payload`: `{ message: string }`
- **`ReadyRound1`**: Broadcast to all participants when the session is full.
  - `payload`: `{ session: string, id_hex: string, min_signers: number, max_signers: number, group_id: string, roster: [number, string, string][] }`
- **`Round1All`**: Broadcast to all participants after everyone has submitted their Round 1 package.
  - `payload`: `{ session: string, packages: [string, string, string][] }`
- **`ReadyRound2`**: Broadcast to all participants after `Round1All` to signal the start of the next phase.
  - `payload`: `{ session: string }`
- **`Round2All`**: Sent to each participant with their specific encrypted shares after everyone has submitted for Round 2.
  - `payload`: `{ session: string, packages: [string, string, string, string, string][] }`
- **`Finalized`**: Broadcast to all participants after everyone has successfully submitted their finalization message.
  - `payload`: `{ session: string, group_vk_sec1_hex: string }`
