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
- **Real-Time Feedback:**
  - A live log view streams all client-side actions and server messages, with a button to clear the view.
  - A status panel with animated indicators shows the current round of the DKG ceremony (Round 1, Round 2, Finalized).
  - A live-updating table shows which participants have successfully joined a session.
- **Dynamic Roster Input:** The creator's UI features a dynamic table for entering participant UIDs and public keys, which automatically adjusts its size based on the "Max Players" input.
- **Graceful Disconnection Handling:** The UI updates in real-time if a participant disconnects from a session, and users are provided with a "Disconnect" button.

## Technology Stack

- **Frontend Framework:** React with TypeScript
- **Build Tool:** Vite
- **Web3 Integration:** `wagmi` for connecting to MetaMask and signing messages.
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

## How to Use the Application

1.  **Choose Key Mode:** Use the wallet switch in the top-right corner to select your key generation method.
2.  **Derive/Generate Keys:**
    - **If MetaMask is connected:** Click the orange **"Derive Roster Key"** button. You will be prompted to sign a message in MetaMask to deterministically generate your keys for the ceremony.
    - **If not using MetaMask:** Click the red **"Generate New Random Keys"** button.
3.  **Create or Join a Session:**
    - **As a Creator:** Select the "Create Session" toggle, fill in the session parameters (Group ID, player count, and the participant roster), and click "Create Session & Connect".
    - **As a Participant:** Select the "Join Session" toggle, connect to the server, and click "Refresh Sessions" to see a list of available DKG ceremonies. Click the "Join" button on the session you wish to enter.
4.  **Run the DKG:** The ceremony will proceed automatically. The UI will provide real-time updates in the log view, participant list, and status indicators.
5.  **View Results:** Upon successful completion, your final secret key share and the group's public key will be displayed in the "Status & Results" panel.
