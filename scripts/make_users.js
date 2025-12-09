#!/usr/bin/env node
// Usage: node scripts/make_users.js <outDir> <n> [keyType]
// Example: node scripts/make_users.js users 3 secp256k1
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const outDir = process.argv[2] || 'users';
const n = parseInt(process.argv[3] || '3', 10);
const keyType = process.argv[4] || 'secp256k1'; // Default to secp256k1

fs.mkdirSync(outDir, { recursive: true });

let edKeys = [];
if (keyType === 'ed25519') {
    try {
        console.log(`Generating ${n} Ed25519 keys using helper crate...`);
        // Use -q to suppress build output, capture stdout
        const output = execSync(`cargo run -q -p helper --bin gen_ed_keys -- ${n}`, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
        edKeys = output.trim().split('\n').map(line => line.trim().split(' '));
        if (edKeys.length < n) {
            throw new Error(`Expected ${n} keys, got ${edKeys.length}`);
        }
    } catch (e) {
        console.error("Failed to generate Ed25519 keys via Rust:", e.message);
        process.exit(1);
    }
}

for (let i = 1; i <= n; i++) {
    let privHex = i.toString(16).padStart(64, '0'); // default for secp256k1 determinism
    let pubKeyHex;
    let rosterPublicKey;

    if (keyType === 'secp256k1') {
        const privKey = Buffer.from(privHex, 'hex');
        const ecdh = crypto.createECDH('secp256k1');
        ecdh.setPrivateKey(privKey);
        pubKeyHex = ecdh.getPublicKey(null, 'compressed').toString('hex');
        rosterPublicKey = {
            type: 'Secp256k1',
            key: pubKeyHex,
        };
    } else if (keyType === 'ed25519') {
        const [genPriv, genPub] = edKeys[i - 1];
        privHex = genPriv;
        pubKeyHex = genPub;

        rosterPublicKey = {
            type: 'Ed25519',
            key: pubKeyHex,
        };
    } else {
        throw new Error(`Unsupported key type: ${keyType}`);
    }

    const user = {
        uid: i,
        private_key_hex: privHex,
        public_key_hex: pubKeyHex,
        roster_public_key: rosterPublicKey,
        key_type: keyType,
    };
    const file = path.join(outDir, `user${i}.json`);
    fs.writeFileSync(file, JSON.stringify(user, null, 2));
    console.log(`Wrote ${file}`);
}
