#!/usr/bin/env node
// Usage: node scripts/make_users.js <outDir> <n>
// Example: node scripts/make_users.js users 3
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const outDir = process.argv[2] || 'users';
const n = parseInt(process.argv[3] || '3', 10);

fs.mkdirSync(outDir, { recursive: true });

for (let i = 1; i <= n; i++) {
    const priv = i.toString(16).padStart(64, '0'); // deterministic 32-byte hex
    const ecdh = crypto.createECDH('secp256k1');
    ecdh.setPrivateKey(Buffer.from(priv, 'hex'));
    const pub = ecdh.getPublicKey(null, 'compressed').toString('hex');

    const user = {
        uid: i,
        ecdsa_priv_hex: priv,
        ecdsa_pub_sec1_hex: pub,
    };
    const file = path.join(outDir, `user${i}.json`);
    fs.writeFileSync(file, JSON.stringify(user, null, 2));
    console.log(`Wrote ${file}`);
}
