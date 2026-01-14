import WebSocket from 'ws';
import * as uuid from 'uuid';
const uuidv4 = uuid.v4;
import * as wasm from 'tokamak-frost-wasm';
import * as fs from 'fs';
import * as path from 'path';
import crypto from 'crypto';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

// ESM compatibility
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Polyfill for WASM randomness in Node.js
if (!(global as any).crypto) {
    (global as any).crypto = {
        getRandomValues: (buffer: any) => { return crypto.randomFillSync(buffer); }
    };
}

const URL = 'ws://127.0.0.1:9034';
const LOG_FILE = path.join(__dirname, '../../debug_test.log');

if (fs.existsSync(LOG_FILE)) fs.unlinkSync(LOG_FILE);

const originalLog = console.log;
const originalError = console.error;

function log(msg: any, ...args: any[]) {
    const str = [msg, ...args].map(a => {
        if (a instanceof Error) return a.stack || a.message;
        if (typeof a === 'object') return JSON.stringify(a);
        return String(a);
    }).join(' ');
    fs.appendFileSync(LOG_FILE, str + '\n');
    originalLog(str);
}

console.log = log;
console.error = log;

function wait(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

interface UserConfig {
    uid: number;
    private_key_hex: string;
    public_key_hex: string;
    roster_public_key: { type: string; key: string };
    key_type: string;
}

interface TestClient {
    uid: number;
    ws: WebSocket;
    user: UserConfig;

    // DKG State
    keyPackageHex?: string;
    signerIdHex?: string;
    verifyShareHex?: string;
    groupVkHex?: string;

    // Signing State
    signNonces?: string;
    signMessageHex?: string;
}

function generateUser(uid: number, keyType: string): UserConfig {
    let kpJson: string;
    let rosterType: string;

    if (keyType === 'secp256k1') {
        kpJson = wasm.generate_ecdsa_keypair();
        rosterType = 'Secp256k1';
    } else {
        kpJson = wasm.generate_eddsa_keypair();
        rosterType = 'EdwardsOnBls12381';
    }

    const kp = JSON.parse(kpJson);
    return {
        uid,
        private_key_hex: kp.private_key_hex,
        public_key_hex: kp.public_key_hex,
        roster_public_key: { type: rosterType, key: kp.public_key_hex },
        key_type: keyType
    };
}

async function createClient(uid: number, keyType: string): Promise<TestClient> {
    const user = generateUser(uid, keyType);
    const ws = new WebSocket(URL);
    await new Promise<void>((resolve) => ws.on('open', resolve));
    return { uid, ws, user };
}

async function runTestFlow(keyType: string) {
    console.log(`\n=== Starting Test Flow for ${keyType} ===`);

    const c1 = await createClient(1, keyType);
    const c2 = await createClient(2, keyType);
    const clients = [c1, c2];

    // 1. Login
    for (const c of clients) {
        c.ws.send(JSON.stringify({ type: 'RequestChallenge', payload: null }));
        await new Promise<void>(resolve => {
            const tempHandler = (data: any) => {
                const msg = JSON.parse(data.toString());
                if (msg.type === 'Challenge') {
                    c.ws.removeListener('message', tempHandler);
                    let sig: string;
                    if (keyType === 'secp256k1') {
                        sig = wasm.sign_challenge_ecdsa(c.user.private_key_hex, msg.payload.challenge);
                    } else {
                        sig = wasm.sign_challenge_eddsa(c.user.private_key_hex, msg.payload.challenge);
                    }

                    c.ws.send(JSON.stringify({
                        type: 'Login',
                        payload: {
                            challenge: msg.payload.challenge,
                            public_key: c.user.roster_public_key,
                            signature_hex: sig
                        }
                    }));

                    // Wait for LoginOk
                    c.ws.once('message', (d2) => {
                        const m2 = JSON.parse(d2.toString());
                        if (m2.type === 'LoginOk') resolve();
                        else console.error(`[C${c.uid}] Login Failed:`, m2);
                    });
                }
            };
            c.ws.on('message', tempHandler);
        });
        console.log(`[C${c.uid}] Logged In (${keyType}).`);
    }

    // =========================================================================
    // DKG PHASE
    // =========================================================================

    let dkgSessionId = "";
    let dkgDoneCount = 0;

    const dkgPromise = new Promise<void>((resolve, reject) => {
        clients.forEach(c => {
            c.ws.on('message', (data) => {
                const msg = JSON.parse(data.toString());
                // Filter out non-DKG messages if reusing socket, mostly Info/Sign
                if (msg.type.startsWith('Sign')) return;

                log(`[C${c.uid} DKG] Recv: ${msg.type}`);
                try {
                    switch (msg.type) {
                        case 'DKGSessionCreated':
                            dkgSessionId = msg.payload.session;
                            clients.forEach(ci => {
                                ci.ws.send(JSON.stringify({
                                    type: 'JoinDKGSession',
                                    payload: { session: dkgSessionId }
                                }));
                            });
                            break;

                        case 'ReadyRound1':
                            if (msg.type === 'ReadyRound1') {
                                console.log(`[C${c.uid}] Starting DKG Round 1`);
                                const idHex = c.uid.toString(16).padStart(64, '0');
                                (c as any).myIdHex = idHex;
                                const resJson = wasm.dkg_part1(idHex, 2, 2);
                                const res = JSON.parse(resJson);
                                (c as any).dkgSecretPkg = res.secret_package_hex;

                                // Sign Round1 Payload
                                const authPayloadHex = wasm.get_auth_payload_round1(dkgSessionId, idHex, res.public_package_hex);
                                let sig: string;
                                if (keyType === 'secp256k1') sig = wasm.sign_message_ecdsa(c.user.private_key_hex, authPayloadHex);
                                else sig = wasm.sign_message_eddsa(c.user.private_key_hex, authPayloadHex);

                                c.ws.send(JSON.stringify({
                                    type: 'Round1Submit',
                                    payload: {
                                        session: dkgSessionId,
                                        id_hex: idHex,
                                        pkg_bincode_hex: res.public_package_hex,
                                        signature_hex: sig
                                    }
                                }));
                            }
                            break;

                        case 'Round1All':
                            console.log(`[C${c.uid}] Starting DKG Round 2`);
                            const myId = (c as any).myIdHex;
                            const allPkgs: [string, string, string][] = msg.payload.packages;
                            const otherPkgsObj: any = {};
                            allPkgs.forEach(p => {
                                if (p[0] !== myId) {
                                    otherPkgsObj[p[0]] = p[1];
                                }
                            });
                            (c as any).dkgRound1Pkgs = otherPkgsObj;

                            const res2Json = wasm.dkg_part2((c as any).dkgSecretPkg, otherPkgsObj);
                            const res2 = JSON.parse(res2Json);
                            (c as any).dkgSecretPkg2 = res2.secret_package_hex;

                            // Transform outgoing packages with ECIES encryption (match web UI)
                            const outgoing: [string, any, string][] = [];
                            for (const [recipientId, pkgHex] of Object.entries(res2.outgoing_packages) as [string, string][]) {
                                // Get recipient public key
                                const recipient = clients.find(cl => cl.uid.toString(16).padStart(64, '0') === recipientId);
                                if (!recipient) throw new Error(`Could not find recipient ${recipientId}`);

                                // Apply ECIES encryption on top of FROST package (like web UI does)
                                let eciesResult: string;
                                if (keyType === 'secp256k1') {
                                    eciesResult = wasm.ecies_encrypt_ecdsa(recipient.user.public_key_hex, pkgHex);
                                } else {
                                    eciesResult = wasm.ecies_encrypt_eddsa(recipient.user.public_key_hex, pkgHex);
                                }

                                const { ephemeral_public_key_hex, nonce_hex, ciphertext_hex } = JSON.parse(eciesResult);

                                // Sign the decomposed payload
                                const authPayload2Hex = wasm.get_auth_payload_round2(
                                    dkgSessionId,
                                    myId,
                                    recipientId,
                                    ephemeral_public_key_hex,
                                    nonce_hex,
                                    ciphertext_hex
                                );

                                let sig2: string;
                                if (keyType === 'secp256k1') sig2 = wasm.sign_message_ecdsa(c.user.private_key_hex, authPayload2Hex);
                                else sig2 = wasm.sign_message_eddsa(c.user.private_key_hex, authPayload2Hex);

                                // Create decomposed EncryptedPayload (match web UI format)
                                const rosterType = keyType === 'secp256k1' ? 'Secp256k1' : 'EdwardsOnBls12381';
                                const encryptedPayload = {
                                    ephemeral_public_key: { type: rosterType, key: ephemeral_public_key_hex },
                                    nonce: nonce_hex,
                                    ciphertext: ciphertext_hex
                                };

                                outgoing.push([recipientId, encryptedPayload, sig2]);
                            }

                            c.ws.send(JSON.stringify({
                                type: 'Round2Submit',
                                payload: {
                                    session: dkgSessionId,
                                    id_hex: myId,
                                    pkgs_cipher: outgoing
                                }
                            }));
                            break;

                        case 'Round2All':
                            console.log(`[C${c.uid}] Starting DKG Finalize`);
                            const r2PkgsArr: [string, any, string][] = msg.payload.packages || [];
                            const r2PkgsObj: any = {};

                            // Decrypt ECIES-encrypted packages
                            for (const [fromId, encryptedPayload, _sig] of r2PkgsArr) {
                                // Extract ephemeral key, nonce, ciphertext
                                const eph = encryptedPayload.ephemeral_public_key;
                                const ephHex = typeof eph === 'string' ? eph : eph.key;
                                const nonceHex = encryptedPayload.nonce;
                                const ctHex = encryptedPayload.ciphertext;

                                // Decrypt using ECIES
                                let decryptedHex: string;
                                if (keyType === 'secp256k1') {
                                    decryptedHex = wasm.ecies_decrypt_ecdsa(c.user.private_key_hex, ephHex, nonceHex, ctHex);
                                } else {
                                    decryptedHex = wasm.ecies_decrypt_eddsa(c.user.private_key_hex, ephHex, nonceHex, ctHex);
                                }

                                // Store the decrypted FROST package
                                r2PkgsObj[fromId] = decryptedHex;
                            }

                            const rosterMap = new Map();
                            rosterMap.set(1, c1.user.public_key_hex);
                            rosterMap.set(2, c2.user.public_key_hex);

                            const res3Json = wasm.dkg_part3(
                                (c as any).dkgSecretPkg2,
                                (c as any).dkgRound1Pkgs,
                                r2PkgsObj,
                                "test_group",
                                rosterMap,
                                keyType
                            );
                            const res3 = JSON.parse(res3Json);
                            c.keyPackageHex = res3.key_package_hex;
                            c.groupVkHex = res3.group_public_key_hex;

                            const pre = JSON.parse(wasm.get_signing_prerequisites(c.keyPackageHex!));
                            c.signerIdHex = pre.signer_id_bincode_hex;
                            c.verifyShareHex = pre.verifying_share_bincode_hex;

                            // Sign Finalize Payload
                            const authPayloadFinHex = wasm.get_auth_payload_finalize(dkgSessionId, c.signerIdHex!, c.groupVkHex!);
                            let sigFin: string;
                            if (keyType === 'secp256k1') sigFin = wasm.sign_message_ecdsa(c.user.private_key_hex, authPayloadFinHex);
                            else sigFin = wasm.sign_message_eddsa(c.user.private_key_hex, authPayloadFinHex);

                            c.ws.send(JSON.stringify({
                                type: 'FinalizeSubmit',
                                payload: {
                                    session: dkgSessionId,
                                    id_hex: c.signerIdHex,
                                    group_vk_sec1_hex: res3.group_public_key_hex,
                                    signature_hex: sigFin
                                }
                            }));
                            break;

                        case 'Finalized':
                            console.log(`[C${c.uid}] DKG Finalized.`);
                            dkgDoneCount++;
                            if (dkgDoneCount === 2) resolve();
                            break;
                    }
                } catch (e) {
                    console.error(`DKG Error C${c.uid}:`, e);
                    reject(e);
                }
            });
        });
    });

    console.log("C1 Announcing DKG...");
    c1.ws.send(JSON.stringify({
        type: 'AnnounceDKGSession',
        payload: {
            min_signers: 2,
            max_signers: 2,
            group_id: "test_group",
            participants: [1, 2],
            participants_pubs: [
                [1, c1.user.roster_public_key],
                [2, c2.user.roster_public_key]
            ]
        }
    }));

    await dkgPromise;
    console.log("DKG Complete. Starting SIGNING Phase.");

    // =========================================================================
    // SIGNING PHASE
    // =========================================================================

    let signSessionId = "";
    let signedCount = 0;

    const signPromise = new Promise<void>((resolve, reject) => {
        clients.forEach(c => {
            c.ws.on('message', (data) => {
                const msg = JSON.parse(data.toString());
                // Filter out DKG messages
                if (msg.type.includes('DKG') || msg.type === 'ReadyRound1' || msg.type === 'Round1All' || msg.type === 'Round2All' || msg.type === 'Finalized') return;

                try {
                    switch (msg.type) {
                        case 'SignSessionCreated':
                            signSessionId = msg.payload.session;
                            if (c.uid === 1) {
                                clients.forEach(ci => {
                                    ci.ws.send(JSON.stringify({
                                        type: 'JoinSignSession',
                                        payload: {
                                            session: signSessionId,
                                            signer_id_bincode_hex: ci.signerIdHex,
                                            verifying_share_bincode_hex: ci.verifyShareHex
                                        }
                                    }));
                                });
                            }
                            break;

                        case 'SignReadyRound1':
                            (c as any).signMessageHex = msg.payload.msg_keccak32_hex;

                            const commResJson = wasm.sign_part1_commit(c.keyPackageHex!);
                            const commRes = JSON.parse(commResJson);
                            c.signNonces = commRes.nonces_hex;

                            // Sign SignRound1 Payload
                            const authPayloadCmdHex = wasm.get_auth_payload_sign_r1(msg.payload.session, msg.payload.group_id, c.signerIdHex!, commRes.commitments_hex);
                            let sigCmd: string;
                            if (keyType === 'secp256k1') sigCmd = wasm.sign_message_ecdsa(c.user.private_key_hex, authPayloadCmdHex);
                            else sigCmd = wasm.sign_message_eddsa(c.user.private_key_hex, authPayloadCmdHex);

                            c.ws.send(JSON.stringify({
                                type: 'SignRound1Submit',
                                payload: {
                                    session: msg.payload.session,
                                    id_hex: c.signerIdHex,
                                    commitments_bincode_hex: commRes.commitments_hex,
                                    signature_hex: sigCmd
                                }
                            }));
                            break;

                        case 'SignSigningPackage':
                            const pkg = msg.payload.signing_package_bincode_hex;
                            const sigShareResJson = wasm.sign_part2_sign(c.keyPackageHex!, c.signNonces!, pkg);

                            let sigShareHex = "";
                            try {
                                const json = JSON.parse(sigShareResJson);
                                sigShareHex = json.signature_share_hex || json;
                            } catch (e) {
                                sigShareHex = sigShareResJson;
                            }

                            // Sign SignRound2 Payload
                            // get_auth_payload_sign_r2(session, group, id, sigshare, msg32)
                            const msg32Hex = (c as any).signMessageHex;
                            const authPayloadShare = wasm.get_auth_payload_sign_r2(msg.payload.session, "test_group", c.signerIdHex!, sigShareHex, msg32Hex);

                            let sigShareAuth: string;
                            if (keyType === 'secp256k1') sigShareAuth = wasm.sign_message_ecdsa(c.user.private_key_hex, authPayloadShare);
                            else sigShareAuth = wasm.sign_message_eddsa(c.user.private_key_hex, authPayloadShare);

                            c.ws.send(JSON.stringify({
                                type: 'SignRound2Submit',
                                payload: {
                                    session: msg.payload.session,
                                    id_hex: c.signerIdHex,
                                    signature_share_bincode_hex: sigShareHex,
                                    signature_hex: sigShareAuth
                                }
                            }));
                            break;

                        case 'SignatureReady':
                            console.log(`[C${c.uid}] SIGNATURE OBTAINED.`);
                            signedCount++;
                            if (signedCount === 2) resolve();
                            break;
                    }
                } catch (e) {
                    console.error(`Sign Error C${c.uid} ${msg.type}:`, e);
                    reject(e);
                }
            });
        });
    });

    console.log("C1 Announcing Signing...");
    c1.ws.send(JSON.stringify({
        type: 'AnnounceSignSession',
        payload: {
            group_id: "test_group",
            threshold: 2,
            participants: [1, 2],
            participants_pubs: [
                [1, c1.user.roster_public_key],
                [2, c2.user.roster_public_key]
            ],
            message: "Hello Compatibility",
            message_hex: crypto.createHash('sha256').update("Hello Compatibility").digest('hex'),
            group_vk_sec1_hex: c1.groupVkHex!
        }
    }));

    await signPromise;
    console.log(`Full Flow Complete for ${keyType}!`);
    clients.forEach(c => c.ws.close());
}

async function main() {
    try {
        await runTestFlow('secp256k1');
        await wait(1000);
        await runTestFlow('edwards_on_bls12381');
        console.log("ALL TESTS PASSED.");
        process.exit(0);
    } catch (e) {
        console.error("Test Failed:", e);
        process.exit(1);
    }
}

main();
