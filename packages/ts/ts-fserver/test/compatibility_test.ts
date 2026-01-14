import WebSocket from 'ws';
import { v4 as uuidv4 } from 'uuid';

const URL = 'ws://127.0.0.1:9034';

function wait(ms: number) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function runTest() {
    console.log("Starting Compatibility Test...");

    // 1. Connect
    const ws = new WebSocket(URL);

    await new Promise<void>((resolve) => {
        ws.on('open', () => {
            console.log("Connected to server");
            resolve();
        });
    });

    // Mock user state
    let challenge = "";

    ws.on('message', (data) => {
        const msg = JSON.parse(data.toString());
        console.log("Recv:", msg.type);

        if (msg.type === 'Challenge') {
            challenge = msg.payload.challenge;
            console.log("Got Challenge:", challenge);
            // Login
            // Mock signature
            ws.send(JSON.stringify({
                type: 'Login',
                payload: {
                    challenge: challenge,
                    public_key: { type: 'Secp256k1', key: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef00' }, // Mock 33 byte key
                    signature_hex: "0xmocksignature"
                }
            }));
        }
        else if (msg.type === 'LoginOk') {
            console.log("Login OK!");
            // Start DKG
            ws.send(JSON.stringify({
                type: 'AnnounceDKGSession',
                payload: {
                    min_signers: 2,
                    max_signers: 3,
                    group_id: "test_group",
                    participants: [1, 2, 3],
                    participants_pubs: [
                        [1, { type: 'Secp256k1', key: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef00' }],
                        [2, { type: 'Secp256k1', key: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef02' }],
                        [3, { type: 'Secp256k1', key: '0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef03' }]
                    ]
                }
            }));
        }
        else if (msg.type === 'DKGSessionCreated') {
            console.log("DKG Session Created:", msg.payload.session);
            // Join it
            ws.send(JSON.stringify({
                type: 'JoinDKGSession',
                payload: { session: msg.payload.session }
            }));
        }
        else if (msg.type === 'DKGSessionJoined') {
            // TS server sends 'Info' for join success, not DKGSessionJoined (my implemention).
            // But let's see. 
        }
        else if (msg.type === 'Info') {
            console.log("Info:", msg.payload.message);
        }
    });

    // Initiate
    ws.send(JSON.stringify({ type: 'RequestChallenge', payload: null }));

    // Keep alive for a bit
    await wait(2000);

    console.log("Test Complete (Partial Flow)");
    ws.close();
}

runTest().catch(console.error);
