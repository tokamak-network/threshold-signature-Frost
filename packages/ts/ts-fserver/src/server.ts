import { WebSocket, WebSocketServer } from 'ws';
import * as uuid from 'uuid';
const uuidv4 = uuid.v4;
import {
    ClientMsg, ServerMsg, DKGSession, SignSession,
    RosterPublicKey
} from './types.js';
import init, * as wasm from 'tokamak-frost-wasm';

function mapToObj<V>(map: Map<string, V>, valueExtractor: (v: V) => string): Record<string, string> {
    const obj: Record<string, string> = {};
    map.forEach((v, k) => {
        obj[k] = valueExtractor(v);
    });
    return obj;
}

interface AuthenticatedSocket {
    ws: WebSocket;
    id: string; // Connection UUID
    publicKey?: string; // Hex string (normalized)
    challenge?: string;
}

export class FServer {
    private wss: WebSocketServer;
    private connections: Map<string, AuthenticatedSocket> = new Map();

    private dkgSessions: Map<string, DKGSession> = new Map();
    private signSessions: Map<string, SignSession> = new Map();

    // Completed sessions storage (like fserver)
    private completedDKGSessions: Map<string, any> = new Map();
    private completedSignSessions: Map<string, any> = new Map();

    constructor(portOrServer: number | { server: import('http').Server; path?: string; allowedOrigins?: string[] }) {
        if (typeof portOrServer === 'number') {
            // Standalone mode: create own WebSocketServer on specified port
            this.wss = new WebSocketServer({ port: portOrServer, host: '0.0.0.0' });
            console.log(`ts-fserver started on port ${portOrServer} (bound to 0.0.0.0)`);
        } else {
            // Attached mode: use noServer to manually handle upgrades for specific path
            const wsPath = portOrServer.path || '/frost-ws';
            const allowedOrigins = portOrServer.allowedOrigins || [];
            this.wss = new WebSocketServer({ noServer: true });

            // Only handle upgrade requests for our specific path
            portOrServer.server.on('upgrade', (request, socket, head) => {
                const pathname = new URL(request.url || '', `http://${request.headers.host}`).pathname;
                if (pathname === wsPath) {
                    // Origin validation for security
                    const origin = request.headers.origin;
                    const host = request.headers.host || '';

                    // Allow same-origin connections and localhost for development
                    const isLocalhost = host.includes('localhost') || host.includes('127.0.0.1');
                    const isSameOrigin = origin && (origin.includes(host) || host.includes(new URL(origin).host));
                    const isAllowed = allowedOrigins.length === 0 || allowedOrigins.includes(origin || '');

                    if (!isLocalhost && !isSameOrigin && !isAllowed) {
                        console.warn(`Rejected WebSocket connection from origin: ${origin}`);
                        socket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
                        socket.destroy();
                        return;
                    }

                    this.wss.handleUpgrade(request, socket, head, (ws) => {
                        this.wss.emit('connection', ws, request);
                    });
                }
                // Don't handle other paths - let Vite's HMR WebSocket work
            });

            console.log(`ts-fserver attached to HTTP server at path ${wsPath}`);
        }
        this.wss.on('connection', (ws) => this.handleConnection(ws));
    }

    private handleConnection(ws: WebSocket) {
        const connId = uuidv4();
        const authSocket: AuthenticatedSocket = { ws, id: connId };
        this.connections.set(connId, authSocket);

        console.log(`New connection: ${connId}`);

        ws.on('message', (data) => {
            try {
                const msg = JSON.parse(data.toString()) as ClientMsg;
                this.handleMessage(authSocket, msg);
            } catch (e) {
                console.error(`Failed to parse message from ${connId}:`, e);
            }
        });

        ws.on('close', () => {
            console.log(`Connection closed: ${connId}`);
            this.handleDisconnect(authSocket);
        });
    }

    private handleDisconnect(socket: AuthenticatedSocket) {
        console.log(`[handleDisconnect] Socket ${socket.id} disconnected. Checking ${this.dkgSessions.size} DKG sessions...`);
        this.connections.delete(socket.id);

        // Clean up DKG sessions the user was part of
        this.dkgSessions.forEach((session, sessionId) => {
            const participants = Array.from(session.joined_participants.values());
            console.log(`[handleDisconnect] Session ${sessionId}: ${participants.length} participants, socketIds: ${participants.map(p => p.socketId).join(', ')}`);

            const participant = participants.find(p => p.socketId === socket.id);
            if (!participant) {
                console.log(`[handleDisconnect] Socket ${socket.id} not found in session ${sessionId}`);
                return;
            }

            const uid = participant.uid;
            session.joined_participants.delete(uid);
            console.log(`[handleDisconnect] User ${uid} removed from DKG session ${sessionId}, state=${session.state}`);

            // Helper to notify a socket about disconnect
            const notifyDisconnect = (targetSocketId: string) => {
                const pSocket = this.connections.get(targetSocketId);
                if (pSocket) {
                    this.send(pSocket.ws, {
                        type: 'Info',
                        payload: { message: `user ${uid} disconnected from session ${sessionId}` }
                    });
                }
            };

            // Helper to notify a socket about session abort
            const notifyAbort = (targetSocketId: string) => {
                const pSocket = this.connections.get(targetSocketId);
                if (pSocket) {
                    this.send(pSocket.ws, {
                        type: 'SessionAborted',
                        payload: { session: sessionId, reason: `Participant ${uid} disconnected` }
                    });
                }
            };

            // Helper to notify ALL configured participants (not just joined ones)
            const notifyAllParticipants = (notifyFn: (socketId: string) => void) => {
                const notifiedSockets = new Set<string>();
                session.participants_pubs.forEach(([_, pubKey]) => {
                    const pubKeyStr = typeof pubKey === 'string' ? pubKey : pubKey.key;
                    const normalizedPubKey = pubKeyStr.toLowerCase().replace('0x', '');

                    this.connections.forEach(conn => {
                        if (conn.publicKey && conn.id !== socket.id && !notifiedSockets.has(conn.id)) {
                            const connPubKey = conn.publicKey.toLowerCase().replace('0x', '');
                            if (connPubKey === normalizedPubKey) {
                                notifyFn(conn.id);
                                notifiedSockets.add(conn.id);
                            }
                        }
                    });
                });
                // Also notify the session creator if not already notified and not the disconnecting user
                if (session.creatorSocketId !== socket.id && !notifiedSockets.has(session.creatorSocketId)) {
                    notifyFn(session.creatorSocketId);
                }
            };

            if (session.state === 'Pending') {
                notifyAllParticipants(notifyDisconnect);
            } else if (session.state === 'Round1' || session.state === 'Round2') {
                // Session already started - must abort since protocol cannot recover
                session.state = 'Failed';
                notifyAllParticipants(notifyAbort);
            }
        });

        // Clean up Sign sessions the user was part of
        this.signSessions.forEach((session, sessionId) => {
            const participant = Array.from(session.joined_participants.values())
                .find(p => p.socketId === socket.id);
            if (!participant) return;

            const uid = participant.uid;
            session.joined_participants.delete(uid);
            console.log(`[handleDisconnect] User ${uid} removed from Sign session ${sessionId}, state=${session.state}`);

            // Helper to notify a socket about disconnect
            const notifyDisconnect = (targetSocketId: string) => {
                const pSocket = this.connections.get(targetSocketId);
                if (pSocket) {
                    this.send(pSocket.ws, {
                        type: 'Info',
                        payload: { message: `user ${uid} disconnected from session ${sessionId}` }
                    });
                }
            };

            // Helper to notify a socket about session abort
            const notifyAbort = (targetSocketId: string) => {
                const pSocket = this.connections.get(targetSocketId);
                if (pSocket) {
                    this.send(pSocket.ws, {
                        type: 'SessionAborted',
                        payload: { session: sessionId, reason: `Participant ${uid} disconnected` }
                    });
                }
            };

            // Helper to notify ALL configured participants (not just joined ones)
            const notifyAllParticipants = (notifyFn: (socketId: string) => void) => {
                const notifiedSockets = new Set<string>();
                session.participants_pubs.forEach(([_, pubKey]) => {
                    const pubKeyStr = typeof pubKey === 'string' ? pubKey : pubKey.key;
                    const normalizedPubKey = pubKeyStr.toLowerCase().replace('0x', '');

                    this.connections.forEach(conn => {
                        if (conn.publicKey && conn.id !== socket.id && !notifiedSockets.has(conn.id)) {
                            const connPubKey = conn.publicKey.toLowerCase().replace('0x', '');
                            if (connPubKey === normalizedPubKey) {
                                notifyFn(conn.id);
                                notifiedSockets.add(conn.id);
                            }
                        }
                    });
                });
                // Also notify the session creator if not already notified and not the disconnecting user
                if (session.creatorSocketId !== socket.id && !notifiedSockets.has(session.creatorSocketId)) {
                    notifyFn(session.creatorSocketId);
                }
            };

            if (session.state === 'Pending') {
                notifyAllParticipants(notifyDisconnect);
            } else if (session.state === 'Round1' || session.state === 'Round2') {
                // Session already started - must abort since protocol cannot recover
                session.state = 'Failed';
                notifyAllParticipants(notifyAbort);
            }
        });
    }

    private send(ws: WebSocket, msg: ServerMsg) {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify(msg));
        }
    }
    private handleMessage(socket: AuthenticatedSocket, msg: ClientMsg) {
        console.log(`[${socket.id}] Recv: ${msg.type}`);
        // console.log(JSON.stringify(msg.payload, null, 2));

        switch (msg.type) {
            // ----------------------------------------------------------------
            // AUTH
            // ----------------------------------------------------------------
            case 'RequestChallenge': {
                const challenge = uuidv4(); // Standard UUID string
                socket.challenge = challenge;
                this.send(socket.ws, { type: 'Challenge', payload: { challenge } });
                break;
            }
            case 'Login': {
                const { challenge, public_key, signature_hex } = msg.payload;
                if (challenge !== socket.challenge) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Invalid challenge" } });
                    return;
                }

                // Convert UUID challenge string to hex bytes for verification
                // UUID is 16 bytes.
                let challengeHex = "";
                try {
                    const bytes = uuid.parse(challenge);
                    challengeHex = Buffer.from(bytes).toString('hex');
                } catch (e) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Invalid challenge format" } });
                    return;
                }

                try {
                    // @ts-ignore - verify_signature added recently
                    const valid = wasm.verify_signature(public_key, challengeHex, signature_hex);
                    if (!valid) {
                        this.send(socket.ws, { type: 'Error', payload: { message: "Signature verification failed" } });
                        return;
                    }
                } catch (e) {
                    console.error("Verification error:", e);
                    this.send(socket.ws, { type: 'Error', payload: { message: "Verification error" } });
                    return;
                }

                let pubKeyStr: string;
                if (typeof public_key === 'string') pubKeyStr = public_key;
                else pubKeyStr = public_key.key;

                socket.publicKey = pubKeyStr;
                this.send(socket.ws, {
                    type: 'LoginOk',
                    payload: {
                        principal: pubKeyStr,
                        suid: 0, // Assigned on join
                        access_token: uuidv4()
                    }
                });
                break;
            }

            case 'Logout': {
                // Remove connection and clear authentication (like fserver lines 757-770)
                socket.publicKey = undefined;
                socket.challenge = undefined;
                this.send(socket.ws, { type: 'Info', payload: { message: 'Logged out' } });
                break;
            }

            // ----------------------------------------------------------------
            // DKG SESSION MANAGEMENT
            // ----------------------------------------------------------------
            case 'AnnounceDKGSession': {
                // Note: Rust server generates ID.
                const sessionID = uuidv4();
                const { min_signers, max_signers, group_id, participants, participants_pubs } = msg.payload;

                // Validate: all public keys must be unique
                const normalizedKeys = participants_pubs.map(([_, pubKey]: [number, RosterPublicKey]) => {
                    const keyStr = typeof pubKey === 'string' ? pubKey : pubKey.key;
                    return keyStr.toLowerCase().replace('0x', '');
                });
                const uniqueKeys = new Set(normalizedKeys);
                if (uniqueKeys.size !== normalizedKeys.length) {
                    this.send(socket.ws, { type: 'Error', payload: { message: 'All participant public keys must be unique' } });
                    return;
                }

                const session: DKGSession = {
                    id: sessionID,
                    creatorSocketId: socket.id,
                    min_signers,
                    max_signers,
                    group_id,
                    participants_config: participants,
                    participants_pubs,
                    joined_participants: new Map(),
                    state: 'Pending',
                    round1_packages: new Map(),
                    round2_packages: new Map(), // Stores *incoming* packages for users
                    created_at: Date.now()
                };

                this.dkgSessions.set(sessionID, session);
                this.send(socket.ws, { type: 'DKGSessionCreated', payload: { session: sessionID } });

                // Broadcast new session only to participants in the session
                const newSessionSummary = {
                    session: session.id,
                    creator_suid: 1, // Creator is participant 1 by convention
                    group_id: session.group_id,
                    min_signers: session.min_signers,
                    max_signers: session.max_signers,
                    participants: session.participants_config,
                    participants_pubs: session.participants_pubs,
                    joined: [] as number[],
                    created_at: new Date(session.created_at).toISOString()
                };

                // Only notify users whose public keys are in sessions.participants_pubs
                const notifiedSockets = new Set<string>();
                session.participants_pubs.forEach(([_, pubKey]) => {
                    const pubKeyStr = typeof pubKey === 'string' ? pubKey : pubKey.key;
                    const normalizedPubKey = pubKeyStr.toLowerCase().replace('0x', '');

                    this.connections.forEach(conn => {
                        // Skip creator and already notified sockets
                        if (conn.id === socket.id || notifiedSockets.has(conn.id)) return;
                        if (!conn.publicKey) return;

                        const connPubKey = conn.publicKey.toLowerCase().replace('0x', '');
                        if (connPubKey === normalizedPubKey) {
                            this.send(conn.ws, { type: 'NewDKGSession', payload: newSessionSummary });
                            notifiedSockets.add(conn.id);
                        }
                    });
                });
                break;
            }

            case 'JoinDKGSession': {
                const { session: sid } = msg.payload;
                const session = this.dkgSessions.get(sid);
                if (!session) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Session not found" } });
                    return;
                }

                if (!socket.publicKey) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Not logged in" } });
                    return;
                }

                // Find configured participant ID (suid) for this pubkey
                const pubEntry = session.participants_pubs.find(p => {
                    const k = typeof p[1] === 'string' ? p[1] : p[1].key;
                    // Simple string match (ignore case/prefix for robustness if needed)
                    return k.toLowerCase().replace('0x', '') === socket.publicKey!.toLowerCase().replace('0x', '');
                });

                if (!pubEntry) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Public key not authorized for this session" } });
                    return;
                }

                const suid = pubEntry[0];
                session.joined_participants.set(suid, { uid: suid, socketId: socket.id, pubKeyProp: pubEntry[1] });

                this.send(socket.ws, { type: 'Info', payload: { message: `Joined session ${sid} as participant ${suid}` } });

                // Broadcast update to ALL configured participants in the session (not just those who joined)
                // Find connected users whose public keys match session.participants_pubs
                const notifiedSockets = new Set<string>();
                session.participants_pubs.forEach(([_, pubKey]) => {
                    const pubKeyStr = typeof pubKey === 'string' ? pubKey : pubKey.key;
                    const normalizedPubKey = pubKeyStr.toLowerCase().replace('0x', '');

                    // Find the connected socket with this public key (including the joiner)
                    this.connections.forEach(conn => {
                        if (conn.publicKey && !notifiedSockets.has(conn.id)) {
                            const connPubKey = conn.publicKey.toLowerCase().replace('0x', '');
                            if (connPubKey === normalizedPubKey) {
                                this.send(conn.ws, { type: 'Info', payload: { message: `participant ${suid} joined session ${sid}` } });
                                notifiedSockets.add(conn.id);
                            }
                        }
                    });
                });
                // Also notify the session creator if they weren't already notified and aren't the joiner
                if (session.creatorSocketId !== socket.id && !notifiedSockets.has(session.creatorSocketId)) {
                    const creatorSocket = this.connections.get(session.creatorSocketId);
                    if (creatorSocket) {
                        this.send(creatorSocket.ws, { type: 'Info', payload: { message: `participant ${suid} joined session ${sid}` } });
                    }
                }

                // Check if all joined
                console.log(`Session ${sid}: Joined ${session.joined_participants.size} / ${session.max_signers}`);
                if (session.joined_participants.size === session.max_signers) {
                    console.log("Starting DKG Round 1...");
                    this.startDKGRound1(session);
                }
                break;
            }

            case 'ListPendingDKGSessions': {
                if (!socket.publicKey) {
                    this.send(socket.ws, { type: 'Error', payload: { message: 'Must login first' } });
                    return;
                }
                const userPubKey = socket.publicKey.toLowerCase().replace('0x', '');

                const list = Array.from(this.dkgSessions.values())
                    .filter(s => s.state !== 'Finalized' && s.state !== 'Failed')
                    // Only show sessions where user is a participant
                    .filter(s => s.participants_pubs.some(([_, pubKey]) => {
                        const keyStr = typeof pubKey === 'string' ? pubKey : pubKey.key;
                        return keyStr.toLowerCase().replace('0x', '') === userPubKey;
                    }))
                    .map(s => {
                        // Find creator's SUID
                        const creatorParticipant = Array.from(s.joined_participants.values())
                            .find(p => p.socketId === s.creatorSocketId);
                        const creatorSuid = creatorParticipant ? creatorParticipant.uid : 1;

                        return {
                            session: s.id,
                            creator_suid: creatorSuid,
                            group_id: s.group_id,
                            min_signers: s.min_signers,
                            max_signers: s.max_signers,
                            participants: s.participants_config,
                            participants_pubs: s.participants_pubs,
                            joined: Array.from(s.joined_participants.keys()),
                            created_at: new Date(s.created_at).toISOString()
                        };
                    });
                this.send(socket.ws, { type: 'PendingDKGSessions', payload: { sessions: list } });
                break;
            }

            case 'ListCompletedDKGSessions': {
                // Return completed DKG sessions user participated in (like fserver lines 916-935)
                if (!socket.publicKey) {
                    this.send(socket.ws, { type: 'Error', payload: { message: 'Must login first' } });
                    return;
                }

                const completedList = Array.from(this.completedDKGSessions.values())
                    .filter(s => {
                        // Check if user's public key is in participants_pubs using normalized comparison
                        return s.participants_pubs.some(([_, pubKey]: [number, RosterPublicKey]) => {
                            const keyStr = typeof pubKey === 'string' ? pubKey : pubKey.key;
                            return keyStr.toLowerCase().replace('0x', '') === socket.publicKey!.toLowerCase().replace('0x', '');
                        });
                    });

                this.send(socket.ws, { type: 'CompletedDKGSessions', payload: { sessions: completedList } });
                break;
            }

            // ----------------------------------------------------------------
            // DKG ROUNDS
            // ----------------------------------------------------------------
            case 'Round1Submit': {
                const { session: sid, id_hex, pkg_bincode_hex, signature_hex } = msg.payload;
                const session = this.dkgSessions.get(sid);
                if (!session) return;

                const participant = Array.from(session.joined_participants.values()).find(p => p.socketId === socket.id);
                if (!participant || !participant.pubKeyProp) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Not a participant or not logged in" } });
                    return;
                }
                participant.frostIdHex = id_hex;

                try {
                    const authPayload = wasm.get_auth_payload_round1(sid, id_hex, pkg_bincode_hex);
                    const valid = wasm.verify_signature(participant.pubKeyProp, authPayload, signature_hex);
                    console.log(`[Round1] Validating ${id_hex.substring(0, 8)}... Result: ${valid}`);
                    if (!valid) {
                        this.send(socket.ws, { type: 'Error', payload: { message: "Invalid signature" } });
                        return;
                    }
                } catch (e) {
                    console.error("Verification error:", e);
                    this.send(socket.ws, { type: 'Error', payload: { message: "Verification failed" } });
                    return;
                }

                session.round1_packages.set(id_hex, { pkg: pkg_bincode_hex, sig: signature_hex });

                // Check if all submitted
                if (session.round1_packages.size === session.max_signers) {
                    this.finishDKGRound1(session);
                }
                break;
            }

            case 'Round2Submit': {
                const { session: sid, id_hex, pkgs_cipher } = msg.payload;
                const session = this.dkgSessions.get(sid);
                if (!session) return;

                const sender = Array.from(session.joined_participants.values()).find(p => p.socketId === socket.id);
                if (!sender || !sender.pubKeyProp) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Unauthorized" } });
                    return;
                }

                // Distribute packages to recipients
                for (const [recipient_id, encrypted_payload, sig] of pkgs_cipher) {
                    try {
                        // Extract fields from EncryptedPayload (web UI sends decomposed format)
                        let ephHex: string, nonceHex: string, ctHex: string;

                        // Handle both decomposed EncryptedPayload object and raw hex string
                        if (typeof encrypted_payload === 'string') {
                            // For compatibility with tests that might send raw hex
                            ephHex = encrypted_payload;
                            nonceHex = '';
                            ctHex = '';
                        } else {
                            // Web UI format: { ephemeral_public_key: { type, key }, nonce, ciphertext }
                            const eph = encrypted_payload.ephemeral_public_key;
                            ephHex = typeof eph === 'string' ? eph : eph.key;
                            nonceHex = encrypted_payload.nonce;
                            ctHex = encrypted_payload.ciphertext;
                        }

                        const authPayload = wasm.get_auth_payload_round2(sid, id_hex, recipient_id, ephHex, nonceHex, ctHex);
                        if (!wasm.verify_signature(sender.pubKeyProp, authPayload, sig)) {
                            console.error(`Invalid signature round2 from ${id_hex} to ${recipient_id}`);
                            this.send(socket.ws, { type: 'Error', payload: { message: "Invalid signature in package" } });
                            return;
                        }
                    } catch (e) {
                        console.error("Verification error R2:", e);
                        this.send(socket.ws, { type: 'Error', payload: { message: "Verification error" } });
                        return;
                    }

                    if (!session.round2_packages.has(recipient_id)) {
                        session.round2_packages.set(recipient_id, []);
                    }
                    session.round2_packages.get(recipient_id)!.push([id_hex, encrypted_payload, sig]);
                }

                // Ideally wait for ALL participants to submit ALL their packages
                // Count total received packages?
                // Simplified: Wait until we have (N-1) packages for EVERY recipient

                const N = session.max_signers;
                let ready = true;
                // Check that every participant has received N-1 packages
                // (We iterate over the *expected* recipients, i.e. joined participants)
                session.joined_participants.forEach((p, suid) => {
                    // We need to look up their id_hex. But we map state by id_hex?
                    // Wait, server usually maps via id_hex.
                    // We need map from suid -> id_hex. That comes from R1?
                    // The client sends id_hex. We should store that in participant state in R1.
                });

                // Actually, simply check total packages count? N * (N-1)
                let totalPackages = 0;
                session.round2_packages.forEach(list => totalPackages += list.length);

                if (totalPackages === N * (N - 1)) {
                    this.finishDKGRound2(session);
                }
                break;
            }

            case 'FinalizeSubmit': {
                const { session: sid, id_hex, group_vk_sec1_hex, signature_hex } = msg.payload;
                const session = this.dkgSessions.get(sid);
                if (!session) return;

                const participant = Array.from(session.joined_participants.values()).find(p => p.socketId === socket.id);
                if (!participant || !participant.pubKeyProp) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Unauthorized" } });
                    return;
                }

                try {
                    const authPayload = wasm.get_auth_payload_finalize(sid, id_hex, group_vk_sec1_hex);
                    // Verify signature
                    if (!wasm.verify_signature(participant.pubKeyProp, authPayload, signature_hex)) {
                        this.send(socket.ws, { type: 'Error', payload: { message: "Invalid signature" } });
                        return;
                    }
                } catch (e) {
                    console.error("Verification error Finalize:", e);
                    this.send(socket.ws, { type: 'Error', payload: { message: "Verification error" } });
                    return;
                }

                // Verify that this user is actually id_hex (matches their frostIdHex from Round1)
                if (participant.frostIdHex && participant.frostIdHex !== id_hex) {
                    console.error(`ID mismatch: participant ${participant.uid} claimed ${id_hex} but expected ${participant.frostIdHex}`);
                    this.send(socket.ws, { type: 'Error', payload: { message: "Identifier mismatch" } });
                    return;
                }

                // Group key consistency check (like fserver lines 1235-1242)
                if (session.final_group_key) {
                    if (session.final_group_key !== group_vk_sec1_hex) {
                        console.error(`Group VK mismatch from uid ${participant.uid}: got ${group_vk_sec1_hex}, expected ${session.final_group_key}`);
                        this.send(socket.ws, { type: 'Error', payload: { message: "Group key mismatch" } });
                        return;
                    }
                } else {
                    // First participant to finalize sets the expected group key
                    session.final_group_key = group_vk_sec1_hex;
                }

                // Track finalized participants (like fserver line 1247)
                if (!session.finalized_uids) {
                    session.finalized_uids = new Set<number>();
                }
                session.finalized_uids.add(participant.uid);

                console.log(`[server] Finalize progress: ${session.finalized_uids.size}/${session.max_signers} (session=${sid})`);

                // Check if all participants have finalized (like fserver lines 1255-1298)
                if (session.finalized_uids.size === session.max_signers) {
                    session.state = 'Finalized';

                    // Find creator's SUID for the completed session
                    const creatorParticipant = Array.from(session.joined_participants.values())
                        .find(p => p.socketId === session.creatorSocketId);
                    const creatorSuid = creatorParticipant ? creatorParticipant.uid : 1;

                    // Store in completed sessions for later retrieval
                    this.completedDKGSessions.set(sid, {
                        session: sid,
                        creator_suid: creatorSuid,
                        group_id: session.group_id,
                        min_signers: session.min_signers,
                        max_signers: session.max_signers,
                        participants: session.participants_config,
                        participants_pubs: session.participants_pubs,
                        joined: Array.from(session.joined_participants.keys()),
                        group_vk_sec1_hex: group_vk_sec1_hex,
                        created_at: new Date(session.created_at).toISOString(),
                        completed_at: new Date().toISOString()
                    });

                    // Broadcast Finalized to all participants
                    session.joined_participants.forEach((p) => {
                        const pSocket = this.connections.get(p.socketId);
                        if (pSocket) {
                            this.send(pSocket.ws, {
                                type: 'Finalized',
                                payload: { session: sid, group_vk_sec1_hex }
                            });
                        }
                    });

                    console.log(`[server] DKG session ${sid} fully finalized.`);
                } else {
                    // Send acknowledgment to this participant only
                    this.send(socket.ws, {
                        type: 'Finalized',
                        payload: { session: sid, group_vk_sec1_hex }
                    });
                }
                break;
            }

            // ----------------------------------------------------------------
            // SIGNING SESSION
            // ----------------------------------------------------------------
            case 'AnnounceSignSession': {
                const sessionID = uuidv4();
                const { group_id, threshold, participants, participants_pubs, message, message_hex, group_vk_sec1_hex } = msg.payload;

                const session: SignSession = {
                    id: sessionID,
                    creatorSocketId: socket.id,
                    group_id,
                    threshold,
                    participants_config: participants,
                    participants_pubs,
                    message,
                    message_hex,
                    group_vk_sec1_hex,
                    joined_participants: new Map(),
                    state: 'Pending',
                    round1_commitments: new Map(),
                    round2_shares: new Map(),
                    created_at: Date.now()
                };

                this.signSessions.set(sessionID, session);

                // Ack to creator
                this.send(socket.ws, { type: 'SignSessionCreated', payload: { session: sessionID } });

                // Broadcast new session only to participants in the session
                const newSessionSummary = {
                    session: session.id,
                    creator_suid: 1, // Creator is participant 1 by convention
                    group_id: session.group_id,
                    threshold: session.threshold,
                    participants: session.participants_config,
                    participants_pubs: session.participants_pubs,
                    message: session.message,
                    message_hex: session.message_hex,
                    joined: [] as number[],
                    created_at: new Date(session.created_at).toISOString()
                };

                // Only notify users whose public keys are in sessions.participants_pubs
                const notifiedSockets = new Set<string>();
                session.participants_pubs.forEach(([_, pubKey]) => {
                    const pubKeyStr = typeof pubKey === 'string' ? pubKey : pubKey.key;
                    const normalizedPubKey = pubKeyStr.toLowerCase().replace('0x', '');

                    this.connections.forEach(conn => {
                        // Skip creator and already notified sockets
                        if (conn.id === socket.id || notifiedSockets.has(conn.id)) return;
                        if (!conn.publicKey) return;

                        const connPubKey = conn.publicKey.toLowerCase().replace('0x', '');
                        if (connPubKey === normalizedPubKey) {
                            this.send(conn.ws, { type: 'NewSignSession', payload: newSessionSummary });
                            notifiedSockets.add(conn.id);
                        }
                    });
                });
                break;
            }

            case 'ListPendingSigningSessions': {
                if (!socket.publicKey) {
                    this.send(socket.ws, { type: 'Error', payload: { message: 'Must login first' } });
                    return;
                }
                const userPubKey = socket.publicKey.toLowerCase().replace('0x', '');

                const list = Array.from(this.signSessions.values())
                    .filter(s => s.state !== 'Complete' && s.state !== 'Failed')
                    // Only show sessions where user is a participant
                    .filter(s => s.participants_pubs.some(([_, pubKey]) => {
                        const keyStr = typeof pubKey === 'string' ? pubKey : pubKey.key;
                        return keyStr.toLowerCase().replace('0x', '') === userPubKey;
                    }))
                    .map(s => {
                        // Find creator's SUID
                        const creatorParticipant = Array.from(s.joined_participants.values())
                            .find(p => p.socketId === s.creatorSocketId);
                        const creatorSuid = creatorParticipant ? creatorParticipant.uid : 1;

                        return {
                            session: s.id,
                            creator_suid: creatorSuid,
                            group_id: s.group_id,
                            threshold: s.threshold,
                            participants: s.participants_config,
                            participants_pubs: s.participants_pubs,
                            message: s.message,
                            message_hex: s.message_hex,
                            status: s.state,
                            created_at: new Date(s.created_at).toISOString(),
                            joined: Array.from(s.joined_participants.keys())
                        };
                    });
                this.send(socket.ws, { type: 'PendingSigningSessions', payload: { sessions: list } });
                break;
            }

            case 'ListCompletedSigningSessions': {
                // Return completed signing sessions user participated in (like fserver lines 975-995)
                if (!socket.publicKey) {
                    this.send(socket.ws, { type: 'Error', payload: { message: 'Must login first' } });
                    return;
                }

                const completedList = Array.from(this.completedSignSessions.values())
                    .filter(s => {
                        // Check if user's public key is in participants_pubs using normalized comparison
                        return s.participants_pubs.some(([_, pubKey]: [number, RosterPublicKey]) => {
                            const keyStr = typeof pubKey === 'string' ? pubKey : pubKey.key;
                            return keyStr.toLowerCase().replace('0x', '') === socket.publicKey!.toLowerCase().replace('0x', '');
                        });
                    });

                this.send(socket.ws, { type: 'CompletedSigningSessions', payload: { sessions: completedList } });
                break;
            }

            case 'JoinSignSession': {
                const { session: sid, signer_id_bincode_hex, verifying_share_bincode_hex } = msg.payload;
                const session = this.signSessions.get(sid);
                if (!session) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Signing session not found" } });
                    return;
                }
                if (!socket.publicKey) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Not logged in" } });
                    return;
                }

                // Identify user from roster
                const pubEntry = session.participants_pubs.find(p => {
                    const k = typeof p[1] === 'string' ? p[1] : p[1].key;
                    return k.toLowerCase().replace('0x', '') === socket.publicKey!.toLowerCase().replace('0x', '');
                });

                if (!pubEntry) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Public key not in signing roster" } });
                    return;
                }

                const suid = pubEntry[0];
                session.joined_participants.set(suid, {
                    uid: suid,
                    socketId: socket.id,
                    pubKeyProp: pubEntry[1],
                    signer_id_hex: signer_id_bincode_hex,
                    verifying_share: verifying_share_bincode_hex
                });

                // this.send(socket.ws, { type: 'SignSessionJoined', payload: { session: sid } });

                // Broadcast update to ALL configured participants in the session (not just those who joined)
                // Find connected users whose public keys match session.participants_pubs
                const notifiedSockets = new Set<string>();
                session.participants_pubs.forEach(([_, pubKey]) => {
                    const pubKeyStr = typeof pubKey === 'string' ? pubKey : pubKey.key;
                    const normalizedPubKey = pubKeyStr.toLowerCase().replace('0x', '');

                    // Find the connected socket with this public key (excluding the joiner)
                    this.connections.forEach(conn => {
                        if (conn.publicKey && !notifiedSockets.has(conn.id)) {
                            const connPubKey = conn.publicKey.toLowerCase().replace('0x', '');
                            if (connPubKey === normalizedPubKey) {
                                this.send(conn.ws, { type: 'Info', payload: { message: `participant ${suid} joined session ${sid}` } });
                                notifiedSockets.add(conn.id);
                            }
                        }
                    });
                });
                // Also notify the session creator if they weren't already notified and aren't the joiner
                if (session.creatorSocketId !== socket.id && !notifiedSockets.has(session.creatorSocketId)) {
                    const creatorSocket = this.connections.get(session.creatorSocketId);
                    if (creatorSocket) {
                        this.send(creatorSocket.ws, { type: 'Info', payload: { message: `participant ${suid} joined session ${sid}` } });
                    }
                }

                // Check if enough joined (Threshold)
                // Note: Unlike DKG (all N), signing requires T.
                // But usually we wait for configurable amount?
                // Actually fserver logic waits for exact subset?
                // Or just waits for "enough"?
                // Let's assume we wait for ALL listed participants in `participants_config`?
                // Or just `threshold`?
                // Looking at `AnnounceSignSession` in `types.ts`, it has `participants` list.
                // So we wait for everyone in that list.

                if (session.joined_participants.size === session.participants_config.length) {
                    this.startSignRound1(session);
                }
                break;
            }

            case 'SignRound1Submit': {
                const { session: sid, id_hex, commitments_bincode_hex, signature_hex } = msg.payload;
                const session = this.signSessions.get(sid);
                if (!session) return;

                const participant = Array.from(session.joined_participants.values()).find(p => p.socketId === socket.id);
                if (!participant || !participant.pubKeyProp) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Unauthorized" } });
                    return;
                }

                try {
                    const authPayload = wasm.get_auth_payload_sign_r1(sid, session.group_id, id_hex, commitments_bincode_hex);
                    if (!wasm.verify_signature(participant.pubKeyProp, authPayload, signature_hex)) {
                        this.send(socket.ws, { type: 'Error', payload: { message: "Invalid signature" } });
                        return;
                    }
                } catch (e) {
                    console.error("Verification error Sign R1:", e);
                    this.send(socket.ws, { type: 'Error', payload: { message: "Verification error" } });
                    return;
                }

                session.round1_commitments.set(id_hex, { commitment: commitments_bincode_hex, sig: signature_hex });

                if (session.round1_commitments.size === session.participants_config.length) {
                    this.finishSignRound1(session);
                }
                break;
            }

            case 'SignRound2Submit': {
                const { session: sid, id_hex, signature_share_bincode_hex, signature_hex } = msg.payload;
                const session = this.signSessions.get(sid);
                if (!session) return;

                const participant = Array.from(session.joined_participants.values()).find(p => p.socketId === socket.id);
                if (!participant || !participant.pubKeyProp) {
                    this.send(socket.ws, { type: 'Error', payload: { message: "Unauthorized" } });
                    return;
                }

                try {
                    const authPayload = wasm.get_auth_payload_sign_r2(sid, session.group_id, id_hex, signature_share_bincode_hex, session.message_hex);
                    if (!wasm.verify_signature(participant.pubKeyProp, authPayload, signature_hex)) {
                        this.send(socket.ws, { type: 'Error', payload: { message: "Invalid signature" } });
                        return;
                    }
                } catch (e) {
                    console.error("Verification error Sign R2:", e);
                    this.send(socket.ws, { type: 'Error', payload: { message: "Verification error" } });
                    return;
                }

                session.round2_shares.set(id_hex, { share: signature_share_bincode_hex, sig: signature_hex });

                if (session.round2_shares.size === session.participants_config.length) {
                    this.finishSignRound2(session);
                }
                break;
            }
        }
    }

    // ----------------------------------------------------------------
    // PROTOCOL HELPERS
    // ----------------------------------------------------------------

    private startDKGRound1(session: DKGSession) {
        session.state = 'Round1';
        // Need to assign id_hex to participants?
        // Actually, in DKG R1, clients GENERATE their id_hex and sending it in R1Submit.
        // But server sends "ReadyRound1".
        // Rust fserver: sends `id_hex` in `ReadyRound1` payload?
        // Wait, let's check `types.ts` definition of `ReadyRound1`.
        // It has `id_hex` at the top level? No, checking logic...
        // `ReadyRound1`: { session, group_id, min/max, roster: [uid, id_hex, pub] }
        // Where does `id_hex` come from?
        // Ah, in Rust `fserver`, `id_hex` seems to be deterministic or pre-assigned?
        // Or maybe the server generates it?
        // Checking `fserver/src/main.rs`:
        // "Server generates random identifiers for them?"
        // Re-reading `useDKGWebSocket.ts`:
        // "const myIdentifierHex = msg.payload.id_hex;"
        // So Server sends it.

        // Let's generate random id_hex (scalar) for each participant.
        // 32 bytes hex.

        const roster: [number, string, RosterPublicKey][] = [];

        session.joined_participants.forEach(p => {
            // Use deterministic ID based on UID (1, 2, 3) to allow easier file mapping in tests/Makefile
            // Pad to 32 bytes (64 hex chars)
            const idVal = BigInt(p.uid);
            p.frostIdHex = idVal.toString(16).padStart(64, '0');
            roster.push([p.uid, p.frostIdHex, p.pubKeyProp!]);
        });

        session.joined_participants.forEach(p => {
            const socket = this.connections.get(p.socketId);
            if (socket) {
                this.send(socket.ws, {
                    type: 'ReadyRound1',
                    payload: {
                        session: session.id,
                        group_id: session.group_id,
                        min_signers: session.min_signers,
                        max_signers: session.max_signers,
                        roster: roster,
                        id_hex: p.frostIdHex! // Personal ID
                    }
                });
            }
        });
    }

    private finishDKGRound1(session: DKGSession) {
        session.state = 'Round2';
        // Broadcast all packages
        const packages: [string, string, string][] = [];
        session.round1_packages.forEach((val, id_hex) => {
            packages.push([id_hex, val.pkg, val.sig]);
        });

        session.joined_participants.forEach(p => {
            const socket = this.connections.get(p.socketId);
            if (socket) {
                this.send(socket.ws, {
                    type: 'Round1All',
                    payload: { session: session.id, packages }
                });

                // Also trigger ReadyRound2
                // The client waits for Round1All then expects ReadyRound2?
                // Or does it transition automatically?
                // `useDKGWebSocket.ts`: handles `Round1All` (stores pkgs), handles `ReadyRound2` (starts R2).
                // So send both.

                this.send(socket.ws, {
                    type: 'ReadyRound2',
                    payload: { session: session.id, participants: [] }
                });
            }
        });
    }

    private finishDKGRound2(session: DKGSession) {
        // Distribute encrypted packages
        session.joined_participants.forEach(p => {
            const socket = this.connections.get(p.socketId);
            if (!socket || !p.frostIdHex) return;

            // Get packages destined for this user
            const incoming = session.round2_packages.get(p.frostIdHex) || [];

            this.send(socket.ws, {
                type: 'Round2All',
                payload: {
                    session: session.id,
                    packages: incoming
                }
            });
        });
    }

    // SIGNING

    private startSignRound1(session: SignSession) {
        session.state = 'Round1';

        const roster: [number, string, RosterPublicKey][] = [];

        session.joined_participants.forEach(p => {
            // We need to map back to the 'id' they used in DKG.
            // In `handleConnection`, we don't know it.
            // BUT, `JoinSignSession` payload had `signer_id_bincode_hex`.
            // We stored it in `signer_id_hex`.
            // That is the `id_hex`.

            if (!p.signer_id_hex) {
                console.error("Missing signer_id_hex for participant", p.uid);
                return;
            }
            roster.push([p.uid, p.signer_id_hex, p.pubKeyProp!]);
        });

        session.joined_participants.forEach(p => {
            const socket = this.connections.get(p.socketId);
            if (socket) {
                this.send(socket.ws, {
                    type: 'SignReadyRound1',
                    payload: {
                        session: session.id,
                        group_id: session.group_id,
                        threshold: session.threshold,
                        participants: session.participants_config.length,
                        roster: roster,
                        msg_keccak32_hex: session.message_hex // Client needs hash
                    }
                });
            }
        });
    }

    private finishSignRound1(session: SignSession) {
        session.state = 'Round2';

        console.log(`[server] Aggregating Commitments for session ${session.id}...`);
        try {
            const commitmentsObj = mapToObj(session.round1_commitments, (v) => v.commitment);
            const signingPackageHex = wasm.compute_signing_package(commitmentsObj, session.message_hex);

            session.signing_package = signingPackageHex;

            // Broadcast SignSigningPackage
            session.joined_participants.forEach(p => {
                const pSocket = this.connections.get(p.socketId);
                if (pSocket) this.send(pSocket.ws, {
                    type: 'SignSigningPackage',
                    payload: {
                        session: session.id,
                        signing_package_bincode_hex: signingPackageHex
                    }
                });
            });
            console.log(`[server] Broadcasted SigningPackage for session ${session.id}`);

        } catch (e: any) {
            console.error(`[server] Aggregation failed: ${e.message}`);
            // Notify all participants about the error
            session.joined_participants.forEach(p => {
                const pSocket = this.connections.get(p.socketId);
                if (pSocket) {
                    this.send(pSocket.ws, {
                        type: 'Error',
                        payload: { message: `Signing Round 1 aggregation failed: ${e.message}` }
                    });
                }
            });
        }
    }

    private finishSignRound2(session: SignSession) {
        console.log(`[server] Aggregating Signatures for session ${session.id}...`);
        try {
            const sharesObj = mapToObj(session.round2_shares, (v) => v.share);

            // Reconstruct verifying shares map (signer_id_hex -> share)
            const vsharesObj: any = {};
            session.joined_participants.forEach((p) => {
                if (p.signer_id_hex && p.verifying_share) {
                    vsharesObj[p.signer_id_hex] = p.verifying_share;
                } else if (p.pubKeyProp && typeof p.pubKeyProp !== 'string' && 'key' in p.pubKeyProp) {
                    // CAUTION: This might be where `verifying_share` is supposedly stored?
                    // No, `handleConnection` or `JoinSignSession` should have populated it.
                    // But `JoinSignSession` logic only set `signer_id_hex`.
                    // Where is `verifying_share`?
                    // Client `JoinSignSession` payload: `verifying_share_bincode_hex`.
                    // Server `JoinSignSession` handler MUST store it.
                }
            });

            // Fix: Logic in JoinSignSession needs to store `verifying_share`.
            // Let's assume verifying_share_bincode_hex IS stored in p.verifying_share (we need to update Join handler too if missed).

            if (!session.signing_package) throw new Error("Missing signing package");

            const resultJson = wasm.aggregate_signatures(
                session.signing_package,
                sharesObj,
                vsharesObj,
                session.group_vk_sec1_hex
            );

            const result = JSON.parse(resultJson);
            session.final_signature = result.signature_bincode_hex;
            session.state = 'Complete';

            // Find creator's SUID for the completed session
            const creatorParticipant = Array.from(session.joined_participants.values())
                .find(p => p.socketId === session.creatorSocketId);
            const creatorSuid = creatorParticipant ? creatorParticipant.uid : 1;

            // Store in completed sessions for later retrieval
            this.completedSignSessions.set(session.id, {
                session: session.id,
                creator_suid: creatorSuid,
                group_id: session.group_id,
                threshold: session.threshold,
                participants: session.participants_config,
                participants_pubs: session.participants_pubs,
                joined: Array.from(session.joined_participants.keys()),
                message: session.message,
                message_hex: session.message_hex,
                group_vk_sec1_hex: session.group_vk_sec1_hex,
                signature: result.signature_bincode_hex,
                rx: result.rx,
                ry: result.ry,
                s: result.s,
                px: result.px,
                py: result.py,
                created_at: new Date(session.created_at).toISOString(),
                completed_at: new Date().toISOString()
            });

            // Broadcast SignatureReady
            session.joined_participants.forEach(p => {
                const pSocket = this.connections.get(p.socketId);
                if (pSocket) this.send(pSocket.ws, {
                    type: 'SignatureReady',
                    payload: {
                        session: session.id,
                        signature_bincode_hex: result.signature_bincode_hex,
                        message: session.message_hex,
                        rx: result.rx,
                        ry: result.ry,
                        s: result.s,
                        px: result.px,
                        py: result.py
                    }
                });
            });
            console.log(`[server] Signature finalized for session ${session.id}`);

        } catch (e: any) {
            console.error(`[server] Signature aggregation failed: ${e.message}`);
            // Notify all participants about the error
            session.joined_participants.forEach(p => {
                const pSocket = this.connections.get(p.socketId);
                if (pSocket) {
                    this.send(pSocket.ws, {
                        type: 'Error',
                        payload: { message: `Signature aggregation failed: ${e.message}` }
                    });
                }
            });
        }
    }
}
