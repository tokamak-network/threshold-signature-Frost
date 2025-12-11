import React from 'react';
import {
    generate_ecdsa_keypair,
    generate_eddsa_keypair,
    derive_keys_from_signature,
    sign_challenge_ecdsa,
    sign_challenge_eddsa,
    dkg_part1,
    dkg_part2,
    dkg_part3,
    ecies_encrypt_ecdsa,
    ecies_encrypt_eddsa,
    ecies_decrypt_ecdsa,
    ecies_decrypt_eddsa,
    get_auth_payload_round1,
    get_auth_payload_round2,
    get_auth_payload_finalize,
    sign_message_ecdsa,
    sign_message_eddsa,
    sign_part1_commit,
    sign_part2_sign,
    get_auth_payload_sign_r1,
    get_auth_payload_sign_r2,
} from '../../pkg/tokamak_frost_wasm.js';
import type { DkgStatus, LogEntry, Participant, PendingDKGSession, CompletedDKGSession, SigningStatus, PendingSigningSession, CompletedSigningSession } from './types';

// ====================================================================
// region: Key Management
// ====================================================================

export const generateRandomKeys = (keyType: 'secp256k1' | 'edwards_on_bls12381') => {
    let keys: { private: string; public: string, key_type?: string } = { private: '', public: '' };
    if (keyType === 'edwards_on_bls12381') {
        const eddsaKeys = JSON.parse(generate_eddsa_keypair());
        keys.key_type = keyType;
        keys.private = eddsaKeys.private_key_hex;
        keys.public = eddsaKeys.public_key_hex;
        return keys;
    }
    const ecdsaKeys = JSON.parse(generate_ecdsa_keypair());
    keys.key_type = keyType;
    keys.private = ecdsaKeys.private_key_hex;
    keys.public = ecdsaKeys.public_key_hex;
    return keys;
};

export const deriveKeysFromMetaMask = async (signMessageAsync: (args: { message: string }) => Promise<`0x${string}`>, targetKeyType: 'secp256k1' | 'edwards_on_bls12381', salt: string) => {
    const messageToSign = `Tokamak-Frost-Seed V1 with salt of ${salt}`;
    const signature = await signMessageAsync({ message: messageToSign });
    const keys = JSON.parse(derive_keys_from_signature(signature, targetKeyType));
    keys.key_type = targetKeyType;
    return keys;
};

// ====================================================================
// region: Crypto Wrappers
// ====================================================================

export const signChallenge = (privateKeyHex: string, challenge: string, keyType: 'secp256k1' | 'edwards_on_bls12381') => {
    if (keyType === 'edwards_on_bls12381') {
        return sign_challenge_eddsa(privateKeyHex, challenge);
    }
    return sign_challenge_ecdsa(privateKeyHex, challenge);
}

export const signMessage = (privateKeyHex: string, messageHex: string, keyType: 'secp256k1' | 'edwards_on_bls12381') => {
    if (keyType === 'edwards_on_bls12381') {
        return sign_message_eddsa(privateKeyHex, messageHex);
    }
    return sign_message_ecdsa(privateKeyHex, messageHex);
}

export const eciesEncrypt = (recipientKeyHex: string, plaintextHex: string) => {
    // Detect recipient key type by length
    // Secp256k1 compressed: 33 bytes => 66 hex chars
    // EdDSA compressed: 32 bytes => 64 hex chars
    if (recipientKeyHex.length === 64) {
        return ecies_encrypt_eddsa(recipientKeyHex, plaintextHex);
    }
    return ecies_encrypt_ecdsa(recipientKeyHex, plaintextHex);
}

export const eciesDecrypt = (privateKeyHex: string, ephPubHex: string, nonceHex: string, ctHex: string, keyType: 'secp256k1' | 'edwards_on_bls12381') => {
    if (keyType === 'edwards_on_bls12381') {
        return ecies_decrypt_eddsa(privateKeyHex, ephPubHex, nonceHex, ctHex);
    }
    return ecies_decrypt_ecdsa(privateKeyHex, ephPubHex, nonceHex, ctHex);
}

// ====================================================================
// region: WebSocket Communication
// ====================================================================

export const sendMessage = (ws: WebSocket | null, message: object, log: (level: LogEntry['level'], message: string) => void) => {
    if (ws && ws.readyState === WebSocket.OPEN) {
        const msgString = JSON.stringify(message);
        log('data', `Sending: ${msgString}`);
        ws.send(msgString);
    } else {
        log('error', 'Cannot send message: WebSocket is not open.');
    }
};

// ====================================================================
// region: DKG Message Handler
// ====================================================================

interface DkgStateSetters {
    setSessionId: React.Dispatch<React.SetStateAction<string>>;
    setDkgStatus: React.Dispatch<React.SetStateAction<DkgStatus>>;
    setPendingSessions: React.Dispatch<React.SetStateAction<PendingDKGSession[]>>;
    setCompletedSessions: React.Dispatch<React.SetStateAction<CompletedDKGSession[]>>;
    setJoinedCount: React.Dispatch<React.SetStateAction<number>>;
    setTotalParticipants: React.Dispatch<React.SetStateAction<number>>;
    setJoinedParticipants: React.Dispatch<React.SetStateAction<Participant[]>>;
    setIsServerConnected: React.Dispatch<React.SetStateAction<boolean>>;
    setFinalShare: React.Dispatch<React.SetStateAction<string>>;
    setFinalGroupKey: React.Dispatch<React.SetStateAction<string>>;
    setJoiningSessionId: React.Dispatch<React.SetStateAction<string | null>>;
    setShowFinalKeyModal: React.Dispatch<React.SetStateAction<boolean>>;
    setMySuid: React.Dispatch<React.SetStateAction<number | null>>;
    setRawKeyPackageHex: React.Dispatch<React.SetStateAction<string>>;
}

export const handleServerMessage = async (
    msg: any,
    state: { privateKey: string, publicKey: string, keyType: 'secp256k1' | 'edwards_on_bls12381', isCreator: boolean, dkgState: React.MutableRefObject<any>, sessionIdRef: React.MutableRefObject<string> },
    setters: DkgStateSetters,
    log: (level: LogEntry['level'], message: string) => void,
    ws: React.MutableRefObject<WebSocket | null>
) => {
    log('info', `Handling DKG message of type: ${msg.type}`);

    switch (msg.type) {
        case 'DKGSessionCreated':
            const newSessionId = msg.payload.session;
            setters.setSessionId(newSessionId);
            state.sessionIdRef.current = newSessionId;
            setters.setDkgStatus('DKGSessionCreated');
            log('success', `DKG session created: ${newSessionId}`);
            log('info', 'Announce successful. Now requesting challenge to log in...');
            sendMessage(ws.current, { type: 'RequestChallenge' }, log);
            break;

        case 'PendingDKGSessions':
            setters.setPendingSessions(msg.payload.sessions);
            log('info', `Found ${msg.payload.sessions.length} pending DKG sessions.`);
            break;

        case 'CompletedDKGSessions':
            setters.setCompletedSessions(msg.payload.sessions);
            log('info', `Found ${msg.payload.sessions.length} completed DKG sessions.`);
            break;

        case 'Info':
            log('info', `Server Info: ${msg.payload.message}`);
            // ... (keep regex logic same)
            const joinMatch = msg.payload.message.match(/participant (\d+) joined session (\S+)/);
            if (joinMatch) {
                const joinedSuid = parseInt(joinMatch[1]);
                const sessionId = joinMatch[2];
                setters.setPendingSessions((prev: PendingDKGSession[]) =>
                    prev.map(s =>
                        s.session === sessionId
                            ? { ...s, joined: [...s.joined, joinedSuid] }
                            : s
                    )
                );
            }
            const disconnectMatch = msg.payload.message.match(/user (\d+) disconnected/i);
            if (disconnectMatch) {
                const disconnectedUid = parseInt(disconnectMatch[1]);
                log('info', `Participant ${disconnectedUid} has left the session.`);
                setters.setJoinedParticipants((prev: Participant[]) => prev.filter(p => p.uid !== disconnectedUid));
                setters.setJoinedCount((prev: number) => prev > 0 ? prev - 1 : 0);
            }
            break;

        case 'Challenge':
            try {
                const signature = signChallenge(state.privateKey, msg.payload.challenge, state.keyType);
                log('info', 'Challenge signed. Sending login...');

                // Construct RosterPublicKey object
                const rosterKey = state.keyType === 'edwards_on_bls12381'
                    ? { type: 'EdwardsOnBls12381', key: state.publicKey }
                    : { type: 'Secp256k1', key: state.publicKey };

                sendMessage(ws.current, {
                    type: 'Login',
                    payload: {
                        challenge: msg.payload.challenge,
                        public_key: rosterKey,
                        signature_hex: signature,
                    }
                }, log);
            } catch (e: any) {
                log('error', `Failed to sign challenge: ${e.message}`);
            }
            break;

        case 'LoginOk':
            setters.setIsServerConnected(true);
            setters.setDkgStatus('Connected');
            if (msg.payload && msg.payload.suid) {
                setters.setMySuid(msg.payload.suid);
                log('success', `Logged in successfully as SUID ${msg.payload.suid}.`);
            } else {
                log('success', `Logged in successfully.`);
            }
            sendMessage(ws.current, { type: 'ListPendingDKGSessions' }, log);
            break;

        case 'ReadyRound1':
            log('info', 'All participants have joined. Starting DKG Round 1...');
            const serverRoster = msg.payload.roster.map((r: any) => ({
                uid: r[0],
                id_hex: r[1],
                pubkey: typeof r[2] === 'string' ? r[2] : r[2].key
            }));

            setters.setJoinedCount(msg.payload.max_signers);
            setters.setTotalParticipants(msg.payload.max_signers);
            setters.setJoinedParticipants(serverRoster.map((p: { uid: number, pubkey: string }) => ({ uid: p.uid, pubkey: p.pubkey })));
            state.dkgState.current.roster = serverRoster;
            state.dkgState.current.group_id = msg.payload.group_id;
            setters.setDkgStatus('Round1');
            try {
                await new Promise(resolve => setTimeout(resolve, 1000));
                const myIdentifierHex = msg.payload.id_hex;
                state.dkgState.current.identifier = myIdentifierHex;

                const { secret_package_hex, public_package_hex } = JSON.parse(dkg_part1(myIdentifierHex, msg.payload.max_signers, msg.payload.min_signers));
                state.dkgState.current.r1_secret = secret_package_hex;

                const payload_hex = get_auth_payload_round1(state.sessionIdRef.current, myIdentifierHex, public_package_hex);
                const signature = signMessage(state.privateKey, payload_hex, state.keyType);

                sendMessage(ws.current, {
                    type: 'Round1Submit',
                    payload: {
                        session: state.sessionIdRef.current,
                        id_hex: myIdentifierHex,
                        pkg_bincode_hex: public_package_hex,
                        signature_hex: signature
                    }
                }, log);
                log('info', 'Round 1 package submitted.');
            } catch (e: any) {
                log('error', `DKG Part 1 failed: ${e.message}`);
            }
            break;

        case 'Round1All':
            log('info', 'Received all Round 1 packages. Storing for future rounds.');
            state.dkgState.current.all_r1_packages = msg.payload.packages.reduce((acc: any, [id_hex, pkg_hex, _sig]: string[]) => {
                acc[id_hex] = pkg_hex;
                return acc;
            }, {});
            break;

        case 'ReadyRound2':
            log('info', 'Ready for Round 2. Generating and encrypting shares...');
            setters.setDkgStatus('Round2');
            try {
                await new Promise(resolve => setTimeout(resolve, 1000));
                const r1_packages_for_part2 = { ...state.dkgState.current.all_r1_packages };
                delete r1_packages_for_part2[state.dkgState.current.identifier];

                const { secret_package_hex, outgoing_packages } = JSON.parse(dkg_part2(state.dkgState.current.r1_secret, r1_packages_for_part2));
                state.dkgState.current.r2_secret = secret_package_hex;

                const pkgs_cipher: [string, any, string][] = [];
                for (const [id_hex, pkg_hex] of Object.entries(outgoing_packages)) {
                    const recipient = state.dkgState.current.roster.find((p: any) => p.id_hex === id_hex);
                    if (!recipient) throw new Error(`Could not find public key for recipient ${id_hex}`);

                    const { ephemeral_public_key_hex, nonce_hex, ciphertext_hex } = JSON.parse(eciesEncrypt(recipient.pubkey, pkg_hex as string));

                    const payload_hex = get_auth_payload_round2(state.sessionIdRef.current, state.dkgState.current.identifier, id_hex, ephemeral_public_key_hex, nonce_hex, ciphertext_hex);
                    const signature = signMessage(state.privateKey, payload_hex, state.keyType);

                    // Construct RosterPublicKey for ephemeral key
                    let ephKeyType = 'Secp256k1';
                    if (ephemeral_public_key_hex.length === 64) {
                        ephKeyType = 'EdwardsOnBls12381';
                    } else if (ephemeral_public_key_hex.length === 66) {
                        ephKeyType = 'Secp256k1'; // Fallback / explicit
                    }

                    const encryptedPayload = {
                        ephemeral_public_key: { type: ephKeyType, key: ephemeral_public_key_hex },
                        nonce: nonce_hex,
                        ciphertext: ciphertext_hex
                    };

                    pkgs_cipher.push([id_hex, encryptedPayload, signature]);
                }

                sendMessage(ws.current, {
                    type: 'Round2Submit',
                    payload: {
                        session: state.sessionIdRef.current,
                        id_hex: state.dkgState.current.identifier,
                        pkgs_cipher: pkgs_cipher
                    }
                }, log);
                log('info', 'Round 2 encrypted packages submitted.');
            } catch (e: any) {
                console.error(e);
                log('error', `DKG Part 2 failed: ${e.message}`);
            }
            break;

        case 'Round2All':
            log('info', 'Received all Round 2 packages. Finalizing...');
            try {
                await new Promise(resolve => setTimeout(resolve, 1000));
                const received_packages = msg.payload.packages;
                const decrypted_packages: any = {};
                for (const [from_id_hex, encrypted_payload, _sig] of received_packages) {
                    // encrypted_payload is { ephemeral_public_key: { type:..., key:... }, nonce: "...", ciphertext: "..." }
                    const eph_pub_key = encrypted_payload.ephemeral_public_key;
                    const eph_pub_hex = typeof eph_pub_key === 'string' ? eph_pub_key : eph_pub_key.key;

                    const decrypted = eciesDecrypt(state.privateKey, eph_pub_hex, encrypted_payload.nonce, encrypted_payload.ciphertext, state.keyType);
                    decrypted_packages[from_id_hex] = decrypted;
                }

                const r1_packages_for_part3 = { ...state.dkgState.current.all_r1_packages };
                delete r1_packages_for_part3[state.dkgState.current.identifier];

                const rosterForPart3 = new Map(state.dkgState.current.roster.map((p: any) => [p.uid, p.pubkey]));

                log('info', `Calling dkg_part3 with group_id=${state.dkgState.current.group_id}`);

                const { key_package_hex, group_public_key_hex } = JSON.parse(dkg_part3(
                    state.dkgState.current.r2_secret,
                    r1_packages_for_part3,
                    decrypted_packages,
                    state.dkgState.current.group_id,
                    rosterForPart3,
                    state.keyType
                ));
                log('info', 'DKG Part 3 success. Generated Group Key.');

                setters.setRawKeyPackageHex(key_package_hex); // <--- THIS LINE WAS MISSING
                setters.setFinalShare(key_package_hex);
                setters.setFinalGroupKey(group_public_key_hex);
                setters.setDkgStatus('Finalized');
                log('success', 'DKG Ceremony Complete! Sending FinalizeSubmit...');

                const payload_hex = get_auth_payload_finalize(state.sessionIdRef.current, state.dkgState.current.identifier, group_public_key_hex);
                const signature = signMessage(state.privateKey, payload_hex, state.keyType);

                sendMessage(ws.current, {
                    type: 'FinalizeSubmit',
                    payload: {
                        session: state.sessionIdRef.current,
                        id_hex: state.dkgState.current.identifier,
                        group_vk_sec1_hex: group_public_key_hex,
                        signature_hex: signature
                    }
                }, log);

            } catch (e: any) {
                log('error', `DKG Part 3 failed: ${e.message}`);
            }
            break;

        case 'Finalized':
            log('success', `Server confirmed finalization. Group Key: ${msg.payload.group_vk_sec1_hex}`);
            setters.setJoiningSessionId(null);
            setters.setShowFinalKeyModal(true);
            if (!state.isCreator) {
                sendMessage(ws.current, { type: 'ListPendingDKGSessions' }, log);
            }
            break;

        case 'Error':
            log('error', `Server error: ${msg.payload.message}`);
            setters.setDkgStatus('Failed');
            setters.setJoiningSessionId(null);
            if (!state.isCreator) {
                sendMessage(ws.current, { type: 'ListPendingDKGSessions' }, log);
            }
            break;

        default:
            log('info', `Received unhandled DKG message type: ${msg.type}`);
            break;
    }
};

// ====================================================================
// region: Signing Message Handler
// ====================================================================

interface SigningStateSetters {
    setSessionId: React.Dispatch<React.SetStateAction<string>>;
    setSigningStatus: React.Dispatch<React.SetStateAction<SigningStatus>>;
    setPendingSessions: React.Dispatch<React.SetStateAction<PendingSigningSession[]>>;
    setCompletedSessions: React.Dispatch<React.SetStateAction<CompletedSigningSession[]>>;
    setFinalSignature: React.Dispatch<React.SetStateAction<string>>;
    setIsServerConnected: React.Dispatch<React.SetStateAction<boolean>>;
    setMySuid: React.Dispatch<React.SetStateAction<number | null>>;
    setPx: React.Dispatch<React.SetStateAction<string>>;
    setPy: React.Dispatch<React.SetStateAction<string>>;
    setRx: React.Dispatch<React.SetStateAction<string>>;
    setRy: React.Dispatch<React.SetStateAction<string>>;
    setS: React.Dispatch<React.SetStateAction<string>>;
    setFinalMessage: React.Dispatch<React.SetStateAction<string>>;
    setShowSignatureModal: React.Dispatch<React.SetStateAction<boolean>>;
}

export const handleSigningServerMessage = async (
    msg: any,
    state: { privateKey: string, publicKey: string, keyPackage: string, keyType: 'secp256k1' | 'edwards_on_bls12381', signingState: React.MutableRefObject<any>, sessionIdRef: React.MutableRefObject<string> },
    setters: SigningStateSetters,
    log: (level: LogEntry['level'], message: string) => void,
    ws: React.MutableRefObject<WebSocket | null>
) => {
    log('info', `Handling Signing message of type: ${msg.type}`);

    if (msg.type === 'Error') {
        log('error', `Server error: ${msg.payload.message}`);
        setters.setSigningStatus('Failed');
        return;
    }

    switch (msg.type) {
        case 'SignSessionCreated':
            const newSessionId = msg.payload.session;
            setters.setSessionId(newSessionId);
            state.sessionIdRef.current = newSessionId;
            setters.setSigningStatus('SessionCreated');
            log('success', `Signing session created: ${newSessionId}`);
            log('info', 'Now refreshing session list...');
            sendMessage(ws.current, { type: 'ListPendingSigningSessions' }, log);
            break;

        case 'Challenge':
            try {
                const signature = signChallenge(state.privateKey, msg.payload.challenge, state.keyType);
                log('info', 'Challenge signed. Sending login...');

                const rosterKey = state.keyType === 'edwards_on_bls12381'
                    ? { type: 'EdwardsOnBls12381', key: state.publicKey }
                    : { type: 'Secp256k1', key: state.publicKey };

                sendMessage(ws.current, {
                    type: 'Login',
                    payload: {
                        challenge: msg.payload.challenge,
                        public_key: rosterKey,
                        signature_hex: signature,
                    }
                }, log);
            } catch (e: any) {
                log('error', `Failed to sign challenge: ${e.message}`);
            }
            break;

        case 'LoginOk':
            setters.setIsServerConnected(true);
            setters.setSigningStatus('Connected');
            if (msg.payload && msg.payload.suid) {
                setters.setMySuid(msg.payload.suid);
                log('success', `Logged in successfully as SUID ${msg.payload.suid}.`);
            } else {
                log('success', `Logged in successfully.`);
            }
            sendMessage(ws.current, { type: 'ListPendingSigningSessions' }, log);
            break;

        case 'Info':
            log('info', `Server Info: ${msg.payload.message}`);
            const joinMatch = msg.payload.message.match(/participant (\d+) joined session (\S+)/);
            if (joinMatch) {
                const joinedSuid = parseInt(joinMatch[1]);
                const sessionId = joinMatch[2];
                setters.setPendingSessions((prev: PendingSigningSession[]) =>
                    prev.map(s =>
                        s.session === sessionId
                            ? { ...s, joined: [...s.joined, joinedSuid] }
                            : s
                    )
                );
            }
            break;

        case 'PendingSigningSessions':
            setters.setPendingSessions(msg.payload.sessions);
            log('info', `Found ${msg.payload.sessions.length} pending signing sessions.`);
            break;

        case 'CompletedSigningSessions':
            setters.setCompletedSessions(msg.payload.sessions);
            log('info', `Found ${msg.payload.sessions.length} completed signing sessions.`);
            break;

        case 'SignReadyRound1':
            log('info', 'All participants have joined. Starting Signing Round 1...');
            setters.setSigningStatus('Round1');
            try {
                const { nonces_hex, commitments_hex } = JSON.parse(sign_part1_commit(state.keyPackage));
                state.signingState.current.nonces = nonces_hex;

                const myKey = state.publicKey;
                const myRosterEntry = msg.payload.roster.find((p: any) => {
                    const pub = p[2];
                    if (typeof pub === 'string') return pub === myKey;
                    return pub.key === myKey;
                });

                if (!myRosterEntry) {
                    throw new Error("Could not find myself in the session roster.");
                }
                const myIdHex = myRosterEntry[1];
                state.signingState.current.identifier = myIdHex;
                state.signingState.current.group_id = msg.payload.group_id;
                state.signingState.current.msg32_hex = msg.payload.msg_keccak32_hex;

                const payload_hex = get_auth_payload_sign_r1(state.sessionIdRef.current, msg.payload.group_id, myIdHex, commitments_hex);
                const signature = signMessage(state.privateKey, payload_hex, state.keyType);

                sendMessage(ws.current, {
                    type: 'SignRound1Submit',
                    payload: {
                        session: state.sessionIdRef.current,
                        id_hex: myIdHex,
                        commitments_bincode_hex: commitments_hex,
                        signature_hex: signature,
                    }
                }, log);
            } catch (e: any) {
                log('error', `Signing Part 1 failed: ${e.message}`);
            }
            break;

        case 'SignSigningPackage':
            log('info', 'Received signing package. Starting Signing Round 2...');
            setters.setSigningStatus('Round2');
            try {
                const signature_share_hex = sign_part2_sign(state.keyPackage, state.signingState.current.nonces, msg.payload.signing_package_bincode_hex);

                const payload_hex = get_auth_payload_sign_r2(
                    state.sessionIdRef.current,
                    state.signingState.current.group_id,
                    state.signingState.current.identifier,
                    signature_share_hex,
                    state.signingState.current.msg32_hex
                );
                const signature = signMessage(state.privateKey, payload_hex, state.keyType);

                sendMessage(ws.current, {
                    type: 'SignRound2Submit',
                    payload: {
                        session: state.sessionIdRef.current,
                        id_hex: state.signingState.current.identifier,
                        signature_share_bincode_hex: signature_share_hex,
                        signature_hex: signature,
                    }
                }, log);
            } catch (e: any) {
                log('error', `Signing Part 2 failed: ${e.message}`);
            }
            break;

        case 'SignatureReady':
            log('success', `Signature Ready!`);
            setters.setFinalSignature(msg.payload.signature_bincode_hex);
            setters.setPx(msg.payload.px);
            setters.setPy(msg.payload.py);
            setters.setRx(msg.payload.rx);
            setters.setRy(msg.payload.ry);
            setters.setS(msg.payload.s);
            setters.setFinalMessage(msg.payload.message);
            setters.setSigningStatus('Complete');
            setters.setShowSignatureModal(true);
            break;
    }
};
