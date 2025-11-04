import React from 'react';
import {
    generate_ecdsa_keypair,
    derive_key_from_signature,
    sign_challenge,
    dkg_part1,
    dkg_part2,
    dkg_part3,
    ecies_encrypt,
    ecies_decrypt,
    get_auth_payload_round1,
    get_auth_payload_round2,
    get_auth_payload_finalize,
    sign_message
} from '../../pkg/tokamak_frost_wasm.js';
import type { DkgStatus, LogEntry, Participant, PendingDKGSession } from './types';

// ====================================================================
// region: Key Management
// ====================================================================

export const generateRandomKeys = () => {
    return JSON.parse(generate_ecdsa_keypair());
};

export const deriveKeysFromMetaMask = async (signMessageAsync: (args: { message: string }) => Promise<`0x${string}`>) => {
    const messageToSign = "Tokamak-Frost-Seed V1";
    const signature = await signMessageAsync({ message: messageToSign });
    return JSON.parse(derive_key_from_signature(signature));
};

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
// region: Server Message Handler (Core DKG Logic)
// ====================================================================

interface StateSetters {
    setSessionId: React.Dispatch<React.SetStateAction<string>>;
    setDkgStatus: React.Dispatch<React.SetStateAction<DkgStatus>>;
    setPendingSessions: React.Dispatch<React.SetStateAction<PendingDKGSession[]>>;
    setJoinedCount: React.Dispatch<React.SetStateAction<number>>;
    setTotalParticipants: React.Dispatch<React.SetStateAction<number>>;
    setJoinedParticipants: React.Dispatch<React.SetStateAction<Participant[]>>;
    setIsServerConnected: React.Dispatch<React.SetStateAction<boolean>>;
    setFinalShare: React.Dispatch<React.SetStateAction<string>>;
    setFinalGroupKey: React.Dispatch<React.SetStateAction<string>>;
    setJoiningSessionId: React.Dispatch<React.SetStateAction<string | null>>;
    setShowFinalKeyModal: React.Dispatch<React.SetStateAction<boolean>>;
}

export const handleServerMessage = async (
    msg: any,
    state: { privateKey: string, publicKey: string, isCreator: boolean, dkgState: React.MutableRefObject<any>, sessionIdRef: React.MutableRefObject<string> },
    setters: StateSetters,
    log: (level: LogEntry['level'], message: string) => void,
    ws: React.MutableRefObject<WebSocket | null>
) => {
    log('info', `Handling message of type: ${msg.type}`);

    switch (msg.type) {
        case 'SessionCreated':
            const newSessionId = msg.payload.session;
            setters.setSessionId(newSessionId);
            state.sessionIdRef.current = newSessionId;
            setters.setDkgStatus('SessionCreated');
            log('success', `DKG session created: ${newSessionId}`);
            log('info', 'Announce successful. Now requesting challenge to log in...');
            sendMessage(ws.current, { type: 'RequestChallenge' }, log);
            break;

        case 'PendingDKGSessions':
            setters.setPendingSessions(msg.payload.sessions);
            log('info', `Found ${msg.payload.sessions.length} pending sessions.`);
            break;

        case 'Info':
            log('info', `Server Info: ${msg.payload.message}`);
            const joinMatch = msg.payload.message.match(/(\d+)\/(\d+)/);
            if (joinMatch) {
                setters.setJoinedCount(parseInt(joinMatch[1]));
                setters.setTotalParticipants(parseInt(joinMatch[2]));
            }
            const disconnectMatch = msg.payload.message.match(/user (\d+) disconnected/i);
            if (disconnectMatch) {
                const disconnectedUid = parseInt(disconnectMatch[1]);
                log('info', `Participant ${disconnectedUid} has left the session.`);
                setters.setJoinedParticipants(prev => prev.filter(p => p.uid !== disconnectedUid));
                setters.setJoinedCount(prev => prev > 0 ? prev - 1 : 0);
            }
            break;

        case 'Challenge':
            try {
                const signature = sign_challenge(state.privateKey, msg.payload.challenge);
                log('info', 'Challenge signed. Sending login...');
                sendMessage(ws.current, {
                    type: 'Login',
                    payload: {
                        challenge: msg.payload.challenge,
                        pubkey_hex: state.publicKey,
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
            log('success', `Logged in successfully as User ID: ${msg.payload.user_id}`);
            if (state.isCreator) {
                setters.setJoinedCount(1);
                sendMessage(ws.current, { type: 'JoinSession', payload: { session: state.sessionIdRef.current } }, log);
            } else {
                sendMessage(ws.current, { type: 'ListPendingDKGSessions' }, log);
            }
            break;

        case 'ReadyRound1':
            log('info', 'All participants have joined. Starting DKG Round 1...');
            const serverRoster = msg.payload.roster.map((r: [number, string, string]) => ({ uid: r[0], id_hex: r[1], pubkey: r[2] }));
            setters.setJoinedCount(msg.payload.max_signers);
            setters.setTotalParticipants(msg.payload.max_signers);
            setters.setJoinedParticipants(serverRoster.map((p: {uid: number, pubkey: string}) => ({ uid: p.uid, pubkey: p.pubkey })));
            state.dkgState.current.roster = serverRoster;
            setters.setDkgStatus('Round1');
            try {
                await new Promise(resolve => setTimeout(resolve, 1000));
                const myIdentifierHex = msg.payload.id_hex;
                state.dkgState.current.identifier = myIdentifierHex;

                const { secret_package_hex, public_package_hex } = JSON.parse(dkg_part1(myIdentifierHex, msg.payload.max_signers, msg.payload.min_signers));
                state.dkgState.current.r1_secret = secret_package_hex;

                const payload_hex = get_auth_payload_round1(state.sessionIdRef.current, myIdentifierHex, public_package_hex);
                const signature = sign_message(state.privateKey, payload_hex);

                sendMessage(ws.current, {
                    type: 'Round1Submit',
                    payload: {
                        session: state.sessionIdRef.current,
                        id_hex: myIdentifierHex,
                        pkg_bincode_hex: public_package_hex,
                        sig_ecdsa_hex: signature
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

                const pkgs_cipher_hex: [string, string, string, string, string][] = [];
                for (const [id_hex, pkg_hex] of Object.entries(outgoing_packages)) {
                    const recipient = state.dkgState.current.roster.find((p: any) => p.id_hex === id_hex);
                    if (!recipient) throw new Error(`Could not find public key for recipient ${id_hex}`);

                    const { ephemeral_public_key_hex, nonce_hex, ciphertext_hex } = JSON.parse(ecies_encrypt(recipient.pubkey, pkg_hex as string));

                    const payload_hex = get_auth_payload_round2(state.sessionIdRef.current, state.dkgState.current.identifier, id_hex, ephemeral_public_key_hex, nonce_hex, ciphertext_hex);
                    const signature = sign_message(state.privateKey, payload_hex);

                    pkgs_cipher_hex.push([id_hex, ephemeral_public_key_hex, nonce_hex, ciphertext_hex, signature]);
                }

                sendMessage(ws.current, {
                    type: 'Round2Submit',
                    payload: {
                        session: state.sessionIdRef.current,
                        id_hex: state.dkgState.current.identifier,
                        pkgs_cipher_hex: pkgs_cipher_hex
                    }
                }, log);
                log('info', 'Round 2 encrypted packages submitted.');
            } catch (e: any) {
                log('error', `DKG Part 2 failed: ${e.message}`);
            }
            break;

        case 'Round2All':
            log('info', 'Received all Round 2 packages. Finalizing...');
            try {
                await new Promise(resolve => setTimeout(resolve, 1000));
                const received_packages = msg.payload.packages;
                const decrypted_packages: any = {};
                for (const [from_id_hex, eph_pub_hex, nonce_hex, ct_hex, _sig] of received_packages) {
                    const decrypted = ecies_decrypt(state.privateKey, eph_pub_hex, nonce_hex, ct_hex);
                    decrypted_packages[from_id_hex] = decrypted;
                }

                const r1_packages_for_part3 = { ...state.dkgState.current.all_r1_packages };
                delete r1_packages_for_part3[state.dkgState.current.identifier];

                const { key_package_hex, group_public_key_hex } = JSON.parse(dkg_part3(state.dkgState.current.r2_secret, r1_packages_for_part3, decrypted_packages));
                setters.setFinalShare(key_package_hex);
                setters.setFinalGroupKey(group_public_key_hex);
                setters.setDkgStatus('Finalized');
                log('success', 'DKG Ceremony Complete!');

                const payload_hex = get_auth_payload_finalize(state.sessionIdRef.current, state.dkgState.current.identifier, group_public_key_hex);
                const signature = sign_message(state.privateKey, payload_hex);

                sendMessage(ws.current, {
                    type: 'FinalizeSubmit',
                    payload: {
                        session: state.sessionIdRef.current,
                        id_hex: state.dkgState.current.identifier,
                        group_vk_sec1_hex: group_public_key_hex,
                        sig_ecdsa_hex: signature
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
            log('info', `Received unhandled message type: ${msg.type}`);
            break;
    }
};
