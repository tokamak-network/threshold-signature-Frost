import { useState, useRef, useEffect } from 'react';
import init, {
    generate_ecdsa_keypair,
    sign_challenge,
    sign_message,
    get_auth_payload_round1,
    get_auth_payload_round2,
    get_auth_payload_finalize,
    dkg_part1,
    dkg_part2,
    dkg_part3,
    ecies_encrypt,
    ecies_decrypt
} from '../../pkg/tokamak_frost_wasm.js';
import './App.css';

// ====================================================================
// region: Helper Types
// ====================================================================

type LogEntry = { level: 'info' | 'error' | 'success' | 'data'; message: string; };
type DkgStatus = 'Idle' | 'Connecting' | 'Connected' | 'SessionCreated' | 'Joined' | 'Round1' | 'Round2' | 'Finalized' | 'Failed';
type Participant = { uid: number; pubkey: string; };
type RosterEntry = { uid: string; pubkey: string; };
type PendingDKGSession = {
    session: string;
    group_id: string;
    min_signers: number;
    max_signers: number;
    participants: number[];
    joined: number[];
};

// ====================================================================
// region: Main App Component
// ====================================================================

function App() {
    // --- State for Connection & Keys ---
    const [ip, setIp] = useState('127.0.0.1');
    const [port, setPort] = useState('9034');
    const [privateKey, setPrivateKey] = useState('');
    const [publicKey, setPublicKey] = useState('');
    const [isConnected, setIsConnected] = useState(false);

    // --- State for DKG Ceremony ---
    const [isCreator, setIsCreator] = useState(true);
    const [groupId, setGroupId] = useState('my-frost-group');
    const [minSigners, setMinSigners] = useState('2');
    const [maxSigners, setMaxSigners] = useState('2');
    const [roster, setRoster] = useState<RosterEntry[]>(Array.from({ length: 2 }, () => ({ uid: '', pubkey: '' })));
    const [sessionId, setSessionId] = useState('');
    const sessionIdRef = useRef(''); // Ref for immediate access
    const [dkgStatus, setDkgStatus] = useState<DkgStatus>('Idle');
    const [joinedCount, setJoinedCount] = useState(0);
    const [totalParticipants, setTotalParticipants] = useState(0);
    const [joinedParticipants, setJoinedParticipants] = useState<Participant[]>([]);
    const [pendingSessions, setPendingSessions] = useState<PendingDKGSession[]>([]);

    // --- State for Logs & Results ---
    const [logs, setLogs] = useState<LogEntry[]>([]);
    const [finalShare, setFinalShare] = useState('');
    const [finalGroupKey, setFinalGroupKey] = useState('');

    // --- Refs for WebSocket and WASM state ---
    const ws = useRef<WebSocket | null>(null);
    const dkgState = useRef<any>({}); // To hold intermediate DKG secrets

    // --- Effects ---
    useEffect(() => {
        init().then(() => {
            log('info', 'WASM module initialized. Please generate keys.');
        });
    }, []);

    useEffect(() => {
        const num = parseInt(maxSigners) || 0;
        if (num < 2) return;
        setRoster(currentRoster => {
            const newRoster = Array.from({ length: num }, (_, i) => {
                return currentRoster[i] || { uid: '', pubkey: '' };
            });
            return newRoster;
        });
    }, [maxSigners]);

    // --- Logging Utility ---
    const log = (level: LogEntry['level'], message: string) => {
        console.log(`[${level.toUpperCase()}] ${message}`);
        setLogs(prev => [...prev, { level, message }]);
    };

    const sendMessage = (message: object) => {
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
            const msgString = JSON.stringify(message);
            log('data', `Sending: ${msgString}`);
            ws.current.send(msgString);
        } else {
            log('error', 'Cannot send message: WebSocket is not open.');
        }
    };

    // --- Core Functions ---
    const handleGenerateKeys = () => {
        try {
            const keys = JSON.parse(generate_ecdsa_keypair());
            setPrivateKey(keys.private_key_hex);
            setPublicKey(keys.public_key_hex);
            log('success', 'New ECDSA key pair generated.');
        } catch (e: any) {
            log('error', `Key generation failed: ${e.message}`);
        }
    };

    const handleDisconnect = () => {
        if (ws.current) {
            ws.current.close();
        }
    };

    const handleClearLogs = () => {
        setLogs([]);
    };

    const handleRosterChange = (index: number, field: keyof RosterEntry, value: string) => {
        const newRoster = [...roster];
        newRoster[index] = { ...newRoster[index], [field]: value };
        setRoster(newRoster);
    };

    const commonConnect = (onOpen: () => void) => {
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
            log('info', 'Already connected.');
            onOpen();
            return;
        }

        if (!privateKey || !publicKey) {
            log('error', 'Please generate or provide keys before connecting.');
            return;
        }

        const url = `ws://${ip}:${port}/ws`;
        log('info', `Connecting to ${url}...`);
        setDkgStatus('Connecting');

        const socket = new WebSocket(url);
        ws.current = socket;

        socket.onopen = onOpen;

        socket.onmessage = (event) => {
            log('data', `Received: ${event.data}`);
            const serverMsg = JSON.parse(event.data);
            handleServerMessage(serverMsg);
        };

        socket.onerror = (err) => {
            log('error', `WebSocket error: ${err.type}`);
            setIsConnected(false);
            setDkgStatus('Failed');
        };

        socket.onclose = () => {
            log('info', 'Disconnected from f-server.');
            setIsConnected(false);
            setDkgStatus('Idle');
            setJoinedCount(0);
            setTotalParticipants(0);
            setJoinedParticipants([]);
            setPendingSessions([]);
        };
    };

    const handleCreatorConnect = () => {
        const min_signers = parseInt(minSigners);
        const max_signers = parseInt(maxSigners);

        if (min_signers < 2 || max_signers < 2) {
            log('error', 'Min/Max players cannot be less than 2.');
            return;
        }
        if (min_signers > max_signers) {
            log('error', 'Min players cannot be greater than Max players.');
            return;
        }

        const participants = roster.map(r => parseInt(r.uid));
        const participants_pubs = roster.map(r => [parseInt(r.uid), r.pubkey]);

        if (participants.some(uid => isNaN(uid)) || participants_pubs.some(p => !p[1])) {
            log('error', 'All UID and Public Key fields in the roster must be filled.');
            return;
        }

        if (participants.length !== max_signers) {
            log('error', `Number of participants in roster must match Max Players (${max_signers}).`);
            return;
        }
        setTotalParticipants(max_signers);

        commonConnect(() => {
            log('info', 'Connected. Announcing session...');
            sendMessage({
                type: 'AnnounceSession',
                payload: {
                    group_id: groupId,
                    min_signers: min_signers,
                    max_signers: max_signers,
                    participants: participants,
                    participants_pubs: participants_pubs
                }
            });
        });
    };

    const handleParticipantConnect = () => {
        commonConnect(() => {
            log('info', 'Connected. Requesting challenge to log in...');
            sendMessage({ type: 'RequestChallenge' });
        });
    };

    const handleRefreshSessions = () => {
        log('info', 'Fetching list of pending DKG sessions...');
        sendMessage({ type: 'ListPendingDKGSessions' });
    };

    const handleJoinSession = (sessionToJoin: string) => {
        log('info', `Joining session ${sessionToJoin}...`);
        sessionIdRef.current = sessionToJoin; // Set the ref immediately
        sendMessage({ type: 'JoinSession', payload: { session: sessionToJoin } });
        setDkgStatus('Joined');
    };

    const handleServerMessage = (msg: any) => {
        log('info', `Handling message of type: ${msg.type}`);

        switch (msg.type) {
            case 'SessionCreated':
                const newSessionId = msg.payload.session;
                setSessionId(newSessionId);
                sessionIdRef.current = newSessionId;
                setDkgStatus('SessionCreated');
                log('success', `DKG session created: ${newSessionId}`);
                log('info', 'Announce successful. Now requesting challenge to log in...');
                sendMessage({ type: 'RequestChallenge' });
                break;

            case 'PendingDKGSessions':
                setPendingSessions(msg.payload.sessions);
                log('info', `Found ${msg.payload.sessions.length} pending sessions.`);
                break;

            case 'Info':
                log('info', `Server Info: ${msg.payload.message}`);
                const joinMatch = msg.payload.message.match(/(\d+)\/(\d+)/);
                if (joinMatch) {
                    setJoinedCount(parseInt(joinMatch[1]));
                    setTotalParticipants(parseInt(joinMatch[2]));
                }
                const disconnectMatch = msg.payload.message.match(/user (\d+) disconnected/i);
                if (disconnectMatch) {
                    const disconnectedUid = parseInt(disconnectMatch[1]);
                    log('info', `Participant ${disconnectedUid} has left the session.`);
                    setJoinedParticipants(prev => prev.filter(p => p.uid !== disconnectedUid));
                    setJoinedCount(prev => prev > 0 ? prev - 1 : 0);
                }
                break;

            case 'Challenge':
                try {
                    const signature = sign_challenge(privateKey, msg.payload.challenge);
                    log('info', 'Challenge signed. Sending login...');
                    sendMessage({
                        type: 'Login',
                        payload: {
                            challenge: msg.payload.challenge,
                            pubkey_hex: publicKey,
                            signature_hex: signature,
                        }
                    });
                } catch (e: any) {
                    log('error', `Failed to sign challenge: ${e.message}`);
                }
                break;

            case 'LoginOk':
                setIsConnected(true);
                setDkgStatus('Connected');
                log('success', `Logged in successfully as User ID: ${msg.payload.user_id}`);
                if (isCreator) {
                    setJoinedCount(1);
                    handleJoinSession(sessionIdRef.current);
                } else {
                    handleRefreshSessions();
                }
                break;

            case 'ReadyRound1':
                log('info', 'All participants have joined. Starting DKG Round 1...');
                const serverRoster = msg.payload.roster.map((r: [number, string, string]) => ({ uid: r[0], id_hex: r[1], pubkey: r[2] }));
                setJoinedCount(msg.payload.max_signers);
                setTotalParticipants(msg.payload.max_signers);
                setJoinedParticipants(serverRoster.map((p: {uid: number, pubkey: string}) => ({ uid: p.uid, pubkey: p.pubkey })));
                dkgState.current.roster = serverRoster;
                setDkgStatus('Round1');
                try {
                    const myIdentifierHex = msg.payload.id_hex;
                    dkgState.current.identifier = myIdentifierHex;

                    const { secret_package_hex, public_package_hex } = JSON.parse(dkg_part1(myIdentifierHex, msg.payload.max_signers, msg.payload.min_signers));
                    dkgState.current.r1_secret = secret_package_hex;

                    const payload_hex = get_auth_payload_round1(sessionIdRef.current, myIdentifierHex, public_package_hex);
                    const signature = sign_message(privateKey, payload_hex);

                    sendMessage({
                        type: 'Round1Submit',
                        payload: {
                            session: sessionIdRef.current,
                            id_hex: myIdentifierHex,
                            pkg_bincode_hex: public_package_hex,
                            sig_ecdsa_hex: signature
                        }
                    });
                    log('info', 'Round 1 package submitted.');
                } catch (e: any) {
                    log('error', `DKG Part 1 failed: ${e.message}`);
                }
                break;

            case 'Round1All':
                log('info', 'Received all Round 1 packages. Storing for future rounds.');
                dkgState.current.all_r1_packages = msg.payload.packages.reduce((acc: any, [id_hex, pkg_hex, _sig]: string[]) => {
                    acc[id_hex] = pkg_hex;
                    return acc;
                }, {});
                break;

            case 'ReadyRound2':
                log('info', 'Ready for Round 2. Generating and encrypting shares...');
                setDkgStatus('Round2');
                try {
                    const r1_packages_for_part2 = { ...dkgState.current.all_r1_packages };
                    delete r1_packages_for_part2[dkgState.current.identifier];

                    const { secret_package_hex, outgoing_packages } = JSON.parse(dkg_part2(dkgState.current.r1_secret, r1_packages_for_part2));
                    dkgState.current.r2_secret = secret_package_hex;

                    const pkgs_cipher_hex: [string, string, string, string, string][] = [];
                    for (const [id_hex, pkg_hex] of Object.entries(outgoing_packages)) {
                        const recipient = dkgState.current.roster.find((p: any) => p.id_hex === id_hex);
                        if (!recipient) throw new Error(`Could not find public key for recipient ${id_hex}`);
                        
                        const { ephemeral_public_key_hex, nonce_hex, ciphertext_hex } = JSON.parse(ecies_encrypt(recipient.pubkey, pkg_hex as string));
                        
                        const payload_hex = get_auth_payload_round2(sessionIdRef.current, dkgState.current.identifier, id_hex, ephemeral_public_key_hex, nonce_hex, ciphertext_hex);
                        const signature = sign_message(privateKey, payload_hex);

                        pkgs_cipher_hex.push([id_hex, ephemeral_public_key_hex, nonce_hex, ciphertext_hex, signature]);
                    }

                    sendMessage({
                        type: 'Round2Submit',
                        payload: {
                            session: sessionIdRef.current,
                            id_hex: dkgState.current.identifier,
                            pkgs_cipher_hex: pkgs_cipher_hex
                        }
                    });
                    log('info', 'Round 2 encrypted packages submitted.');
                } catch (e: any) {
                    log('error', `DKG Part 2 failed: ${e.message}`);
                }
                break;

            case 'Round2All':
                log('info', 'Received all Round 2 packages. Finalizing...');
                try {
                    const received_packages = msg.payload.packages;
                    const decrypted_packages: any = {};
                    for (const [from_id_hex, eph_pub_hex, nonce_hex, ct_hex, _sig] of received_packages) {
                        const decrypted = ecies_decrypt(privateKey, eph_pub_hex, nonce_hex, ct_hex);
                        decrypted_packages[from_id_hex] = decrypted;
                    }

                    const r1_packages_for_part3 = { ...dkgState.current.all_r1_packages };
                    delete r1_packages_for_part3[dkgState.current.identifier];

                    const { key_package_hex, group_public_key_hex } = JSON.parse(dkg_part3(dkgState.current.r2_secret, r1_packages_for_part3, decrypted_packages));
                    setFinalShare(key_package_hex);
                    setFinalGroupKey(group_public_key_hex);
                    setDkgStatus('Finalized');
                    log('success', 'DKG Ceremony Complete!');

                    const payload_hex = get_auth_payload_finalize(sessionIdRef.current, dkgState.current.identifier, group_public_key_hex);
                    const signature = sign_message(privateKey, payload_hex);

                    sendMessage({ 
                        type: 'FinalizeSubmit', 
                        payload: { 
                            session: sessionIdRef.current, 
                            id_hex: dkgState.current.identifier, 
                            group_vk_sec1_hex: group_public_key_hex, 
                            sig_ecdsa_hex: signature
                        }
                    });

                } catch (e: any) {
                    log('error', `DKG Part 3 failed: ${e.message}`);
                }
                break;

            case 'Finalized':
                log('success', `Server confirmed finalization. Group Key: ${msg.payload.group_vk_sec1_hex}`);
                break;

            case 'Error':
                log('error', `Server error: ${msg.payload.message}`);
                setDkgStatus('Failed');
                break;

            default:
                log('info', `Received unhandled message type: ${msg.type}`);
                break;
        }
    };

    // --- Render ---
    return (
        <div className="App">
            <header>
                <h1>Tokamak-FROST DKG Web Client</h1>
            </header>

            <div className="grid-container">
                {/* Connection Panel */}
                <div className="panel">
                    <h2>1. Identity & Connection</h2>
                    <div className="form-group">
                        <label>Your Private Key</label>
                        <input type="password" value={privateKey} onChange={e => setPrivateKey(e.target.value)} disabled={isConnected} />
                    </div>
                    <div className="form-group">
                        <label>Your Public Key</label>
                        <input type="text" value={publicKey} onChange={e => setPublicKey(e.target.value)} disabled={isConnected} />
                    </div>
                    <button onClick={handleGenerateKeys} disabled={isConnected}>Generate New Keys</button>
                    <hr />
                    <div className="form-group">
                        <label>F-Server IP:Port</label>
                        <div style={{ display: 'flex', gap: '10px' }}>
                            <input type="text" value={ip} onChange={e => setIp(e.target.value)} disabled={isConnected} style={{ flex: 3 }} />
                            <input type="text" value={port} onChange={e => setPort(e.target.value)} disabled={isConnected} style={{ flex: 1 }} />
                        </div>
                    </div>
                    {isConnected ? (
                        <button onClick={handleDisconnect} className="disconnect-button">Disconnect</button>
                    ) : (
                        <button onClick={handleParticipantConnect} disabled={isCreator}>Connect to Participate</button>
                    )}
                    {dkgStatus === 'Connecting' && <p>Status: Connecting...</p>}
                </div>

                {/* Session Panel */}
                <div className="panel">
                    <h2>2. DKG Session</h2>
                    <div className="toggle-switch">
                        <span>Join Session</span>
                        <label className="switch">
                            <input type="checkbox" checked={isCreator} onChange={() => setIsCreator(!isCreator)} disabled={isConnected} />
                            <span className="slider"></span>
                        </label>
                        <span>Create Session</span>
                    </div>

                    {isCreator ? (
                        <div className="creator-panel">
                            <h3>Create New Session</h3>
                            <div className="form-group">
                                <label>Group ID</label>
                                <input type="text" value={groupId} onChange={e => setGroupId(e.target.value)} />
                            </div>
                            <div className="form-group">
                                <label>Min / Max Players</label>
                                <div style={{ display: 'flex', gap: '10px' }}>
                                    <input type="number" value={minSigners} onChange={e => setMinSigners(e.target.value)} min="2" />
                                    <input type="number" value={maxSigners} onChange={e => setMaxSigners(e.target.value)} min="2" />
                                </div>
                            </div>
                            <div className="form-group">
                                <label>Participant Roster</label>
                                <table className="roster-input-table">
                                    <thead>
                                        <tr>
                                            <th>UID</th>
                                            <th>Public Key</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {roster.map((entry, index) => (
                                            <tr key={index}>
                                                <td><input type="text" value={entry.uid} onChange={e => handleRosterChange(index, 'uid', e.target.value)} /></td>
                                                <td><input type="text" value={entry.pubkey} onChange={e => handleRosterChange(index, 'pubkey', e.target.value)} /></td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                            <button onClick={handleCreatorConnect} disabled={isConnected}>Create Session & Connect</button>
                        </div>
                    ) : (
                        <div className="participant-panel">
                            <h3>Join Existing Session</h3>
                            <button onClick={handleRefreshSessions} disabled={!isConnected}>Refresh Sessions</button>
                            {pendingSessions.length > 0 && (
                                <table className="sessions-table">
                                    <thead>
                                        <tr>
                                            <th>Session ID</th>
                                            <th>Group</th>
                                            <th>Progress</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {pendingSessions.map(s => (
                                            <tr key={s.session}>
                                                <td><code>{s.session}</code></td>
                                                <td>{s.group_id}</td>
                                                <td>{s.joined.length} / {s.max_signers}</td>
                                                <td><button onClick={() => handleJoinSession(s.session)}>Join</button></td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    )}

                    {sessionId && isCreator && (
                        <div className="session-id-display">
                            <p>Session Created! Share this ID with participants:</p>
                            <code>{sessionId}</code>
                        </div>
                    )}
                    
                    {totalParticipants > 0 && (
                        <div className="join-status">
                            <p>Participants Joined: {joinedCount} / {totalParticipants}</p>
                        </div>
                    )}

                    {joinedParticipants.length > 0 && (
                        <div className="participant-list">
                            <h4>Joined Participants:</h4>
                            <table className="participant-table">
                                <thead>
                                    <tr>
                                        <th>UID</th>
                                        <th>Public Key</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    {joinedParticipants.map(p => (
                                        <tr key={p.uid}>
                                            <td>{p.uid}</td>
                                            <td><code>{p.pubkey}</code></td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    )}
                </div>

                {/* Status & Results Panel */}
                <div className="panel">
                    <h2>3. Status & Results</h2>
                    <div className="status-indicator">
                        <div className={`light ${['Round2', 'Finalized'].includes(dkgStatus) ? 'active' : ''}`}></div>
                        <span>Round 1</span>
                    </div>
                    <div className="status-indicator">
                        <div className={`light ${dkgStatus === 'Finalized' ? 'active' : ''}`}></div>
                        <span>Round 2</span>
                    </div>
                    <div className="status-indicator">
                        <div className={`light ${dkgStatus === 'Finalized' ? 'active' : ''}`}></div>
                        <span>Finalized</span>
                    </div>

                    {finalShare && (
                        <div className="results-display">
                            <h3>Your Final Share (Secret)</h3>
                            <textarea readOnly value={finalShare} rows={6}></textarea>
                            <h3>Final Group Public Key</h3>
                            <textarea readOnly value={finalGroupKey} rows={4}></textarea>
                        </div>
                    )}
                </div>

                {/* Log Panel */}
                <div className="panel log-panel">
                    <div className="log-panel-header">
                        <h2>Logs</h2>
                        <button onClick={handleClearLogs} className="clear-logs-button">Clear</button>
                    </div>
                    <div className="log-view">
                        {logs.map((log, i) => (
                            <p key={i} className={log.level}>{`[${new Date().toLocaleTimeString()}] ${log.message}`}</p>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    );
}

export default App;
