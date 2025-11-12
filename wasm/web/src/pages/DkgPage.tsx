import { useState, useRef, useEffect } from 'react';
import { useAccount, useConnect, useDisconnect, useSignMessage } from 'wagmi';
import toast, { Toaster } from 'react-hot-toast';
import type { DkgStatus, LogEntry, Participant, PendingDKGSession } from '../types';
import { handleServerMessage, sendMessage, generateRandomKeys, deriveKeysFromMetaMask } from '../lib';
import init from '../../../pkg/tokamak_frost_wasm.js';
import '../App.css';

// ====================================================================
// region: Helper Components
// ====================================================================

const WalletSwitch = ({ isConnected, address, onConnect, onDisconnect }: { isConnected: boolean, address: string | undefined, onConnect: () => void, onDisconnect: () => void }) => {
    const truncateAddress = (addr: string) => `${addr.slice(0, 6)}...${addr.slice(-4)}`;

    return (
        <div className="wallet-switch-container">
            {isConnected && address && <span className="wallet-address">{truncateAddress(address)}</span>}
            <label className="switch">
                <input type="checkbox" checked={isConnected} onChange={isConnected ? onDisconnect : onConnect} />
                <span className="slider round"></span>
            </label>
        </div>
    );
};

const ResultsModal = ({ show, onClose, groupPublicKey }: { show: boolean, onClose: () => void, groupPublicKey: string }) => {
    if (!show) return null;

    return (
        <div className="modal-overlay">
            <div className="modal-content">
                <div className="success-animation">
                    <svg className="checkmark" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 52 52">
                        <circle className="checkmark__circle" cx="26" cy="26" r="25" fill="none" />
                        <path className="checkmark__check" fill="none" d="M14.1 27.2l7.1 7.2 16.7-16.8" />
                    </svg>
                </div>
                <h2>DKG Ceremony Complete!</h2>
                <p>The final group public key has been generated:</p>
                <textarea readOnly value={groupPublicKey} rows={4}></textarea>
                <button onClick={onClose}>Close</button>
            </div>
        </div>
    );
};

// ====================================================================
// region: Main App Component
// ====================================================================

function DkgPage() {
    // --- Wagmi Hooks ---
    const { address, isConnected: isMetaMaskConnected } = useAccount();
    const { connect, connectors } = useConnect();
    const { disconnect } = useDisconnect();
    const { signMessageAsync } = useSignMessage();

    // --- State for Connection & Keys ---
    const [ip, setIp] = useState('127.0.0.1');
    const [port, setPort] = useState('9034');
    const [privateKey, setPrivateKey] = useState('');
    const [publicKey, setPublicKey] = useState('');
    const [isServerConnected, setIsServerConnected] = useState(false);

    // --- State for DKG Ceremony ---
    const [isCreator, setIsCreator] = useState(false);
    const [groupId, setGroupId] = useState('my-frost-group');
    const [minSigners, setMinSigners] = useState('2');
    const [maxSigners, setMaxSigners] = useState('2');
    const [roster, setRoster] = useState<string[]>(Array.from({ length: 2 }, () => ''));
    const [sessionId, setSessionId] = useState('');
    const sessionIdRef = useRef(''); // Ref for immediate access
    const [dkgStatus, setDkgStatus] = useState<DkgStatus>('Idle');
    const [joinedCount, setJoinedCount] = useState(0);
    const [totalParticipants, setTotalParticipants] = useState(0);
    const [joinedParticipants, setJoinedParticipants] = useState<Participant[]>([]);
    const [pendingSessions, setPendingSessions] = useState<PendingDKGSession[]>([]);
    const [joiningSessionId, setJoiningSessionId] = useState<string | null>(null);
    const [showFinalKeyModal, setShowFinalKeyModal] = useState(false);

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
            const newRoster = Array.from({ length: num }, (_, i) => currentRoster[i] || '');
            return newRoster;
        });
    }, [maxSigners]);

    // --- Logging Utility ---
    const log = (level: LogEntry['level'], message: string) => {
        console.log(`[${level.toUpperCase()}] ${message}`);
        setLogs(prev => [...prev, { level, message }]);
    };

    // --- Core Functions ---
    const handleKeyGeneration = async () => {
        try {
            if (isMetaMaskConnected) {
                log('info', 'Deriving keys from MetaMask signature...');
                const derivedKeys = await deriveKeysFromMetaMask(signMessageAsync);
                setPrivateKey(derivedKeys.private_key_hex);
                setPublicKey(derivedKeys.public_key_hex);
                toast.success('Roster keys derived from MetaMask signature.');
            } else {
                log('info', 'Generating new random keys...');
                const keys = generateRandomKeys();
                setPrivateKey(keys.private_key_hex);
                setPublicKey(keys.public_key_hex);
                toast.success('New random ECDSA key pair generated.');
            }
        } catch (e: any) {
            toast.error(`Key generation/derivation failed: ${e.message}`);
        }
    };

    const handleMetaMaskToggle = () => {
        const injectedConnector = connectors.find(c => c.id === 'io.metamask' || c.id === 'injected');
        if (isMetaMaskConnected) {
            disconnect();
        } else if (injectedConnector) {
            connect({ connector: injectedConnector });
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

    const handleRosterChange = (index: number, value: string) => {
        const newRoster = [...roster];
        newRoster[index] = value;
        setRoster(newRoster);
    };

    const commonConnect = (onOpen: () => void) => {
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
            log('info', 'Already connected.');
            onOpen();
            return;
        }

        if (!privateKey || !publicKey) {
            toast.error('Please generate or provide keys before connecting.');
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
            handleServerMessage(serverMsg, { privateKey, publicKey, isCreator, dkgState, sessionIdRef }, {
                setSessionId,
                setDkgStatus,
                setPendingSessions,
                setJoinedCount,
                setTotalParticipants,
                setJoinedParticipants,
                setIsServerConnected,
                setFinalShare,
                setFinalGroupKey,
                setJoiningSessionId,
                setShowFinalKeyModal
            }, log, ws);
        };

        socket.onerror = (err) => {
            log('error', `WebSocket error: ${err.type}`);
            setIsServerConnected(false);
            setDkgStatus('Failed');
        };

        socket.onclose = () => {
            log('info', 'Disconnected from f-server.');
            setIsServerConnected(false);
            setDkgStatus('Idle');
            setJoinedCount(0);
            setTotalParticipants(0);
            setJoinedParticipants([]);
            setPendingSessions([]);
            setJoiningSessionId(null);
        };
    };

    const handleCreatorConnect = () => {
        setFinalShare('');
        setFinalGroupKey('');
        const min_signers = parseInt(minSigners);
        const max_signers = parseInt(maxSigners);

        if (min_signers > max_signers) {
            toast.error('Min players cannot be greater than Max players.');
            return;
        }

        if (roster.some(pubkey => pubkey.trim() === '')) {
            toast.error('All Public Key fields in the roster must be filled.');
            return;
        }

        const sortedPubKeys = [...roster].sort();
        const participants = sortedPubKeys.map((_, index) => index + 1);
        const participants_pubs = sortedPubKeys.map((pubkey, index) => [index + 1, pubkey]);

        if (participants.length !== max_signers) {
            toast.error(`Number of participants in roster must match Max Players (${max_signers}).`);
            return;
        }
        setTotalParticipants(max_signers);

        commonConnect(() => {
            log('info', 'Connected. Announcing session...');
            sendMessage(ws.current, {
                type: 'AnnounceSession',
                payload: {
                    group_id: groupId,
                    min_signers: min_signers,
                    max_signers: max_signers,
                    participants: participants,
                    participants_pubs: participants_pubs
                }
            }, log);
            setIsCreator(false);
        });
    };

    const handleParticipantConnect = () => {
        commonConnect(() => {
            log('info', 'Connected. Requesting challenge to log in...');
            sendMessage(ws.current, { type: 'RequestChallenge' }, log);
        });
    };

    const handleRefreshSessions = () => {
        log('info', 'Fetching list of pending DKG sessions...');
        sendMessage(ws.current, { type: 'ListPendingDKGSessions' }, log);
    };

    const handleJoinSession = (sessionToJoin: string) => {
        setFinalShare('');
        setFinalGroupKey('');
        setJoiningSessionId(sessionToJoin);
        log('info', `Joining session ${sessionToJoin}...`);
        sessionIdRef.current = sessionToJoin;
        sendMessage(ws.current, { type: 'JoinSession', payload: { session: sessionToJoin } }, log);
        setDkgStatus('Joined');
    };

    // --- Render ---
    return (
        <div className="App">
            <Toaster position="top-center" reverseOrder={false} />
            <ResultsModal show={showFinalKeyModal} onClose={() => setShowFinalKeyModal(false)} groupPublicKey={finalGroupKey} />
            <header className="App-header">
                <h1>Tokamak-FROST DKG Web Client</h1>
                <WalletSwitch
                    isConnected={isMetaMaskConnected}
                    address={address}
                    onConnect={handleMetaMaskToggle}
                    onDisconnect={handleMetaMaskToggle}
                />
            </header>

            <div className="grid-container">
                {/* Connection Panel */}
                <div className="panel">
                    <h2>1. Identity & Connection</h2>
                    <div className="form-group">
                        <label>Your Derived Private Key</label>
                        <input type="password" value={privateKey} onChange={e => setPrivateKey(e.target.value)} disabled={isServerConnected} />
                    </div>
                    <div className="form-group">
                        <label>Your Derived Public Key</label>
                        <input type="text" value={publicKey} onChange={e => setPublicKey(e.target.value)} disabled={isServerConnected} />
                    </div>
                    <button
                        onClick={handleKeyGeneration}
                        disabled={isServerConnected}
                        className={isMetaMaskConnected ? 'metamask-button' : 'generate-button'}
                    >
                        {isMetaMaskConnected ? 'Derive Roster Key' : 'Generate New Random Keys'}
                    </button>
                    <hr />
                    <div className="form-group">
                        <label>F-Server IP:Port</label>
                        <div style={{ display: 'flex', gap: '10px' }}>
                            <input type="text" value={ip} onChange={e => setIp(e.target.value)} disabled={isServerConnected} style={{ flex: 3 }} />
                            <input type="text" value={port} onChange={e => setPort(e.target.value)} disabled={isServerConnected} style={{ flex: 1 }} />
                        </div>
                    </div>
                    {isServerConnected ? (
                        <button onClick={handleDisconnect} className="disconnect-button">Disconnect</button>
                    ) : (
                        <button className="grey-button" onClick={handleParticipantConnect}>Connect & Login</button>
                    )}
                    {dkgStatus === 'Connecting' && <p>Status: Connecting...</p>}
                </div>

                {/* Session Panel */}
                <div className="panel">
                    <div className="panel-header">
                        <h2>2. DKG Session</h2>
                    </div>
                    <div className="toggle-switch">
                        <span>Join Session</span>
                        <label className="switch">
                            <input type="checkbox" checked={isCreator} onChange={() => setIsCreator(!isCreator)} />
                            <span className="slider round"></span>
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
                                            <th>Public Key</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {roster.map((pubkey, index) => (
                                            <tr key={index}>
                                                <td><input type="text" value={pubkey} onChange={e => handleRosterChange(index, e.target.value)} /></td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                            <button onClick={handleCreatorConnect} className="grey-button">Create Session & Connect</button>
                        </div>
                    ) : (
                        <div className="participant-panel">
                            <h3>Join Existing Session</h3>
                            <button onClick={handleRefreshSessions} className="grey-button" disabled={!isServerConnected}>Refresh Sessions</button>
                            {pendingSessions.length > 0 && (
                                <table className="sessions-table">
                                    <thead>
                                        <tr>
                                            <th>Session ID</th>
                                            <th>Group</th>
                                            <th>Created</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {pendingSessions.map(s => (
                                            <tr key={s.session}>
                                                <td><code>{s.session.slice(0, 8)}...</code></td>
                                                <td>{s.group_id}</td>
                                                <td>{new Date(s.created_at).toLocaleString()}</td>
                                                <td><button className="grey-button" onClick={() => handleJoinSession(s.session)} disabled={joiningSessionId !== null}>Join</button></td>
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

export default DkgPage;
