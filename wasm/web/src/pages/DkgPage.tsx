import { useState, useRef, useEffect } from 'react';
import { useAccount, useConnect, useDisconnect, useSignMessage } from 'wagmi';
import toast, { Toaster } from 'react-hot-toast';
import type { DkgStatus, LogEntry, Participant, PendingDKGSession, CompletedDKGSession } from '../types';
import { handleServerMessage, sendMessage, generateRandomKeys, deriveKeysFromMetaMask } from '../lib';
import init, { encrypt_share } from '../../../pkg/tokamak_frost_wasm.js';
import '../App.css';
import { useModal } from '../useModal';

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
    const { position, modalRef, onMouseDown, onMouseMove, onMouseUp } = useModal();

    if (!show) return null;

    return (
        <div className="modal-overlay" onMouseMove={onMouseMove} onMouseUp={onMouseUp}>
            <div
                ref={modalRef}
                className="modal-content"
                style={{ top: position.y, left: position.x, cursor: 'move' }}
                onMouseDown={onMouseDown}
            >
                <div className="success-animation">
                    <svg className="checkmark" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 52 52">
                        <circle className="checkmark__circle" cx="26" cy="26" r="25" fill="none" />
                        <path className="checkmark__check" fill="none" d="M14.1 27.2l7.1 7.2 16.7-16.8" />
                    </svg>
                </div>
                <h2>DKG Ceremony Complete!</h2>
                <p>The final group public key has been generated:</p>
                <textarea readOnly value={groupPublicKey} rows={4}></textarea>
                <button onClick={onClose} className="grey-button">Close</button>
            </div>
        </div>
    );
};

const SessionDetailsModal = ({ session, onClose, zIndex }: { session: PendingDKGSession | CompletedDKGSession | null, onClose: () => void, zIndex: number }) => {
    const { position, modalRef, onMouseDown, onMouseMove, onMouseUp } = useModal();

    if (!session) return null;

    const handleCopy = (text: string) => {
        navigator.clipboard.writeText(text);
        toast.success('Copied to clipboard!');
    };

    return (
        <div className="modal-overlay" style={{ zIndex }} onMouseMove={onMouseMove} onMouseUp={onMouseUp}>
            <div
                ref={modalRef}
                className="modal-content session-details-modal"
                style={{ top: position.y, left: position.x, cursor: 'move' }}
                onMouseDown={onMouseDown}
            >
                <h2>Session Details</h2>
                <div className="detail-row">
                    <strong>Session ID:</strong>
                    <code>{session.session}</code>
                </div>
                <div className="detail-row">
                    <strong>Group ID:</strong>
                    <span>{session.group_id}</span>
                </div>
                {'group_vk_sec1_hex' in session && (
                    <div className="detail-row">
                        <strong>Group Public Key:</strong>
                        <textarea readOnly value={(session as CompletedDKGSession).group_vk_sec1_hex} rows={4}></textarea>
                    </div>
                )}
                <div className="detail-row">
                    <strong>Participants:</strong>
                    <table className="participant-table">
                        <thead>
                            <tr>
                                <th>SUID</th>
                                <th>Roster Public Key</th>
                                <th>Copy</th>
                                <th>Joined</th>
                            </tr>
                        </thead>
                        <tbody>
                            {session.participants_pubs.map(([suid, pubkey]) => (
                                <tr key={suid}>
                                    <td>{suid}{session.creator_suid === suid ? ' (Creator)' : ''}</td>
                                    <td><code title={pubkey}>{`${pubkey.slice(0, 10)}...${pubkey.slice(-8)}`}</code></td>
                                    <td>
                                        <button onClick={() => handleCopy(pubkey)} className="copy-button">
                                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                                        </button>
                                    </td>
                                    <td className="status-cell">
                                        {session.joined.includes(suid) ? (
                                            <span className="status-ok">✓</span>
                                        ) : (
                                            <span className="status-err">✗</span>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
                <button onClick={onClose} className="grey-button">Close</button>
            </div>
        </div>
    );
};

const CompletedSessionsModal = ({ sessions, onClose, onSelect, zIndex }: { sessions: CompletedDKGSession[], onClose: () => void, onSelect: (session: CompletedDKGSession) => void, zIndex: number }) => {
    const { position, modalRef, onMouseDown, onMouseMove, onMouseUp } = useModal();

    if (sessions.length === 0) return null;

    return (
        <div className="modal-overlay" style={{ zIndex }} onMouseMove={onMouseMove} onMouseUp={onMouseUp}>
            <div
                ref={modalRef}
                className="modal-content session-details-modal"
                style={{ top: position.y, left: position.x, cursor: 'move' }}
                onMouseDown={onMouseDown}
            >
                <h2>Completed DKG Sessions</h2>
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
                        {sessions.map(s => (
                            <tr key={s.session}>
                                <td><code>{s.session.slice(0, 8)}...</code></td>
                                <td>{s.group_id}</td>
                                <td>{new Date(s.created_at).toLocaleString()}</td>
                                <td><button className="grey-button" onClick={() => onSelect(s)}>View</button></td>
                            </tr>
                        ))}
                    </tbody>
                </table>
                <button onClick={onClose} className="grey-button">Close</button>
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
    const [aesKey, setAesKey] = useState('');
    const [isServerConnected, setIsServerConnected] = useState(false);
    const [mySuid, setMySuid] = useState<number | null>(null);

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
    const [completedSessions, setCompletedSessions] = useState<CompletedDKGSession[]>([]);
    const [joiningSessionId, setJoiningSessionId] = useState<string | null>(null);
    const [showFinalKeyModal, setShowFinalKeyModal] = useState(false);
    const [viewingSession, setViewingSession] = useState<PendingDKGSession | CompletedDKGSession | null>(null);
    const [showCompleted, setShowCompleted] = useState(false);
    const [modalStack, setModalStack] = useState<string[]>([]);

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

    useEffect(() => {
        if (isCreator && publicKey) {
            setRoster(currentRoster => {
                const newRoster = [...currentRoster];
                newRoster[0] = publicKey;
                return newRoster;
            });
        }
    }, [isCreator, publicKey]);

    useEffect(() => {
        if (viewingSession) {
            const allSessions = [...pendingSessions, ...completedSessions];
            const updatedSession = allSessions.find(s => s.session === viewingSession.session);
            if (updatedSession) {
                setViewingSession(updatedSession);
            }
        }
    }, [pendingSessions, completedSessions, viewingSession]);

    // --- Logging Utility ---
    const log = (level: LogEntry['level'], message: string) => {
        console.log(`[${level.toUpperCase()}] ${message}`);
        setLogs(prev => [...prev, { level, message }]);
    };

    // --- Modal Management ---
    const openModal = (modalId: string) => {
        setModalStack(prev => [...prev, modalId]);
    };

    const closeModal = (modalId: string) => {
        setModalStack(prev => prev.filter(id => id !== modalId));
    };

    const getZIndex = (modalId: string) => {
        return modalStack.indexOf(modalId) + 100;
    };

    // --- Core Functions ---
    const handleKeyGeneration = async () => {
        try {
            if (isMetaMaskConnected) {
                log('info', 'Deriving keys from MetaMask signature...');
                const derivedKeys = await deriveKeysFromMetaMask(signMessageAsync);
                setPrivateKey(derivedKeys.private_key_hex);
                setPublicKey(derivedKeys.public_key_hex);
                setAesKey(derivedKeys.aes_key_hex);
                toast.success('Roster and AES keys derived from MetaMask signature.');
            } else {
                log('info', 'Generating new random keys...');
                const keys = generateRandomKeys();
                setPrivateKey(keys.private_key_hex);
                setPublicKey(keys.public_key_hex);
                setAesKey(''); // No AES key for random generation
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

    const handleConnect = () => {
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
            log('info', 'Already connected.');
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

        socket.onopen = () => {
            log('info', 'Connected. Requesting challenge to log in...');
            sendMessage(ws.current, { type: 'RequestChallenge' }, log);
        };

        socket.onmessage = (event) => {
            log('data', `Received: ${event.data}`);
            const serverMsg = JSON.parse(event.data);
            handleServerMessage(serverMsg, { privateKey, publicKey, isCreator, dkgState, sessionIdRef }, {
                setSessionId,
                setDkgStatus,
                setPendingSessions,
                setCompletedSessions,
                setJoinedCount,
                setTotalParticipants,
                setJoinedParticipants,
                setIsServerConnected,
                setFinalShare,
                setFinalGroupKey,
                setJoiningSessionId,
                setShowFinalKeyModal,
                setMySuid,
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

    const handleAnnounceDKG = () => {
        setFinalShare('');
        setFinalGroupKey('');
        const min_signers = parseInt(minSigners);
        const max_signers = parseInt(maxSigners);

        if (min_signers > max_signers) {
            toast.error('Min players cannot be greater than Max players.');
            return;
        }

        if (roster.some(pubkey => pubkey.trim() === '') || roster.length !== max_signers) {
            toast.error(`All Public Key fields in the roster must be filled and match Max Players (${max_signers}).`);
            return;
        }

        const sortedPubKeys = [...roster].sort();
        const participants = sortedPubKeys.map((_, index) => index + 1);
        const participants_pubs = sortedPubKeys.map((pubkey, index) => [index + 1, pubkey]);

        setTotalParticipants(max_signers);

        log('info', 'Announcing DKG session...');
        sendMessage(ws.current, {
            type: 'AnnounceDKGSession',
            payload: {
                group_id: groupId,
                min_signers: min_signers,
                max_signers: max_signers,
                participants: participants,
                participants_pubs: participants_pubs
            }
        }, log);
        setIsCreator(false);
    };

    const handleRefreshSessions = () => {
        log('info', 'Fetching list of pending DKG sessions...');
        sendMessage(ws.current, { type: 'ListPendingDKGSessions' }, log);
    };

    const handleViewCompleted = () => {
        log('info', 'Fetching list of completed DKG sessions...');
        sendMessage(ws.current, { type: 'ListCompletedDKGSessions' }, log);
        setShowCompleted(true);
        openModal('completed');
    };

    const handleJoinSession = (sessionToJoin: string) => {
        setFinalShare('');
        setFinalGroupKey('');
        setJoiningSessionId(sessionToJoin);
        log('info', `Joining DKG session ${sessionToJoin}...`);
        sessionIdRef.current = sessionToJoin;
        sendMessage(ws.current, { type: 'JoinDKGSession', payload: { session: sessionToJoin } }, log);
        setDkgStatus('Joined');

        if (mySuid) {
            setPendingSessions((prev: PendingDKGSession[]) => 
                prev.map(s => 
                    s.session === sessionToJoin 
                        ? { ...s, joined: [...s.joined, mySuid] } 
                        : s
                )
            );
        }
    };

    const handleViewSessionDetails = (session: PendingDKGSession | CompletedDKGSession) => {
        setViewingSession(session);
        openModal('details');
    };

    const handleDownloadKey = () => {
        if (!finalShare || !finalGroupKey) {
            toast.error('No final key to download.');
            return;
        }

        const keyData = {
            finalShare: JSON.parse(finalShare), // The share is already a JSON string of the encrypted object
            finalGroupKey,
        };

        const blob = new Blob([JSON.stringify(keyData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'frost-key.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        log('info', 'Downloaded frost-key.json.');
    };

    useEffect(() => {
        // Check if the share is finalized, an AES key is available, and the share is not already encrypted
        const isPlaintextHex = (str: string) => /^[0-9a-fA-F]+$/.test(str);

        if (dkgStatus === 'Finalized' && finalShare && aesKey && isPlaintextHex(finalShare)) {
            try {
                const encrypted = encrypt_share(aesKey, finalShare);
                setFinalShare(encrypted);
                log('success', 'Final share has been encrypted.');
            } catch (e: any) {
                log('error', `Failed to encrypt final share: ${e.message}`);
                toast.error('Failed to encrypt the final share.');
            }
        }
    }, [dkgStatus, finalShare, aesKey]);

    // --- Render ---
    return (
        <div className="App">
            <Toaster position="top-center" reverseOrder={false} />
            <ResultsModal show={showFinalKeyModal} onClose={() => setShowFinalKeyModal(false)} groupPublicKey={finalGroupKey} />
            {viewingSession && (
                <SessionDetailsModal
                    session={viewingSession}
                    onClose={() => {
                        setViewingSession(null);
                        closeModal('details');
                    }}
                    zIndex={getZIndex('details')}
                />
            )}
            {showCompleted && (
                <CompletedSessionsModal
                    sessions={completedSessions}
                    onClose={() => {
                        setShowCompleted(false);
                        closeModal('completed');
                    }}
                    onSelect={(s) => {
                        handleViewSessionDetails(s);
                    }}
                    zIndex={getZIndex('completed')}
                />
            )}
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
                        <button className="grey-button" onClick={handleConnect}>Connect & Login</button>
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
                                <input type="text" value={groupId} onChange={e => setGroupId(e.target.value)} disabled={!isServerConnected} />
                            </div>
                            <div className="form-group">
                                <label>Min / Max Players</label>
                                <div style={{ display: 'flex', gap: '10px' }}>
                                    <input type="number" value={minSigners} onChange={e => setMinSigners(e.target.value)} min="2" disabled={!isServerConnected} />
                                    <input type="number" value={maxSigners} onChange={e => setMaxSigners(e.target.value)} min="2" disabled={!isServerConnected} />
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
                                                <td><input type="text" value={pubkey} onChange={e => handleRosterChange(index, e.target.value)} disabled={!isServerConnected} /></td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                            <button onClick={handleAnnounceDKG} className="grey-button" disabled={!isServerConnected}>Announce DKG Session</button>
                        </div>
                    ) : (
                        <div className="participant-panel">
                            <h3>Join Existing Session</h3>
                            <div className="button-group">
                                <button onClick={handleRefreshSessions} className="grey-button" disabled={!isServerConnected}>Refresh Sessions</button>
                                <button onClick={handleViewCompleted} className="grey-button" disabled={!isServerConnected}>Completed Sessions</button>
                            </div>
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
                                                <td><button className="link-button" onClick={() => handleViewSessionDetails(s)}>{s.session.slice(0, 8)}...</button></td>
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
                            <p>DKG Session Created! Share this ID with participants:</p>
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
                            <h3>Your Final Share (Encrypted)</h3>
                            <textarea readOnly value={finalShare} rows={6}></textarea>
                            <h3>Final Group Public Key</h3>
                            <textarea readOnly value={finalGroupKey} rows={4}></textarea>
                            <button onClick={handleDownloadKey} className="grey-button">Download Key File</button>
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
