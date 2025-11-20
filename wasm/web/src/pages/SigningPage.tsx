import { useState, useRef, useEffect } from 'react';
import { useAccount, useConnect, useDisconnect, useSignMessage } from 'wagmi';
import toast, { Toaster } from 'react-hot-toast';
import type { SigningStatus, LogEntry, PendingSigningSession, CompletedSigningSession } from '../types';
import { handleSigningServerMessage, sendMessage, generateRandomKeys, deriveKeysFromMetaMask } from '../lib';
import init, { get_signing_prerequisites, get_key_package_metadata, keccak256 } from '../../../pkg/tokamak_frost_wasm.js';
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

const SessionDetailsModal = ({ session, onClose, zIndex }: { session: PendingSigningSession | CompletedSigningSession | null, onClose: () => void, zIndex: number }) => {
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
                <div className="detail-row">
                    <strong>Message:</strong>
                    <span>{session.message}</span>
                </div>
                <div className="detail-row">
                    <strong>Message Hash (Hex):</strong>
                    <code>{session.message_hex}</code>
                </div>
                {'signature' in session && (
                    <div className="detail-row">
                        <strong>Final Signature:</strong>
                        <textarea readOnly value={(session as CompletedSigningSession).signature} rows={4}></textarea>
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

const CompletedSessionsModal = ({ sessions, onClose, onSelect, zIndex }: { sessions: CompletedSigningSession[], onClose: () => void, onSelect: (session: CompletedSigningSession) => void, zIndex: number }) => {
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
                <h2>Completed Signing Sessions</h2>
                <table className="sessions-table">
                    <thead>
                        <tr>
                            <th>Session ID</th>
                            <th>Group</th>
                            <th>Message</th>
                            <th>Created</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {sessions.map(s => (
                            <tr key={s.session}>
                                <td><code>{s.session.slice(0, 8)}...</code></td>
                                <td>{s.group_id}</td>
                                <td>{s.message}</td>
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
// region: Main Signing Page Component
// ====================================================================

function SigningPage() {
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
    const [keyPackage, setKeyPackage] = useState('');
    const [mySuid, setMySuid] = useState<number | null>(null);

    // --- State for Signing Ceremony ---
    const [isCreator, setIsCreator] = useState(false);
    const [groupId, setGroupId] = useState('');
    const [threshold, setThreshold] = useState('');
    const [roster, setRoster] = useState<string[]>([]);
    const [messageToSign, setMessageToSign] = useState('hello frost');
    const [messageHash, setMessageHash] = useState('');
    const [groupVk, setGroupVk] = useState('');
    // @ts-expect-error
    const [sessionId, setSessionId] = useState('');
    const sessionIdRef = useRef('');
    const [signingStatus, setSigningStatus] = useState<SigningStatus>('Idle');
    const [pendingSessions, setPendingSessions] = useState<PendingSigningSession[]>([]);
    const [completedSessions, setCompletedSessions] = useState<CompletedSigningSession[]>([]);
    const [finalSignature, setFinalSignature] = useState('');
    const [joiningSessionId, setJoiningSessionId] = useState<string | null>(null);
    const [viewingSession, setViewingSession] = useState<PendingSigningSession | CompletedSigningSession | null>(null);
    const [showCompleted, setShowCompleted] = useState(false);
    const [modalStack, setModalStack] = useState<string[]>([]);

    // --- State for Logs ---
    const [logs, setLogs] = useState<LogEntry[]>([]);

    // --- Refs ---
    const ws = useRef<WebSocket | null>(null);
    const signingState = useRef<any>({});

    // --- Effects ---
    useEffect(() => {
        init().then(() => {
            log('info', 'WASM module initialized.');
        });
    }, []);

    useEffect(() => {
        if (keyPackage.trim() !== '' && publicKey) {
            try {
                const metadata = JSON.parse(get_key_package_metadata(keyPackage));
                setGroupId(metadata.group_id);
                setThreshold(metadata.threshold.toString());
                setGroupVk(metadata.group_public_key);
                const pubkeys = Object.values(metadata.roster) as string[];
                if (!pubkeys.includes(publicKey)) {
                    pubkeys.unshift(publicKey);
                }
                setRoster(pubkeys);
                toast.success('Key package metadata loaded!');
            } catch (e: any) {
                toast.error(`Invalid key package: ${e.message}`);
            }
        }
    }, [keyPackage, publicKey]);

    useEffect(() => {
        try {
            const hash = keccak256(messageToSign);
            setMessageHash(hash);
        } catch (e) {
            setMessageHash('');
        }
    }, [messageToSign]);

    useEffect(() => {
        if (viewingSession) {
            const allSessions = [...pendingSessions, ...completedSessions];
            const updatedSession = allSessions.find(s => s.session === viewingSession.session);
            if (updatedSession) {
                setViewingSession(updatedSession);
            }
        }
    }, [pendingSessions, completedSessions, viewingSession]);

    // --- Logging ---
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
                const derivedKeys = await deriveKeysFromMetaMask(signMessageAsync);
                setPrivateKey(derivedKeys.private_key_hex);
                setPublicKey(derivedKeys.public_key_hex);
                toast.success('Roster keys derived from MetaMask signature.');
            } else {
                const keys = generateRandomKeys();
                setPrivateKey(keys.private_key_hex);
                setPublicKey(keys.public_key_hex);
                toast.success('New random ECDSA key pair generated.');
            }
        } catch (e: any) {
            toast.error(`Key operation failed: ${e.message}`);
        }
    };

    const handleMetaMaskToggle = () => {
        const injectedConnector = connectors.find(c => c.id === 'io.metamask' || c.id === 'injected');
        if (isMetaMaskConnected) disconnect();
        else if (injectedConnector) connect({ connector: injectedConnector });
    };

    const handleConnect = () => {
        if (ws.current && ws.current.readyState === WebSocket.OPEN) {
            log('info', 'Already connected.');
            return;
        }
        if (!privateKey || !publicKey) {
            toast.error('Please generate or provide roster keys before connecting.');
            return;
        }
        const url = `ws://${ip}:${port}/ws`;
        log('info', `Connecting to ${url}...`);
        setSigningStatus('Connecting');
        const socket = new WebSocket(url);
        ws.current = socket;

        socket.onopen = () => {
            log('info', 'Connected. Requesting challenge to log in...');
            sendMessage(ws.current, { type: 'RequestChallenge' }, log);
        };

        socket.onmessage = (event) => {
            const serverMsg = JSON.parse(event.data);
            handleSigningServerMessage(serverMsg, { privateKey, publicKey, keyPackage, signingState, sessionIdRef }, {
                setSessionId,
                setSigningStatus,
                setPendingSessions,
                setCompletedSessions,
                setFinalSignature,
                setIsServerConnected,
                setMySuid,
            }, log, ws);
        };

        socket.onclose = () => {
            log('info', 'Disconnected from f-server.');
            setIsServerConnected(false);
            setSigningStatus('Idle');
            setJoiningSessionId(null);
        };
    };
    
    const handleDisconnect = () => {
        if (ws.current) {
            ws.current.close();
        }
    };

    const handleAnnounceSigning = () => {
        if (keyPackage.trim() === '') {
            toast.error('Please provide your DKG Secret Key Package.');
            return;
        }
        const thresholdNum = parseInt(threshold);
        if (isNaN(thresholdNum) || thresholdNum < 2) {
            toast.error('Threshold must be at least 2.');
            return;
        }
        if (roster.some(pk => pk.trim() === '')) {
            toast.error('All participant public keys must be filled.');
            return;
        }
        
        const participants = roster.map((_, i) => i + 1);
        const participants_pubs = roster.map((pubkey, i) => [i + 1, pubkey]);

        sendMessage(ws.current, {
            type: 'AnnounceSignSession',
            payload: {
                group_id: groupId,
                threshold: thresholdNum,
                participants,
                participants_pubs,
                group_vk_sec1_hex: groupVk,
                message: messageToSign,
                message_hex: messageHash,
            }
        }, log);
        setIsCreator(false);
    };

    const handleJoinSession = (session: string) => {
        if (keyPackage.trim() === '') {
            toast.error('Please provide your DKG Secret Key Package to join.');
            return;
        }
        try {
            setJoiningSessionId(session);
            sessionIdRef.current = session;
            const prereqs = JSON.parse(get_signing_prerequisites(keyPackage));
            sendMessage(ws.current, {
                type: 'JoinSignSession',
                payload: {
                    session,
                    signer_id_bincode_hex: prereqs.signer_id_bincode_hex,
                    verifying_share_bincode_hex: prereqs.verifying_share_bincode_hex,
                }
            }, log);

            if (mySuid) {
                setPendingSessions((prev: PendingSigningSession[]) => 
                    prev.map(s => 
                        s.session === session 
                            ? { ...s, joined: [...s.joined, mySuid] } 
                            : s
                    )
                );
            }
        } catch (e: any) {
            toast.error(`Failed to process key package: ${e.message}`);
        }
    };

    const handleViewCompleted = () => {
        log('info', 'Fetching list of completed signing sessions...');
        sendMessage(ws.current, { type: 'ListCompletedSigningSessions' }, log);
        setShowCompleted(true);
        openModal('completed');
    };

    const handleViewSessionDetails = (session: PendingSigningSession | CompletedSigningSession) => {
        setViewingSession(session);
        openModal('details');
    };

    return (
        <div className="App">
            <Toaster position="top-center" reverseOrder={false} />
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
                <h1>Tokamak-FROST Signing Ceremony</h1>
                <WalletSwitch
                    isConnected={isMetaMaskConnected}
                    address={address}
                    onConnect={handleMetaMaskToggle}
                    onDisconnect={handleMetaMaskToggle}
                />
            </header>

            <div className="grid-container">
                {/* Connection & Key Panel */}
                <div className="panel">
                    <h2>1. Identity & Keys</h2>
                    <div className="form-group">
                        <label>Your Roster Private Key</label>
                        <input type="password" value={privateKey} onChange={e => setPrivateKey(e.target.value)} disabled={isServerConnected} />
                    </div>
                    <div className="form-group">
                        <label>Your Roster Public Key</label>
                        <input type="text" value={publicKey} onChange={e => setPublicKey(e.target.value)} disabled={isServerConnected} />
                    </div>
                    <button onClick={handleKeyGeneration} disabled={isServerConnected} className={isMetaMaskConnected ? 'metamask-button' : 'generate-button'}>
                        {isMetaMaskConnected ? 'Derive Roster Key' : 'Generate New Random Keys'}
                    </button>
                    <hr />
                    <div className="form-group">
                        <label>Your DKG Secret Key Package</label>
                        <textarea value={keyPackage} onChange={e => setKeyPackage(e.target.value)} rows={4} placeholder="Paste your secret key package from the DKG ceremony..."></textarea>
                    </div>
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
                        <button onClick={handleConnect} className="grey-button">Connect & Login</button>
                    )}
                </div>

                {/* Signing Session Panel */}
                <div className="panel">
                    <div className="panel-header">
                        <h2>2. Signing Session</h2>
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
                            <h3>Create New Signing Session</h3>
                            <div className="form-group">
                                <label>Group ID</label>
                                <input type="text" value={groupId} disabled />
                            </div>
                            <div className="form-group">
                                <label>Message to Sign</label>
                                <input type="text" value={messageToSign} onChange={e => setMessageToSign(e.target.value)} />
                            </div>
                            <div className="form-group">
                                <label>Data to Sign (Keccak256 Hash)</label>
                                <input type="text" value={messageHash} readOnly disabled />
                            </div>
                            <div className="form-group">
                                <label>Group Public Key (from DKG)</label>
                                <input type="text" value={groupVk} disabled />
                            </div>
                            <div className="form-group">
                                <label>Threshold</label>
                                <input type="number" value={threshold} disabled />
                            </div>
                            <div className="form-group">
                                <label>Participant Roster (Public Keys)</label>
                                <table className="roster-input-table">
                                    <thead>
                                        <tr>
                                            <th>Public Key</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {roster.map((pubkey, index) => (
                                            <tr key={index}>
                                                <td><input type="text" value={pubkey} disabled /></td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                            <button onClick={handleAnnounceSigning} className="grey-button" disabled={!isServerConnected || keyPackage.trim() === '' || signingStatus !== 'Connected' || messageHash.trim() === ''}>Announce Signing Session</button>
                        </div>
                    ) : (
                        <div className="participant-panel">
                            <h3>Join Existing Session</h3>
                            <div className="button-group">
                                <button onClick={() => sendMessage(ws.current, { type: 'ListPendingSigningSessions' }, log)} className="grey-button" disabled={!isServerConnected}>Refresh Sessions</button>
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
                                                <td><button onClick={() => handleJoinSession(s.session)} className="grey-button" disabled={joiningSessionId !== null || keyPackage.trim() === ''}>Join</button></td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            )}
                        </div>
                    )}
                </div>

                {/* Status & Results Panel */}
                <div className="panel">
                    <h2>3. Status & Signature</h2>
                    {/* Status indicators will be added here */}
                    {finalSignature && (
                        <div className="results-display">
                            <h3>Final Aggregated Signature</h3>
                            <textarea readOnly value={finalSignature} rows={6}></textarea>
                        </div>
                    )}
                </div>

                {/* Log Panel */}
                <div className="panel log-panel">
                    <div className="log-panel-header">
                        <h2>Logs</h2>
                        <button onClick={() => setLogs([])} className="clear-logs-button">Clear</button>
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

export default SigningPage;
