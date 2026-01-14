export type RosterPublicKey =
    | { type: 'Secp256k1', key: string }
    | { type: 'EdwardsOnBls12381', key: string }
    | string; // For backward compatibility if needed, though robust clients send objects

export interface EncryptedPayload {
    ephemeral_public_key: RosterPublicKey;
    nonce: string;
    ciphertext: string;
}

// ----------------------------------------------------------------------------
// Client Messages (Client -> Server)
// ----------------------------------------------------------------------------

export type ClientMsg =
    | { type: 'AnnounceDKGSession', payload: { min_signers: number; max_signers: number; group_id: string; participants: number[]; participants_pubs: [number, RosterPublicKey][] } }
    | { type: 'RequestChallenge', payload: null }
    | { type: 'Login', payload: { challenge: string; public_key: RosterPublicKey; signature_hex: string } }
    | { type: 'Logout', payload: null }
    | { type: 'JoinDKGSession', payload: { session: string } }
    | { type: 'ListPendingDKGSessions', payload: null }
    | { type: 'ListCompletedDKGSessions', payload: null }
    | { type: 'ListPendingSigningSessions', payload: null }
    | { type: 'ListCompletedSigningSessions', payload: null }
    // DKG Rounds
    | { type: 'Round1Submit', payload: { session: string; id_hex: string; pkg_bincode_hex: string; signature_hex: string } }
    | { type: 'Round2Submit', payload: { session: string; id_hex: string; pkgs_cipher: [string, EncryptedPayload, string][] } } // [recipient_id, payload, signature]
    | { type: 'FinalizeSubmit', payload: { session: string; id_hex: string; group_vk_sec1_hex: string; signature_hex: string } }
    // Signing
    | { type: 'AnnounceSignSession', payload: { group_id: string; threshold: number; participants: number[]; participants_pubs: [number, RosterPublicKey][]; group_vk_sec1_hex: string; message: string; message_hex: string } }
    | { type: 'JoinSignSession', payload: { session: string; signer_id_bincode_hex: string; verifying_share_bincode_hex: string } }
    | { type: 'SignRound1Submit', payload: { session: string; id_hex: string; commitments_bincode_hex: string; signature_hex: string } }
    | { type: 'SignRound2Submit', payload: { session: string; id_hex: string; signature_share_bincode_hex: string; signature_hex: string } };

// ----------------------------------------------------------------------------
// Server Messages (Server -> Client)
// ----------------------------------------------------------------------------

export type ServerMsg =
    | { type: 'Error', payload: { message: string } }
    | { type: 'Info', payload: { message: string } }
    | { type: 'SessionAborted', payload: { session: string; reason: string } }
    | { type: 'Challenge', payload: { challenge: string } }
    | { type: 'LoginOk', payload: { principal: string; suid: number; access_token: string } }

    // DKG Session Updates
    | { type: 'DKGSessionCreated', payload: { session: string } }
    | { type: 'NewDKGSession', payload: any } // Broadcast to all users when a new session is created
    | { type: 'PendingDKGSessions', payload: { sessions: any[] } } // Using 'any' for now, can refine DKGSessionSummary
    | { type: 'CompletedDKGSessions', payload: { sessions: any[] } }

    // DKG Protocol
    | { type: 'ReadyRound1', payload: { session: string; group_id: string; min_signers: number; max_signers: number; roster: [number, string, RosterPublicKey][]; id_hex: string } }
    | { type: 'Round1All', payload: { session: string; packages: [string, string, string][] } } // [id_hex, pkg_hex, sig_hex]
    | { type: 'ReadyRound2', payload: { session: string; participants: string[] } }
    | { type: 'Round2All', payload: { session: string; packages: [string, EncryptedPayload, string][] } } // [from_id_hex, payload, sig_hex]
    | { type: 'Finalized', payload: { session: string; group_vk_sec1_hex: string } }

    // Signing Session Updates
    | { type: 'SignSessionCreated', payload: { session: string } }
    | { type: 'NewSignSession', payload: any } // Broadcast to all users when a new session is created
    | { type: 'SignSessionAnnounced', payload: any }
    | { type: 'PendingSigningSessions', payload: { sessions: any[] } }
    | { type: 'CompletedSigningSessions', payload: { sessions: any[] } }
    | { type: 'SignSessionJoined', payload: { session: string } } // Verified in code, this exists

    // Signing Protocol
    | { type: 'SignReadyRound1', payload: { session: string; group_id: string; threshold: number; participants: number; roster: [number, string, RosterPublicKey][]; msg_keccak32_hex: string } }
    | { type: 'SignRound1All', payload: { session: string; commitments: [string, string, string][] } } // Not strictly sent but useful
    | { type: 'SignSigningPackage', payload: { session: string; signing_package_bincode_hex: string } } // AKA ReadyRound2 equiv
    | { type: 'SignReadyRound2', payload: any } // Maybe not used if SignSigningPackage is the trigger
    | { type: 'SignatureReady', payload: { session: string; signature_bincode_hex: string; message: string; rx: string; ry: string; s: string; px: string; py: string } };

// ----------------------------------------------------------------------------
// Internal State
// ----------------------------------------------------------------------------

export interface Participant {
    uid: number; // session-unique ID
    socketId: string; // Connection ID
    pubKeyProp?: RosterPublicKey; // Normalized public key object
    frostIdHex?: string; // Derived later
}

// DKG Session State
export interface DKGSession {
    id: string;
    creatorSocketId: string;
    min_signers: number;
    max_signers: number;
    group_id: string;
    participants_config: number[]; // allowed UIDs (simple 1..N)
    participants_pubs: [number, RosterPublicKey][]; // Configured public keys

    // Active state
    joined_participants: Map<number, Participant>; // Map UID -> Participant

    state: 'Pending' | 'Round1' | 'Round2' | 'Finalized' | 'Failed';

    // Round Data
    round1_packages: Map<string, { pkg: string; sig: string }>; // id_hex -> data
    round2_packages: Map<string, [string, EncryptedPayload, string][]>; // recipient_id -> list of incoming packages

    final_group_key?: string;
    finalized_uids?: Set<number>; // Track which participants have finalized
    created_at: number;
}

// Signing Session State
export interface SignSession {
    id: string;
    creatorSocketId: string;
    group_id: string;
    threshold: number;

    participants_config: number[]; // expected SUIDs (1..N from original DKG usually, or arbitrary)
    participants_pubs: [number, RosterPublicKey][];

    message: string;
    message_hex: string;
    group_vk_sec1_hex: string;

    // Active state
    joined_participants: Map<number, Participant & { signer_id_hex?: string; verifying_share?: string }>;

    state: 'Pending' | 'Round1' | 'Round2' | 'Complete' | 'Failed';

    // Round Data
    round1_commitments: Map<string, { commitment: string; sig: string }>; // id_hex -> data
    round2_shares: Map<string, { share: string; sig: string }>; // id_hex -> data

    created_at: number;

    // Aggregated results
    signing_package?: string; // Generated after R1
    final_signature?: string;
}
