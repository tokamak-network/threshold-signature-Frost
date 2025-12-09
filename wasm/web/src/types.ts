export type LogEntry = { level: 'info' | 'error' | 'success' | 'data'; message: string; };

// DKG Types
export type DkgStatus = 'Idle' | 'Connecting' | 'Connected' | 'DKGSessionCreated' | 'Joined' | 'Round1' | 'Round2' | 'Finalized' | 'Failed';
export type Participant = { uid: number; pubkey: string; };
export type RosterPublicKey = string | { type: string; key: string };

export type PendingDKGSession = {
    session: string;
    creator_suid: number;
    group_id: string;
    min_signers: number;
    max_signers: number;
    participants: number[];
    participants_pubs: [number, RosterPublicKey][];
    joined: number[];
    created_at: string;
};
export type CompletedDKGSession = PendingDKGSession & {
    group_vk_sec1_hex: string;
};

// Signing Types
export type SigningStatus = 'Idle' | 'Connecting' | 'Connected' | 'SessionCreated' | 'Joined' | 'Round1' | 'Round2' | 'Complete' | 'Failed';
export type PendingSigningSession = {
    session: string;
    creator_suid: number;
    group_id: string;
    threshold: number;
    participants: number[];
    joined: number[];
    message: string;
    message_hex: string;
    participants_pubs: [number, RosterPublicKey][];
    created_at: string;
};
export type CompletedSigningSession = PendingSigningSession & {
    signature: string;
};
