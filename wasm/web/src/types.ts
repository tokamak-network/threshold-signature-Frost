export type LogEntry = { level: 'info' | 'error' | 'success' | 'data'; message: string; };

// DKG Types
export type DkgStatus = 'Idle' | 'Connecting' | 'Connected' | 'SessionCreated' | 'Joined' | 'Round1' | 'Round2' | 'Finalized' | 'Failed';
export type Participant = { uid: number; pubkey: string; };
export type PendingDKGSession = {
    session: string;
    group_id: string;
    min_signers: number;
    max_signers: number;
    participants: number[];
    joined: number[];
    created_at: string;
};

// Signing Types
export type SigningStatus = 'Idle' | 'Connecting' | 'Connected' | 'SessionCreated' | 'Joined' | 'Round1' | 'Round2' | 'Complete' | 'Failed';
export type PendingSigningSession = {
    session: string;
    group_id: string;
    threshold: number;
    participants: number[];
    joined: number[];
    message_hex: string;
    participants_pubs: [number, string][];
    created_at: string;
};
