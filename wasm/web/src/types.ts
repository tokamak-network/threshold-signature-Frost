export type LogEntry = { level: 'info' | 'error' | 'success' | 'data'; message: string; };
export type DkgStatus = 'Idle' | 'Connecting' | 'Connected' | 'SessionCreated' | 'Joined' | 'Round1' | 'Round2' | 'Finalized' | 'Failed';
export type Participant = { uid: number; pubkey: string; };
export type PendingDKGSession = {
    session: string;
    group_id: string;
    min_signers: number;
    max_signers: number;
    participants: number[];
    joined: number[];
};
