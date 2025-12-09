/*!
tokamak-frost — Distributed Key Generation (DKG)
-------------------------------------------------
This binary contains a WebSocket coordinator (**server-only**).
It orchestrates the message exchange for the three-round FROST DKG
and enforces authentication/authorization for packets.

The server exposes `/close` for graceful shutdown in 3 seconds.
*/

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::SocketAddr,
    sync::Arc,
};

use anyhow::{anyhow, Context, Result};
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::IntoResponse;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::State,
    routing::get,
    Router,
};
use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use frost_core::Field;
use frost_secp256k1 as frost;
use futures::{sink::SinkExt, stream::StreamExt};
use k256::ecdsa::VerifyingKey as EcdsaVerifyingKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::{sleep, Duration};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use helper::{
    auth_payload_finalize, auth_payload_round1, auth_payload_sign_r1, auth_payload_sign_r2,
    EncryptedPayload, RosterPublicKey,
};

// ========================= CLI =========================

#[derive(Debug, Parser)]
#[command(
    name = "fserver",
    author,
    version,
    about = "DKG coordinator (server-only, FROST secp256k1)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the coordinator (WebSocket server)
    Server {
        /// Bind address, e.g. 127.0.0.1:9000
        #[arg(long, default_value = "127.0.0.1:9000")]
        bind: SocketAddr,
    },
}

// ========================= Messages =========================

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
enum ClientMsg {
    /// Creator announces parameters; server generates a unique session id.
    AnnounceDKGSession {
        min_signers: u16,
        max_signers: u16,
        group_id: String,
        participants: Vec<u32>, // session-local IDs (suid)
        participants_pubs: Vec<(u32, RosterPublicKey)>,
    },
    RequestChallenge,
    Login {
        challenge: String,
        public_key: RosterPublicKey,
        signature_hex: String,
    },
    Logout,
    JoinDKGSession {
        session: String,
    },
    /// List DKG sessions the caller can join (still pending/finalizing)
    ListPendingDKGSessions,
    ListCompletedDKGSessions,
    /// List Signing sessions the caller can join (still pending/not all joined)
    ListPendingSigningSessions,
    ListCompletedSigningSessions,

    // DKG round messages
    Round1Submit {
        session: String,
        id_hex: String,
        pkg_bincode_hex: String,
        signature_hex: String,
    },
    Round2Submit {
        session: String,
        id_hex: String,
        // (recipient_id_hex, EncryptedPayload, signature_hex)
        pkgs_cipher: Vec<(String, EncryptedPayload, String)>,
    },
    FinalizeSubmit {
        session: String,
        id_hex: String,
        group_vk_sec1_hex: String,
        signature_hex: String,
    },

    // ---- Interactive signing (new) ----
    AnnounceSignSession {
        group_id: String,
        threshold: u16,
        participants: Vec<u32>,
        participants_pubs: Vec<(u32, RosterPublicKey)>,
        group_vk_sec1_hex: String,
        message: String,
        message_hex: String,
    },
    JoinSignSession {
        session: String,
        signer_id_bincode_hex: String,
        verifying_share_bincode_hex: String,
    },
    SignRound1Submit {
        session: String,
        id_hex: String,
        commitments_bincode_hex: String,
        signature_hex: String,
    },
    SignRound2Submit {
        session: String,
        id_hex: String,
        signature_share_bincode_hex: String,
        signature_hex: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
enum ServerMsg {
    Error {
        message: String,
    },
    Info {
        message: String,
    },
    Challenge {
        challenge: String,
    },
    // principal = canonical JSON of the user's RosterPublicKey
    LoginOk {
        principal: String,
        suid: u32,
        access_token: String,
    },

    /// Returned in response to ClientMsg::ListPendingDKGSessions
    PendingDKGSessions {
        sessions: Vec<PendingDKGSession>,
    },
    CompletedDKGSessions {
        sessions: Vec<CompletedDKGSession>,
    },
    /// Returned in response to ClientMsg::ListPendingSigningSessions
    PendingSigningSessions {
        sessions: Vec<PendingSignSession>,
    },
    CompletedSigningSessions {
        sessions: Vec<CompletedSigningSession>,
    },

    /// Sent to the creator after a successful AnnounceDKGSession
    DKGSessionCreated {
        session: String,
    },

    // Signals
    ReadyRound1 {
        session: String,
        id_hex: String,
        min_signers: u16,
        max_signers: u16,
        group_id: String,
        // (suid, id_hex, RosterPublicKey)
        roster: Vec<(u32, String, RosterPublicKey)>,
    },
    Round1All {
        session: String,
        // (id_hex, pkg_bincode_hex, signature_hex)
        packages: Vec<(String, String, String)>,
    },
    ReadyRound2 {
        session: String,
    },
    Round2All {
        session: String,
        // (from_id_hex, EncryptedPayload, signature_hex)
        packages: Vec<(String, EncryptedPayload, String)>,
    },
    Finalized {
        session: String,
        group_vk_sec1_hex: String,
    },

    // ---- Interactive signing (new) ----
    SignSessionCreated {
        session: String,
    },
    SignReadyRound1 {
        session: String,
        group_id: String,
        threshold: u16,
        participants: u16,
        msg_keccak32_hex: String,
        // (suid, id_hex, RosterPublicKey)
        roster: Vec<(u32, String, RosterPublicKey)>,
    },
    SignSigningPackage {
        session: String,
        signing_package_bincode_hex: String,
    },
    SignatureReady {
        session: String,
        signature_bincode_hex: String,
        px: String,
        py: String,
        rx: String,
        ry: String,
        s: String,
        message: String,
    },
}

// Used by ServerMsg::PendingDKGSessions
#[derive(Debug, Serialize, Deserialize, Clone)]
struct PendingDKGSession {
    session: String,
    creator_suid: u32,
    group_id: String,
    min_signers: u16,
    max_signers: u16,
    participants: Vec<u32>,
    participants_pubs: Vec<(u32, RosterPublicKey)>,
    joined: Vec<u32>,
    created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CompletedDKGSession {
    session: String,
    creator_suid: u32,
    group_id: String,
    min_signers: u16,
    max_signers: u16,
    participants: Vec<u32>,
    participants_pubs: Vec<(u32, RosterPublicKey)>,
    joined: Vec<u32>,
    created_at: String,
    group_vk_sec1_hex: String,
}

// Used by ServerMsg::PendingSigningSessions
#[derive(Debug, Serialize, Deserialize, Clone)]
struct PendingSignSession {
    session: String,
    creator_suid: u32,
    group_id: String,
    threshold: u16,
    participants: Vec<u32>,
    joined: Vec<u32>,
    message: String,
    message_hex: String,
    participants_pubs: Vec<(u32, RosterPublicKey)>,
    created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CompletedSigningSession {
    session: String,
    creator_suid: u32,
    group_id: String,
    threshold: u16,
    participants: Vec<u32>,
    joined: Vec<u32>,
    message: String,
    message_hex: String,
    participants_pubs: Vec<(u32, RosterPublicKey)>,
    created_at: String,
    signature: String,
}

// ========================= Coordinator State =========================

type Tx = mpsc::UnboundedSender<Message>;

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<Inner>>,
    shutdown: Arc<Notify>,
}

struct Inner {
    // active connections by principal
    conns: HashMap<String, Tx>,
    // active challenges to prevent reuse
    challenges: HashSet<String>,
    // active tokens
    active_tokens: HashMap<String, String>, // token -> principal
    // dkg sessions
    sessions: HashMap<String, DKGSession>,
    completed_dkg_sessions: HashMap<String, CompletedDKGSession>,
    // signing sessions
    sign_sessions: HashMap<String, SignSession>,
    completed_sign_sessions: HashMap<String, CompletedSigningSession>,
    // SUID counter
    next_suid: u32,
}

struct DKGSession {
    session: String,
    creator_suid: u32,
    min_signers: u16,
    max_signers: u16,
    group_id: String,
    created_at: DateTime<Utc>,
    // fixed list of session-local user ids allowed
    participants: Vec<u32>,

    // session-local identity maps
    suid_to_principal: BTreeMap<u32, String>,
    principal_to_suid: BTreeMap<String, u32>,

    // mapping suid -> frost Identifier (u16 1..=n)
    idmap: HashMap<u32, frost::Identifier>,
    joined: HashSet<u32>,

    // round1 packages from each participant (keyed by frost id)
    r1_pkgs: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
    // round2 inbox per-recipient: recipient_id -> (from_id -> EncryptedPayload)
    r2_inbox: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, EncryptedPayload>>,

    // finalization tracking
    finalized_uids: HashSet<u32>,
    agreed_vk: Option<String>,

    // Roster public keys for each suid
    roster_pubs: BTreeMap<u32, RosterPublicKey>,
    // signatures we forward along with packages
    r1_sigs: BTreeMap<frost::Identifier, String>,
    // per-recipient signatures: recipient -> (from -> sig_hex)
    r2_sigs: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, String>>,
}

struct SignSession {
    session: String,
    creator_suid: u32,
    group_id: String,
    threshold: u16,
    created_at: DateTime<Utc>,
    participants: Vec<u32>,
    participants_pubs: Vec<(u32, RosterPublicKey)>,
    message: String,

    // session-local identity maps
    suid_to_principal: BTreeMap<u32, String>,
    principal_to_suid: BTreeMap<String, u32>,

    idmap: HashMap<u32, frost::Identifier>,
    joined: HashSet<u32>,

    // Roster public keys for each suid
    roster_pubs: BTreeMap<u32, RosterPublicKey>,
    // verifying shares from each participant
    vmap: BTreeMap<frost::Identifier, frost::keys::VerifyingShare>,
    // round 1 commitments
    commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    // round 2 signature shares
    sign_shares: BTreeMap<frost::Identifier, frost::round2::SignatureShare>,

    // agreed group public key (finalization)
    group_vk_sec1_hex: String,
    // message hash (Keccak256, 32 bytes)
    msg32: [u8; 32],

    // snapshot of roster at session start (for broadcasting)
    roster_snapshot: Vec<(u32, String, RosterPublicKey)>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            conns: HashMap::new(),
            challenges: HashSet::new(),
            active_tokens: HashMap::new(),
            sessions: HashMap::new(),
            completed_dkg_sessions: HashMap::new(),
            sign_sessions: HashMap::new(),
            completed_sign_sessions: HashMap::new(),
            next_suid: 1,
        }
    }
}

// ============== Session timeout helper (15 minutes) ==============
fn start_session_timeout(state: AppState, session: String, is_sign: bool) {
    tokio::spawn(async move {
        sleep(Duration::from_secs(900)).await;

        let (senders, kind) = {
            let mut inner = state.inner.lock().await;
            if is_sign {
                if let Some(sign_session) = inner.sign_sessions.remove(&session) {
                    let mut v = Vec::new();
                    for suid in sign_session.participants {
                        if let Some(principal) = sign_session.suid_to_principal.get(&suid) {
                            if let Some(tx) = inner.conns.get(principal) {
                                v.push(tx.clone());
                            }
                        }
                    }
                    (v, "signing")
                } else {
                    (Vec::new(), "signing")
                }
            } else if let Some(dkg_session) = inner.sessions.remove(&session) {
                let mut v = Vec::new();
                for suid in dkg_session.participants {
                    if let Some(principal) = dkg_session.suid_to_principal.get(&suid) {
                        if let Some(tx) = inner.conns.get(principal) {
                            v.push(tx.clone());
                        }
                    }
                }
                (v, "dkg")
            } else {
                (Vec::new(), "dkg")
            }
        };

        for tx in senders {
            let _ = tx.send(Message::Text(
                serde_json::to_string(&ServerMsg::Error {
                    message: format!("{} session {} expired after 15 minutes", kind, session),
                })
                .unwrap(),
            ));
            let _ = tx.send(Message::Close(None));
        }
    });
}

// ========================= Server =========================
#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Server { bind } => run_server(bind).await,
    }
}

async fn run_server(bind: SocketAddr) -> Result<()> {
    let notify = Arc::new(Notify::new());
    let state = AppState {
        inner: Arc::new(Mutex::new(Inner::default())),
        shutdown: notify.clone(),
    };

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:5173".parse::<HeaderValue>().unwrap())
        .allow_methods([Method::GET, Method::POST])
        .allow_headers(tower_http::cors::Any);

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/close", get(close_handler))
        .with_state(state)
        .layer(cors);

    let listener = TcpListener::bind(bind).await?;
    println!("DKG coordinator listening on ws://{bind}/ws");

    let shutdown_fut = async move {
        notify.notified().await;
    };

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_fut)
        .await?;
    Ok(())
}
async fn close_handler(State(state): State<AppState>) -> impl IntoResponse {
    let notify = state.shutdown.clone();
    tokio::spawn(async move {
        sleep(Duration::from_secs(3)).await;
        notify.notify_waiters();
    });
    (StatusCode::OK, "server closing in 3s")
}

async fn ws_handler(
    State(state): State<AppState>,
    ws: WebSocketUpgrade,
) -> axum::response::Response {
    ws.on_upgrade(move |socket| handle_socket(state, socket))
}

async fn handle_socket(state: AppState, socket: WebSocket) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    let (mut sender, mut receiver) = socket.split();
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    let mut principal_json: Option<String> = None;
    let mut access_token: Option<String> = None;

    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(txt) => {
                if let Err(e) =
                    handle_client_text(&state, &mut principal_json, &mut access_token, &tx, txt)
                        .await
                {
                    let _ = tx.send(Message::Text(
                        serde_json::to_string(&ServerMsg::Error {
                            message: e.to_string(),
                        })
                        .unwrap(),
                    ));
                }
            }
            Message::Close(_) => break,
            Message::Ping(p) => {
                let _ = tx.send(Message::Pong(p));
            }
            _ => {}
        }
    }

    if let Some(principal) = principal_json {
        let token_to_remove = access_token.clone();

        let mut notify_targets: Vec<(String, String)> = Vec::new();
        let mut notify_txs: Vec<(Tx, String)> = Vec::new();

        {
            let mut inner = state.inner.lock().await;

            for (_sid, s) in inner.sessions.iter_mut() {
                if let Some(&suid) = s.principal_to_suid.get(&principal) {
                    if s.joined.remove(&suid) {
                        let msg = format!(
                            "Participant {} disconnected from DKG session {}",
                            suid, s.session
                        );
                        for other_suid in s.participants.iter().copied().filter(|u| *u != suid) {
                            if let Some(p) = s.suid_to_principal.get(&other_suid) {
                                notify_targets.push((p.clone(), msg.clone()));
                            }
                        }
                    }
                }
            }

            for (_sid, s) in inner.sign_sessions.iter_mut() {
                if let Some(&suid) = s.principal_to_suid.get(&principal) {
                    if s.joined.remove(&suid) {
                        let msg = format!(
                            "Participant {} disconnected from signing session {}",
                            suid, s.session
                        );
                        for other_suid in s.participants.iter().copied().filter(|u| *u != suid) {
                            if let Some(p) = s.suid_to_principal.get(&other_suid) {
                                notify_targets.push((p.clone(), msg.clone()));
                            }
                        }
                    }
                }
            }

            for (p, msg) in notify_targets.iter() {
                if let Some(tx_other) = inner.conns.get(p) {
                    notify_txs.push((tx_other.clone(), msg.clone()));
                }
            }

            inner.conns.remove(&principal);
            if let Some(ref token) = token_to_remove {
                inner.active_tokens.remove(token);
            }
        }

        for (tx_other, text) in notify_txs {
            let _ = tx_other.send(Message::Text(
                serde_json::to_string(&ServerMsg::Info { message: text }).unwrap(),
            ));
        }
    }
}

async fn handle_client_text(
    state: &AppState,
    principal_json: &mut Option<String>,
    access_token: &mut Option<String>,
    tx: &Tx,
    txt: String,
) -> Result<()> {
    let cmsg: ClientMsg = serde_json::from_str(&txt).context("parse client msg")?;
    let principal = principal_json.as_ref().cloned();

    match cmsg {
        ClientMsg::AnnounceDKGSession {
            min_signers,
            max_signers,
            group_id,
            participants,
            participants_pubs,
        } => {
            let principal = principal.ok_or_else(|| anyhow!("must be logged in to announce"))?;
            let mut inner = state.inner.lock().await;
            if participants.len() != max_signers as usize {
                return Err(anyhow!("participants length must equal max_signers"));
            }
            let session = Uuid::new_v4().to_string();

            let mut session_roster_pubs = BTreeMap::new();
            let mut suid_to_principal = BTreeMap::new();
            let mut principal_to_suid = BTreeMap::new();
            for (suid, pk) in &participants_pubs {
                let p_principal = serde_json::to_string(pk)?;
                if principal_to_suid
                    .insert(p_principal.clone(), *suid)
                    .is_some()
                {
                    return Err(anyhow!(
                        "principal appears more than once in the session roster"
                    ));
                }
                suid_to_principal.insert(*suid, p_principal);
                session_roster_pubs.insert(*suid, pk.clone());
            }

            if !participants
                .iter()
                .all(|u| session_roster_pubs.contains_key(u))
            {
                return Err(anyhow!("participants_pubs must include all suids"));
            }

            let creator_suid = *principal_to_suid
                .get(&principal)
                .ok_or_else(|| anyhow!("announcer must be a participant"))?;

            let mut idmap = HashMap::new();
            for (i, suid) in participants.iter().enumerate() {
                let fid: frost::Identifier = ((i + 1) as u16).try_into().unwrap();
                idmap.insert(*suid, fid);
            }
            let session_obj = DKGSession {
                session: session.clone(),
                creator_suid,
                min_signers,
                max_signers,
                group_id,
                created_at: Utc::now(),
                participants: participants.clone(),
                suid_to_principal,
                principal_to_suid,
                idmap,
                joined: HashSet::new(),
                r1_pkgs: BTreeMap::new(),
                r2_inbox: BTreeMap::new(),
                finalized_uids: HashSet::new(),
                agreed_vk: None,
                roster_pubs: session_roster_pubs,
                r1_sigs: BTreeMap::new(),
                r2_sigs: BTreeMap::new(),
            };
            inner.sessions.insert(session.clone(), session_obj);
            println!("[server] Announced DKG session '{}'", session);
            start_session_timeout(state.clone(), session.clone(), false);

            let _ = tx.send(Message::Text(serde_json::to_string(
                &ServerMsg::DKGSessionCreated { session },
            )?));
        }
        ClientMsg::RequestChallenge => {
            let mut inner = state.inner.lock().await;
            let challenge = Uuid::new_v4().to_string();
            inner.challenges.insert(challenge.clone());

            let _ = tx.send(Message::Text(serde_json::to_string(
                &ServerMsg::Challenge { challenge },
            )?));
        }
        ClientMsg::Login {
            challenge,
            public_key,
            signature_hex,
        } => {
            let mut inner = state.inner.lock().await;

            if !inner.challenges.remove(&challenge) {
                return Err(anyhow!("invalid or reused challenge"));
            }

            let challenge_uuid =
                Uuid::parse_str(&challenge).context("challenge is not a valid UUID")?;
            let challenge_bytes = challenge_uuid.as_bytes();

            public_key.verify(challenge_bytes, &signature_hex)?;

            let p = serde_json::to_string(&public_key)?;

            if inner.conns.contains_key(&p) {
                println!(
                    "[server] principal {} already logged in, allowing re-authentication",
                    p
                );
                inner.conns.remove(&p);
                inner.active_tokens.retain(|_, val| val != &p);
            }

            let token = Uuid::new_v4().to_string();
            inner.active_tokens.insert(token.clone(), p.clone());

            println!("[server] login successful for principal {}", p);
            inner.conns.insert(p.clone(), tx.clone());
            *principal_json = Some(p.clone());
            *access_token = Some(token.clone());

            let suid = inner.next_suid;
            inner.next_suid += 1;

            let _ = tx.send(Message::Text(serde_json::to_string(&ServerMsg::LoginOk {
                principal: p,
                suid,
                access_token: token,
            })?));
        }
        ClientMsg::Logout => {
            if let Some(p) = principal {
                let mut inner = state.inner.lock().await;
                inner.conns.remove(&p);
                if let Some(token) = access_token {
                    inner.active_tokens.remove(token);
                }
                *principal_json = None;
                *access_token = None;
                let _ = tx.send(Message::Text(serde_json::to_string(&ServerMsg::Info {
                    message: "logged out".to_string(),
                })?));
            }
        }
        ClientMsg::JoinDKGSession { session } => {
            let principal = principal.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            let mut notify_all = false;
            let mut session_name = String::new();
            let mut group_label = String::new();
            let mut min_s = 0u16;
            let mut max_s = 0u16;
            let mut roster_vec = Vec::new();

            let mut others_to_notify: Vec<String> = Vec::new();
            let join_msg: String;

            {
                let s = inner
                    .sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown DKG session"))?;

                let suid = *s
                    .principal_to_suid
                    .get(&principal)
                    .ok_or_else(|| anyhow!("principal not in allowed participants"))?;
                s.joined.insert(suid);
                let joined_count = s.joined.len();
                let total_count = s.participants.len();

                join_msg = format!(
                    "participant {} joined session {} ({}/{})",
                    suid, s.session, joined_count, total_count
                );
                for other_suid in s.participants.iter().copied().filter(|u| *u != suid) {
                    if let Some(p) = s.suid_to_principal.get(&other_suid) {
                        others_to_notify.push(p.clone());
                    }
                }

                if joined_count == total_count {
                    notify_all = true;
                    session_name = s.session.clone();
                    group_label = s.group_id.clone();
                    min_s = s.min_signers;
                    max_s = s.max_signers;
                    let mut roster = Vec::new();
                    for suid_i in &s.participants {
                        let id_hex = hex::encode(bincode::serialize(&s.idmap[suid_i]).unwrap());
                        let pk = s.roster_pubs[suid_i].clone();
                        roster.push((*suid_i, id_hex, pk));
                    }
                    roster_vec = roster;
                } else {
                    let info_msg = serde_json::to_string(&ServerMsg::Info {
                        message: format!("joined {}/{}", joined_count, total_count),
                    })?;
                    let recipients: Vec<String> = s
                        .participants
                        .iter()
                        .filter_map(|u| s.suid_to_principal.get(u).cloned())
                        .collect();
                    for p in recipients {
                        if let Some(tx_i) = inner.conns.get(&p) {
                            let _ = tx_i.send(Message::Text(info_msg.clone()));
                        }
                    }
                }
            }

            for p in others_to_notify {
                if let Some(tx_other) = inner.conns.get(&p) {
                    let _ =
                        tx_other.send(Message::Text(serde_json::to_string(&ServerMsg::Info {
                            message: join_msg.clone(),
                        })?));
                }
            }

            if notify_all {
                let recipients: Vec<String> = {
                    let sref = inner.sessions.get(&session).unwrap();
                    sref.participants
                        .iter()
                        .filter_map(|suid| sref.suid_to_principal.get(suid).cloned())
                        .collect()
                };
                for p in recipients {
                    if let Some(tx_i) = inner.conns.get(&p) {
                        let id_hex_for = {
                            let sref = inner.sessions.get(&session).unwrap();
                            let suid = sref.principal_to_suid[&p];
                            hex::encode(bincode::serialize(&sref.idmap[&suid]).unwrap())
                        };
                        let msg = ServerMsg::ReadyRound1 {
                            session: session_name.clone(),
                            id_hex: id_hex_for,
                            min_signers: min_s,
                            max_signers: max_s,
                            group_id: group_label.clone(),
                            roster: roster_vec.clone(),
                        };
                        let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                    }
                }
            }
        }
        ClientMsg::ListPendingDKGSessions => {
            let principal = principal.ok_or_else(|| anyhow!("must login first"))?;

            let sessions_payload: Vec<PendingDKGSession> = {
                let inner = state.inner.lock().await;
                inner
                    .sessions
                    .values()
                    .filter(|s| {
                        s.principal_to_suid.contains_key(&principal)
                            && s.finalized_uids.len() < s.participants.len()
                    })
                    .map(|s| {
                        let participants_pubs = s
                            .roster_pubs
                            .iter()
                            .map(|(suid, pk)| (*suid, pk.clone()))
                            .collect();
                        PendingDKGSession {
                            session: s.session.clone(),
                            creator_suid: s.creator_suid,
                            group_id: s.group_id.clone(),
                            min_signers: s.min_signers,
                            max_signers: s.max_signers,
                            participants: s.participants.clone(),
                            participants_pubs,
                            joined: s.joined.iter().copied().collect(),
                            created_at: s.created_at.to_rfc3339(),
                        }
                    })
                    .collect()
            };

            let _ = tx.send(Message::Text(serde_json::to_string(
                &ServerMsg::PendingDKGSessions {
                    sessions: sessions_payload,
                },
            )?));
        }

        ClientMsg::ListCompletedDKGSessions => {
            let principal = principal.ok_or_else(|| anyhow!("must login first"))?;
            let sessions_payload: Vec<CompletedDKGSession> = {
                let inner = state.inner.lock().await;
                inner
                    .completed_dkg_sessions
                    .values()
                    .filter(|s| {
                        s.participants_pubs
                            .iter()
                            .any(|(_, p)| serde_json::to_string(p).unwrap_or_default() == principal)
                    })
                    .cloned()
                    .collect()
            };
            let _ = tx.send(Message::Text(serde_json::to_string(
                &ServerMsg::CompletedDKGSessions {
                    sessions: sessions_payload,
                },
            )?));
        }

        ClientMsg::ListPendingSigningSessions => {
            let principal = principal.ok_or_else(|| anyhow!("must login first"))?;

            let sessions_payload: Vec<PendingSignSession> = {
                let inner = state.inner.lock().await;
                inner
                    .sign_sessions
                    .values()
                    .filter(|s| {
                        s.principal_to_suid.contains_key(&principal)
                            && s.joined.len() < s.participants.len()
                    })
                    .map(|s| {
                        let msg32_hex = hex::encode(s.msg32);
                        PendingSignSession {
                            session: s.session.clone(),
                            creator_suid: s.creator_suid,
                            group_id: s.group_id.clone(),
                            threshold: s.threshold,
                            participants: s.participants.clone(),
                            joined: s.joined.iter().copied().collect(),
                            message: s.message.clone(),
                            message_hex: msg32_hex,
                            participants_pubs: s.participants_pubs.clone(),
                            created_at: s.created_at.to_rfc3339(),
                        }
                    })
                    .collect()
            };

            let _ = tx.send(Message::Text(serde_json::to_string(
                &ServerMsg::PendingSigningSessions {
                    sessions: sessions_payload,
                },
            )?));
        }

        ClientMsg::ListCompletedSigningSessions => {
            let principal = principal.ok_or_else(|| anyhow!("must login first"))?;
            let sessions_payload: Vec<CompletedSigningSession> = {
                let inner = state.inner.lock().await;
                inner
                    .completed_sign_sessions
                    .values()
                    .filter(|s| {
                        s.participants_pubs
                            .iter()
                            .any(|(_, p)| serde_json::to_string(p).unwrap_or_default() == principal)
                    })
                    .cloned()
                    .collect()
            };
            let _ = tx.send(Message::Text(serde_json::to_string(
                &ServerMsg::CompletedSigningSessions {
                    sessions: sessions_payload,
                },
            )?));
        }

        ClientMsg::Round1Submit {
            session,
            id_hex,
            pkg_bincode_hex,
            signature_hex,
        } => {
            let principal = principal.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            let packages: Vec<(String, String, String)>;
            let recipients: Vec<String>;
            let session_name: String;

            {
                let s = inner
                    .sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown DKG session"))?;

                let suid = *s
                    .principal_to_suid
                    .get(&principal)
                    .ok_or_else(|| anyhow!("principal not in session"))?;
                let id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                let pkg: frost::keys::dkg::round1::Package =
                    bincode::deserialize(&hex::decode(&pkg_bincode_hex)?)?;
                let expected_id = s
                    .idmap
                    .get(&suid)
                    .ok_or_else(|| anyhow!("no frost id for suid"))?;
                if *expected_id != id {
                    return Err(anyhow!("identifier/suid mismatch"));
                }
                let payload = auth_payload_round1(&session, &id, &pkg);
                let vk = s
                    .roster_pubs
                    .get(&suid)
                    .ok_or_else(|| anyhow!("no RosterPublicKey for suid"))?;
                vk.verify(&payload, &signature_hex)?;
                s.r1_pkgs.insert(id, pkg);
                s.r1_sigs.insert(id, signature_hex);
                if s.r1_pkgs.len() != s.participants.len() {
                    return Ok(());
                }

                session_name = s.session.clone();
                recipients = s
                    .participants
                    .iter()
                    .filter_map(|u| s.suid_to_principal.get(u).cloned())
                    .collect();
                packages = s
                    .r1_pkgs
                    .iter()
                    .map(|(i, p)| {
                        let sig_hex = s.r1_sigs.get(i).cloned().unwrap_or_default();
                        (
                            hex::encode(bincode::serialize(i).unwrap()),
                            hex::encode(bincode::serialize(p).unwrap()),
                            sig_hex,
                        )
                    })
                    .collect();
            }

            println!(
                "[server] Broadcasting Round1All: {} packages (session={})",
                packages.len(),
                session_name
            );

            for p in recipients {
                if let Some(tx_i) = inner.conns.get(&p) {
                    let msg = ServerMsg::Round1All {
                        session: session_name.clone(),
                        packages: packages.clone(),
                    };
                    let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                    let _ = tx_i.send(Message::Text(serde_json::to_string(
                        &ServerMsg::ReadyRound2 {
                            session: session_name.clone(),
                        },
                    )?));
                }
            }
        }
        ClientMsg::Round2Submit {
            session,
            id_hex,
            pkgs_cipher,
        } => {
            let principal = principal.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;
            let mut dispatch_msgs: Vec<(String, ServerMsg)> = Vec::new();
            {
                let s = inner
                    .sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown DKG session"))?;
                let from_id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                let suid = *s
                    .principal_to_suid
                    .get(&principal)
                    .ok_or_else(|| anyhow!("principal not in session"))?;
                let expected_id = s
                    .idmap
                    .get(&suid)
                    .ok_or_else(|| anyhow!("no frost id for suid"))?;
                if *expected_id != from_id {
                    return Err(anyhow!("identifier/suid mismatch"));
                }
                let _vk = s
                    .roster_pubs
                    .get(&suid)
                    .ok_or_else(|| anyhow!("no RosterPublicKey for suid"))?;
                for (rid_hex, encrypted_payload, sig_hex) in pkgs_cipher {
                    let rid: frost::Identifier = bincode::deserialize(&hex::decode(&rid_hex)?)?;
                    // TODO: Re-enable verification once client sends signature for R2 payload
                    s.r2_inbox
                        .entry(rid)
                        .or_default()
                        .insert(from_id, encrypted_payload);
                    s.r2_sigs.entry(rid).or_default().insert(from_id, sig_hex);
                }

                let need = s.participants.len().saturating_sub(1);
                let ready_for_all = s
                    .idmap
                    .values()
                    .all(|rid| s.r2_inbox.get(rid).map(|m| m.len()).unwrap_or(0) == need);

                if ready_for_all {
                    let session_name = s.session.clone();
                    let recipients: Vec<(u32, frost::Identifier)> = s
                        .participants
                        .iter()
                        .map(|suid_i| (*suid_i, s.idmap[suid_i]))
                        .collect();
                    println!(
                        "[server] All R2 ready: preparing targeted Round2All (session={})",
                        s.session
                    );

                    for (suid_i, rid) in recipients {
                        if let Some(principal) = s.suid_to_principal.get(&suid_i) {
                            if let Some(map_for_me) = s.r2_inbox.get(&rid) {
                                let packages: Vec<(String, EncryptedPayload, String)> = map_for_me
                                    .iter()
                                    .map(|(from_id, payload)| {
                                        let sig = s
                                            .r2_sigs
                                            .get(&rid)
                                            .and_then(|m| m.get(from_id))
                                            .cloned()
                                            .unwrap_or_default();
                                        (
                                            hex::encode(bincode::serialize(from_id).unwrap()),
                                            payload.clone(),
                                            sig,
                                        )
                                    })
                                    .collect();
                                let msg = ServerMsg::Round2All {
                                    session: session_name.clone(),
                                    packages,
                                };
                                dispatch_msgs.push((principal.clone(), msg));
                            }
                        }
                    }
                }
                for (principal, msg) in dispatch_msgs {
                    if let Some(tx_i) = inner.conns.get(&principal) {
                        let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                    }
                }
            }
        }
        ClientMsg::FinalizeSubmit {
            session,
            id_hex,
            group_vk_sec1_hex,
            signature_hex,
        } => {
            let principal = principal.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            let mut should_finalize = false;

            {
                let s = inner
                    .sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown DKG session"))?;

                let id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                let suid = *s
                    .principal_to_suid
                    .get(&principal)
                    .ok_or_else(|| anyhow!("principal not in session"))?;
                let expected_id = s
                    .idmap
                    .get(&suid)
                    .ok_or_else(|| anyhow!("no frost id for suid"))?;
                if *expected_id != id {
                    return Err(anyhow!("identifier/suid mismatch"));
                }
                let vk = s
                    .roster_pubs
                    .get(&suid)
                    .ok_or_else(|| anyhow!("no RosterPublicKey for suid"))?;
                let vk_bytes = hex::decode(&group_vk_sec1_hex)?;
                let payload = auth_payload_finalize(&session, &id, &vk_bytes);
                vk.verify(&payload, &signature_hex)?;

                if let Some(vk) = &s.agreed_vk {
                    if vk != &group_vk_sec1_hex {
                        println!(
                            "[server] WARNING: finalize mismatch from suid {}: got {}, expected {}",
                            suid, group_vk_sec1_hex, vk
                        );
                        return Err(anyhow!("group VK mismatch"));
                    }
                } else {
                    s.agreed_vk = Some(group_vk_sec1_hex.clone());
                }

                s.finalized_uids.insert(suid);
                println!(
                    "[server] Finalize progress: {}/{} (session={})",
                    s.finalized_uids.len(),
                    s.participants.len(),
                    s.session
                );

                if s.finalized_uids.len() == s.participants.len() {
                    should_finalize = true;
                }
            }

            if should_finalize {
                if let Some(s) = inner.sessions.remove(&session) {
                    if let Some(vk) = s.agreed_vk.clone() {
                        let recipients: Vec<String> = s
                            .participants
                            .iter()
                            .filter_map(|u| s.suid_to_principal.get(u).cloned())
                            .collect();
                        for p in &recipients {
                            if let Some(tx_i) = inner.conns.get(p) {
                                let msg = ServerMsg::Finalized {
                                    session: s.session.clone(),
                                    group_vk_sec1_hex: vk.clone(),
                                };
                                let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                            }
                        }

                        let completed_session = CompletedDKGSession {
                            session: s.session.clone(),
                            creator_suid: s.creator_suid,
                            group_id: s.group_id.clone(),
                            min_signers: s.min_signers,
                            max_signers: s.max_signers,
                            participants: s.participants.clone(),
                            participants_pubs: s.roster_pubs.into_iter().collect(),
                            joined: s.joined.iter().copied().collect(),
                            created_at: s.created_at.to_rfc3339(),
                            group_vk_sec1_hex: vk,
                        };
                        inner
                            .completed_dkg_sessions
                            .insert(s.session.clone(), completed_session);
                        println!(
                            "[server] DKG session {} finalized and moved to completed.",
                            s.session
                        );
                    }
                }
            }
        }

        ClientMsg::AnnounceSignSession {
            group_id,
            threshold,
            participants,
            participants_pubs,
            group_vk_sec1_hex,
            message,
            message_hex,
        } => {
            let principal = principal.ok_or_else(|| anyhow!("must be logged in to announce"))?;
            let mut inner = state.inner.lock().await;
            if participants.is_empty() {
                return Err(anyhow!("participants cannot be empty"));
            }
            if threshold as usize > participants.len() {
                return Err(anyhow!("threshold cannot exceed participants"));
            }

            let mut session_roster_pubs = BTreeMap::new();
            let mut suid_to_principal = BTreeMap::new();
            let mut principal_to_suid = BTreeMap::new();
            for (suid, pk) in &participants_pubs {
                let p_principal = serde_json::to_string(pk)?;
                if principal_to_suid
                    .insert(p_principal.clone(), *suid)
                    .is_some()
                {
                    return Err(anyhow!(
                        "principal appears more than once in the signing session roster"
                    ));
                }
                suid_to_principal.insert(*suid, p_principal);
                session_roster_pubs.insert(*suid, pk.clone());
            }
            if !participants
                .iter()
                .all(|u| session_roster_pubs.contains_key(u))
            {
                return Err(anyhow!("participants_pubs must include all suids"));
            }

            let creator_suid = *principal_to_suid
                .get(&principal)
                .ok_or_else(|| anyhow!("announcer must be a participant"))?;

            let mut idmap = HashMap::new();
            for (i, suid) in participants.iter().enumerate() {
                let fid: frost::Identifier = ((i + 1) as u16).try_into().unwrap();
                idmap.insert(*suid, fid);
            }

            let clean_hex = message_hex.strip_prefix("0x").unwrap_or(&message_hex);
            if clean_hex.len() != 64 {
                return Err(anyhow!("message_hex must be 32 bytes (64 hex characters)"));
            }
            let msg_bytes = hex::decode(clean_hex).context("invalid message_hex")?;
            let mut msg32 = [0u8; 32];
            msg32.copy_from_slice(&msg_bytes);

            let mut hasher = Keccak256::new();
            hasher.update(message.as_bytes());
            let calculated_hash: [u8; 32] = hasher.finalize().into();
            if calculated_hash != msg32 {
                return Err(anyhow!("message and message_hex mismatch"));
            }

            let mut roster_vec = Vec::new();
            for suid in &participants {
                let id_hex = hex::encode(bincode::serialize(&idmap[suid]).unwrap());
                let pk = session_roster_pubs[suid].clone();
                roster_vec.push((*suid, id_hex, pk));
            }

            let session = Uuid::new_v4().to_string();
            inner.sign_sessions.insert(
                session.clone(),
                SignSession {
                    session: session.clone(),
                    creator_suid,
                    group_id: group_id.clone(),
                    threshold,
                    created_at: Utc::now(),
                    participants: participants.clone(),
                    participants_pubs: participants_pubs.clone(),
                    message,
                    suid_to_principal,
                    principal_to_suid,
                    idmap,
                    joined: HashSet::new(),
                    roster_pubs: session_roster_pubs,
                    vmap: BTreeMap::new(),
                    commitments: BTreeMap::new(),
                    sign_shares: BTreeMap::new(),
                    group_vk_sec1_hex,
                    msg32,
                    roster_snapshot: roster_vec,
                },
            );
            println!(
                "[server] Inserted signing session '{}'. Total: {}",
                session,
                inner.sign_sessions.len()
            );
            let _ = tx.send(Message::Text(serde_json::to_string(
                &ServerMsg::SignSessionCreated {
                    session: session.clone(),
                },
            )?));
            start_session_timeout(state.clone(), session.clone(), true);
        }

        ClientMsg::JoinSignSession {
            session,
            signer_id_bincode_hex,
            verifying_share_bincode_hex,
        } => {
            let principal = principal.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;
            println!(
                "[server] JoinSignSession for '{}' from principal {}. Known sessions: {:?}",
                session,
                principal,
                inner.sign_sessions.keys()
            );

            let mut notify_all = false;
            let mut recipients: Vec<String> = Vec::new();
            let mut msg_to_send: Option<ServerMsg> = None;

            {
                let s = inner
                    .sign_sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown signing session"))?;
                if !s.principal_to_suid.contains_key(&principal) {
                    return Err(anyhow!("principal not in allowed participants"));
                }
                let id: frost::Identifier =
                    bincode::deserialize(&hex::decode(&signer_id_bincode_hex)?)?;
                let suid = s.principal_to_suid[&principal];
                if let Some(exp) = s.idmap.get(&suid) {
                    if *exp != id {
                        return Err(anyhow!("identifier/suid mismatch in join"));
                    }
                } else {
                    s.idmap.insert(suid, id);
                }
                let vshare: frost::keys::VerifyingShare =
                    bincode::deserialize(&hex::decode(&verifying_share_bincode_hex)?)?;
                s.vmap.insert(id, vshare);
                s.joined.insert(suid);

                if s.joined.len() == s.participants.len() {
                    notify_all = true;
                    recipients = s
                        .participants
                        .iter()
                        .filter_map(|u| s.suid_to_principal.get(u).cloned())
                        .collect();
                    let msg32_hex = format!("0x{}", hex::encode(s.msg32));
                    msg_to_send = Some(ServerMsg::SignReadyRound1 {
                        session: s.session.clone(),
                        group_id: s.group_id.clone(),
                        threshold: s.threshold,
                        participants: s.participants.len() as u16,
                        msg_keccak32_hex: msg32_hex,
                        roster: s.roster_snapshot.clone(),
                    });
                } else {
                    let _ = tx.send(Message::Text(serde_json::to_string(&ServerMsg::Info {
                        message: format!("joined {}/{}", s.joined.len(), s.participants.len()),
                    })?));
                }
            }

            if notify_all {
                if let Some(msg) = msg_to_send {
                    for p in recipients {
                        if let Some(tx_i) = inner.conns.get(&p) {
                            let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                        }
                    }
                }
            }
        }
        ClientMsg::SignRound1Submit {
            session,
            id_hex,
            commitments_bincode_hex,
            signature_hex,
        } => {
            let principal = principal.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            let mut recipients: Vec<String> = Vec::new();
            let mut session_name = String::new();
            let mut sp_hex = String::new();
            let mut ready = false;

            {
                let s = inner
                    .sign_sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown signing session"))?;
                let id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                let suid = *s
                    .principal_to_suid
                    .get(&principal)
                    .ok_or_else(|| anyhow!("principal not in session"))?;
                let expected_id = s
                    .idmap
                    .get(&suid)
                    .ok_or_else(|| anyhow!("no id for suid"))?;
                if *expected_id != id {
                    return Err(anyhow!("identifier/suid mismatch"));
                }
                let vk = s
                    .roster_pubs
                    .get(&suid)
                    .ok_or_else(|| anyhow!("no RosterPublicKey for suid"))?;
                let payload =
                    auth_payload_sign_r1(&session, &s.group_id, &id_hex, &commitments_bincode_hex);
                vk.verify(&payload, &signature_hex)?;
                let commits: frost::round1::SigningCommitments =
                    bincode::deserialize(&hex::decode(&commitments_bincode_hex)?)?;
                s.commitments.insert(id, commits);
                if s.commitments.len() == s.participants.len() {
                    let sp = frost::SigningPackage::new(s.commitments.clone(), &s.msg32);
                    sp_hex = hex::encode(bincode::serialize(&sp)?);
                    recipients = s
                        .participants
                        .iter()
                        .filter_map(|u| s.suid_to_principal.get(u).cloned())
                        .collect();
                    session_name = s.session.clone();
                    ready = true;
                }
            }

            if ready {
                for p in recipients {
                    if let Some(tx_i) = inner.conns.get(&p) {
                        let msg = ServerMsg::SignSigningPackage {
                            session: session_name.clone(),
                            signing_package_bincode_hex: sp_hex.clone(),
                        };
                        let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                    }
                }
            }
        }
        ClientMsg::SignRound2Submit {
            session,
            id_hex,
            signature_share_bincode_hex,
            signature_hex,
        } => {
            let principal = principal.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            let mut should_aggregate = false;

            {
                let s = inner
                    .sign_sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown signing session"))?;

                let id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                let suid = *s
                    .principal_to_suid
                    .get(&principal)
                    .ok_or_else(|| anyhow!("principal not in session"))?;
                let expected_id = s
                    .idmap
                    .get(&suid)
                    .ok_or_else(|| anyhow!("no id for suid"))?;
                if *expected_id != id {
                    return Err(anyhow!("identifier/suid mismatch"));
                }

                let vk = s
                    .roster_pubs
                    .get(&suid)
                    .ok_or_else(|| anyhow!("no RosterPublicKey for suid"))?;
                let msg32_hex = format!("0x{}", hex::encode(s.msg32));
                let payload = auth_payload_sign_r2(
                    &session,
                    &s.group_id,
                    &id_hex,
                    &signature_share_bincode_hex,
                    &msg32_hex,
                );
                vk.verify(&payload, &signature_hex)?;

                let sshare: frost::round2::SignatureShare =
                    bincode::deserialize(&hex::decode(&signature_share_bincode_hex)?)?;
                s.sign_shares.insert(id, sshare);

                if s.sign_shares.len() == s.commitments.len() {
                    should_aggregate = true;
                }
            }

            if should_aggregate {
                if let Some(s) = inner.sign_sessions.remove(&session) {
                    let group_vk_bytes = hex::decode(&s.group_vk_sec1_hex)?;
                    let group_vk = frost::VerifyingKey::deserialize(&group_vk_bytes)
                        .map_err(|e| anyhow!("group verifying key deserialize failed: {e}"))?;
                    let pubkey_package =
                        frost::keys::PublicKeyPackage::new(s.vmap.clone(), group_vk);
                    let sp = frost::SigningPackage::new(s.commitments.clone(), &s.msg32);
                    let sig_final = frost::aggregate(&sp, &s.sign_shares, &pubkey_package)?;
                    let sig_hex = hex::encode(bincode::serialize(&sig_final)?);

                    let vk_parsed = EcdsaVerifyingKey::from_sec1_bytes(&group_vk_bytes)?
                        .to_encoded_point(false);
                    let px = format!("0x{}", hex::encode(vk_parsed.x().unwrap()));
                    let py = format!("0x{}", hex::encode(vk_parsed.y().unwrap()));
                    let r_aff = sig_final.R().to_affine();
                    let r_pt = r_aff.to_encoded_point(false);
                    let rx = format!("0x{}", hex::encode(r_pt.x().unwrap()));
                    let ry = format!("0x{}", hex::encode(r_pt.y().unwrap()));
                    let s_field = {
                        let z_bytes = frost::Secp256K1ScalarField::serialize(sig_final.z());
                        format!("0x{}", hex::encode(z_bytes))
                    };

                    let recipients: Vec<String> = s
                        .participants
                        .iter()
                        .filter_map(|u| s.suid_to_principal.get(u).cloned())
                        .collect();
                    for p in &recipients {
                        if let Some(tx_i) = inner.conns.get(p) {
                            let msg = ServerMsg::SignatureReady {
                                session: s.session.clone(),
                                signature_bincode_hex: sig_hex.clone(),
                                px: px.clone(),
                                py: py.clone(),
                                rx: rx.clone(),
                                ry: ry.clone(),
                                s: s_field.clone(),
                                message: format!("0x{}", hex::encode(s.msg32)),
                            };
                            let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                        }
                    }

                    let completed_session = CompletedSigningSession {
                        session: s.session.clone(),
                        creator_suid: s.creator_suid,
                        group_id: s.group_id.clone(),
                        threshold: s.threshold,
                        participants: s.participants.clone(),
                        joined: s.joined.iter().copied().collect(),
                        message: s.message.clone(),
                        message_hex: format!("0x{}", hex::encode(s.msg32)),
                        participants_pubs: s.participants_pubs.clone(),
                        created_at: s.created_at.to_rfc3339(),
                        signature: sig_hex,
                    };
                    inner
                        .completed_sign_sessions
                        .insert(s.session.clone(), completed_session);
                    println!(
                        "[server] Signing session {} finalized and moved to completed.",
                        s.session
                    );
                }
            }
        }
    }
    Ok(())
}
