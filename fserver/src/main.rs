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
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    extract::State,
    routing::get,
    Router,
};
use clap::{Parser, Subcommand};
use frost_core::Field;
use frost_secp256k1 as frost;
use futures::{sink::SinkExt, stream::StreamExt};
use k256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use signature::DigestVerifier;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::{sleep, Duration};
use uuid::Uuid;
use tokio::time::{self, Instant};
// -------- ECDSA auth helpers (source integrity & authentication) --------
fn auth_payload_round1(
    session: &str,
    id: &frost::Identifier,
    pkg: &frost::keys::dkg::round1::Package,
) -> Vec<u8> {
    let mut v = b"TOKAMAK_FROST_DKG_R1|".to_vec();
    v.extend_from_slice(session.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(id).unwrap());
    v.extend_from_slice(&bincode::serialize(pkg).unwrap());
    v
}
fn auth_payload_round2(
    session: &str,
    from: &frost::Identifier,
    to: &frost::Identifier,
    eph_pub_sec1: &[u8],
    nonce: &[u8],
    ct: &[u8],
) -> Vec<u8> {
    // Sign the encrypted envelope (not the plaintext): session | from | to | eph_pub | nonce | ct
    let mut v = b"TOKAMAK_FROST_DKG_R2|".to_vec();
    v.extend_from_slice(session.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(from).unwrap());
    v.extend_from_slice(&bincode::serialize(to).unwrap());
    v.extend_from_slice(eph_pub_sec1);
    v.extend_from_slice(nonce);
    v.extend_from_slice(ct);
    v
}
fn auth_payload_finalize(session: &str, id: &frost::Identifier, group_vk_sec1: &[u8]) -> Vec<u8> {
    let mut v = b"TOKAMAK_FROST_DKG_FIN|".to_vec();
    v.extend_from_slice(session.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(id).unwrap());
    v.extend_from_slice(group_vk_sec1);
    v
}
fn parse_sig_hex(hexstr: &str) -> anyhow::Result<EcdsaSignature> {
    use core::convert::TryFrom;
    let bytes = hex::decode(hexstr)?;
    // Prefer DER; if that fails, accept 64-byte compact signatures (r||s)
    if let Ok(sig) = EcdsaSignature::from_der(&bytes) {
        return Ok(sig);
    }
    EcdsaSignature::try_from(bytes.as_slice())
        .map_err(|_| anyhow::anyhow!("invalid ECDSA signature: expected DER or 64-byte compact"))
}

// Additional auth helpers for interactive signing flow
fn auth_payload_sign_r1(session: &str, group_id: &str, id_hex: &str, commits_hex: &str) -> Vec<u8> {
    format!("SIGN_WS_R1|{}|{}|{}|{}", session, group_id, id_hex, commits_hex).into_bytes()
}
fn auth_payload_sign_r2(session: &str, group_id: &str, id_hex: &str, sigshare_hex: &str, msg32_hex: &str) -> Vec<u8> {
    format!("SIGN_WS_R2|{}|{}|{}|{}|{}", session, group_id, id_hex, sigshare_hex, msg32_hex).into_bytes()
}

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
    AnnounceSession {
        min_signers: u16,
        max_signers: u16,
        group_id: String,
        participants: Vec<u32>,
        participants_pubs: Vec<(u32, String)>,
    },
    RequestChallenge,
    Login {
        challenge: String,
        pubkey_hex: String,
        signature_hex: String,
    },
    Logout,
    JoinSession {
        session: String,
    },

    // DKG round messages
    Round1Submit {
        session: String,
        id_hex: String,
        pkg_bincode_hex: String,
        sig_ecdsa_hex: String,
    },
    Round2Submit {
        session: String,
        id_hex: String,
        // encrypted triples: (recipient_id_hex, eph_pub_sec1_hex, nonce_hex, ct_hex, sig_hex)
        pkgs_cipher_hex: Vec<(String, String, String, String, String)>,
    },
    FinalizeSubmit {
        session: String,
        id_hex: String,
        group_vk_sec1_hex: String,
        sig_ecdsa_hex: String,
    },

    // ---- Interactive signing (new) ----
    AnnounceSignSession {
        group_id: String,
        threshold: u16,
        participants: Vec<u32>,
        participants_pubs: Vec<(u32, String)>,
        group_vk_sec1_hex: String,
        // message bytes, as hex (0x... or plain hex)
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
        sig_ecdsa_hex: String,
    },
    SignRound2Submit {
        session: String,
        id_hex: String,
        signature_share_bincode_hex: String,
        sig_ecdsa_hex: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
enum ServerMsg {
    Error { message: String },
    Info { message: String },
    Challenge { challenge: String },
    LoginOk { user_id: u32, access_token: String },

    /// Sent to the creator after a successful AnnounceSession
    SessionCreated { session: String },

    // Signals
    ReadyRound1 {
        session: String,
        id_hex: String,
        min_signers: u16,
        max_signers: u16,
        group_id: String,
        // (uid, id_hex, ecdsa_pub_sec1_hex)
        roster: Vec<(u32, String, String)>,
    },
    Round1All {
        session: String,
        // (id_hex, pkg_bincode_hex, sig_ecdsa_hex)
        packages: Vec<(String, String, String)>,
    },
    ReadyRound2 { session: String },
    Round2All {
        session: String,
        // encrypted tuples: (from_id_hex, eph_pub_sec1_hex, nonce_hex, ct_hex, sig_ecdsa_hex)
        packages: Vec<(String, String, String, String, String)>,
    },
    Finalized { session: String, group_vk_sec1_hex: String },

    // ---- Interactive signing (new) ----
    SignSessionCreated { session: String },
    SignReadyRound1 {
        session: String,
        group_id: String,
        threshold: u16,
        participants: u16,
        msg_keccak32_hex: String,
        // (uid, id_hex, ecdsa_pub_sec1_hex)
        roster: Vec<(u32, String, String)>,
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


// ========================= Coordinator State =========================

type Tx = mpsc::UnboundedSender<Message>;

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<Inner>>,
    shutdown: Arc<Notify>,
}

struct Inner {
    // Canonical mapping of pubkey -> uid for all known participants.
    roster: BTreeMap<EcdsaVerifyingKey, u32>,
    // active connections by uid
    conns: HashMap<u32, Tx>,
    // active challenges to prevent reuse
    challenges: HashSet<String>,
    // active tokens
    active_tokens: HashMap<String, u32>, // token -> uid
    // sessions
    sessions: HashMap<String, Session>,
    // signing sessions
    sign_sessions: HashMap<String, SignSession>,
}

struct Session {
    session: String,
    min_signers: u16,
    max_signers: u16,
    group_id: String,
    // fixed list of user ids allowed
    participants: Vec<u32>,
    // mapping user id -> frost Identifier (u16 1..=n)
    idmap: HashMap<u32, frost::Identifier>,
    joined: HashSet<u32>,

    // round1 packages from each participant (keyed by frost id)
    r1_pkgs: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
    // round2 inbox per-recipient: recipient_id -> (from_id -> (eph_pub_hex, nonce_hex, ct_hex))
    r2_inbox: BTreeMap<
        frost::Identifier,
        BTreeMap<frost::Identifier, (String, String, String)>,
    >,

    // finalization tracking
    finalized_uids: HashSet<u32>,
    agreed_vk: Option<String>,

    // ECDSA verifying keys for each uid
    ecdsa_pubs: BTreeMap<u32, EcdsaVerifyingKey>,
    // signatures we forward along with packages
    r1_sigs: BTreeMap<frost::Identifier, String>,
    // per-recipient signatures: recipient -> (from -> sig_hex)
    r2_sigs: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, String>>,
}

struct SignSession {
    session: String,
    group_id: String,
    threshold: u16,
    participants: Vec<u32>,
    idmap: HashMap<u32, frost::Identifier>,
    joined: HashSet<u32>,

    // ECDSA verifying keys for each uid
    ecdsa_pubs: BTreeMap<u32, EcdsaVerifyingKey>,
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
    roster_snapshot: Vec<(u32, String, String)>,
}

impl Default for Inner {
    fn default() -> Self {
        Self {
            roster: BTreeMap::new(),
            conns: HashMap::new(),
            challenges: HashSet::new(),
            active_tokens: HashMap::new(),
            sessions: HashMap::new(),
            sign_sessions: HashMap::new(),
        }
    }
}

// ============== Session timeout helper (3 minutes) ==============
fn start_session_timeout(state: AppState, session: String, is_sign: bool) {
    // Spawn a background task that expires the session after 180 seconds
    tokio::spawn(async move {
        sleep(Duration::from_secs(180)).await;

        // Collect the client senders for participants and remove the session
        let (senders, kind) = {
            let mut inner = state.inner.lock().await;
            if is_sign {
                if let Some(sign_session) = inner.sign_sessions.remove(&session) {
                    let mut v = Vec::new();
                    for uid in sign_session.participants {
                        if let Some(tx) = inner.conns.get(&uid) {
                            v.push(tx.clone());
                        }
                    }
                    (v, "signing")
                } else {
                    (Vec::new(), "signing")
                }
            } else {
                if let Some(dkg_session) = inner.sessions.remove(&session) {
                    let mut v = Vec::new();
                    for uid in dkg_session.participants {
                        if let Some(tx) = inner.conns.get(&uid) {
                            v.push(tx.clone());
                        }
                    }
                    (v, "dkg")
                } else {
                    (Vec::new(), "dkg")
                }
            }
        };

        // Notify clients and close their WebSocket connections
        for tx in senders {
            let _ = tx.send(Message::Text(
                serde_json::to_string(&ServerMsg::Error {
                    message: format!("{} session {} expired after 3 minutes", kind, session),
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
    // shared shutdown signal
    let notify = Arc::new(Notify::new());
    let state = AppState {
        inner: Arc::new(Mutex::new(Inner::default())),
        shutdown: notify.clone(),
    };

    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/close", get(close_handler))
        .with_state(state);

    let listener = TcpListener::bind(bind).await?;
    println!("DKG coordinator listening on ws://{bind}/ws");

    // graceful shutdown when notified (triggered by /close after 3s)
    let shutdown_fut = async move {
        notify.notified().await;
    };

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_fut)
        .await?;
    Ok(())
}
async fn close_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Delay 3 seconds, then notify the server to shut down
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
    // Create a channel so other tasks can send to this socket
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Split the socket into sender and receiver
    let (mut sender, mut receiver) = socket.split();
    // Spawn a writer task
    tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            if sender.send(msg).await.is_err() {
                break;
            }
        }
    });

    // Session info
    let mut session_uid: Option<u32> = None;
    let mut access_token: Option<String> = None;

    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(txt) => {
                if let Err(e) = handle_client_text(&state, &mut session_uid, &mut access_token, &tx, txt).await {
                    let _ = tx.send(Message::Text(
                        serde_json::to_string(&ServerMsg::Error { message: e.to_string() }).unwrap(),
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

    // Cleanup on disconnect
    if let Some(uid) = session_uid {
        let mut inner = state.inner.lock().await;
        inner.conns.remove(&uid);
        if let Some(token) = access_token {
            inner.active_tokens.remove(&token);
        }
    }
}

async fn handle_client_text(
    state: &AppState,
    session_uid: &mut Option<u32>,
    access_token: &mut Option<String>,
    tx: &Tx,
    txt: String,
) -> Result<()> {
    let cmsg: ClientMsg = serde_json::from_str(&txt).context("parse client msg")?;
    match cmsg {
        ClientMsg::AnnounceSession {
            min_signers,
            max_signers,
            group_id,
            participants,
            participants_pubs,
        } => {
            let mut inner = state.inner.lock().await;
            if participants.len() != max_signers as usize {
                return Err(anyhow!("participants length must equal max_signers"));
            }
            // Generate unique session id
            let session = Uuid::new_v4().to_string();

            // Populate server-wide roster and session-specific key map.
            let mut session_ecdsa_pubs = BTreeMap::new();
            for (p_uid, p_pk_hex) in &participants_pubs {
                let p_pk_bytes = hex::decode(p_pk_hex).context("roster pubkey hex")?;
                let p_vk = EcdsaVerifyingKey::from_sec1_bytes(&p_pk_bytes)
                    .map_err(|_| anyhow!("bad ECDSA pub for uid {}", p_uid))?;

                // Add to server-wide roster if not present, or verify consistency.
                if let Some(existing_uid) = inner.roster.get(&p_vk) {
                    if existing_uid != p_uid {
                        return Err(anyhow!(
                            "pubkey for uid {} is already registered with a different uid {}",
                            p_uid, existing_uid
                        ));
                    }
                } else {
                    inner.roster.insert(p_vk.clone(), *p_uid);
                }
                session_ecdsa_pubs.insert(*p_uid, p_vk);
            }

            if !participants.iter().all(|u| session_ecdsa_pubs.contains_key(u)) {
                return Err(anyhow!("participants_pubs must include all uids"));
            }

            // build id map 1..=n based on order
            let mut idmap = HashMap::new();
            for (i, uid_i) in participants.iter().enumerate() {
                let fid: frost::Identifier = ((i + 1) as u16).try_into().unwrap();
                idmap.insert(*uid_i, fid);
            }
            let session_obj = Session {
                session: session.clone(),
                min_signers,
                max_signers,
                group_id,
                participants: participants.clone(),
                idmap,
                joined: HashSet::new(),
                r1_pkgs: BTreeMap::new(),
                r2_inbox: BTreeMap::new(),
                finalized_uids: HashSet::new(),
                agreed_vk: None,
                ecdsa_pubs: session_ecdsa_pubs,
                r1_sigs: BTreeMap::new(),
                r2_sigs: BTreeMap::new(),
            };
            inner.sessions.insert(session.clone(), session_obj);
            println!("[server] Announced session '{}'", session);
            // Start a 3-minute timeout for this DKG session
            start_session_timeout(state.clone(), session.clone(), false);

            // Reply to creator with the session id
            let _ = tx.send(Message::Text(serde_json::to_string(&ServerMsg::SessionCreated {
                session,
            })?));
        }
        ClientMsg::RequestChallenge => {
            let mut inner = state.inner.lock().await;
            let challenge = Uuid::new_v4().to_string();
            inner.challenges.insert(challenge.clone());

            let _ = tx.send(Message::Text(serde_json::to_string(&ServerMsg::Challenge { challenge })?));
        }
        ClientMsg::Login { challenge, pubkey_hex, signature_hex } => {
            let mut inner = state.inner.lock().await;

            if !inner.challenges.remove(&challenge) {
                return Err(anyhow!("invalid or reused challenge"));
            }

            let pubkey_bytes = hex::decode(&pubkey_hex).context("pubkey hex decode")?;
            let vk = EcdsaVerifyingKey::from_sec1_bytes(&pubkey_bytes)
                .map_err(|_| anyhow!("invalid public key format (must be 33-byte compressed SEC1)"))?;

            let sig = parse_sig_hex(&signature_hex)?;
            let challenge_uuid = Uuid::parse_str(&challenge).context("challenge is not a valid UUID")?;
            let challenge_bytes = challenge_uuid.as_bytes();

            vk.verify_digest(Keccak256::new().chain_update(challenge_bytes), &sig)
                .map_err(|_| anyhow!("ECDSA signature verification failed"))?;

            // Find the canonical UID from the roster based on the verified public key.
            let uid = match inner.roster.get(&vk) {
                Some(id) => *id,
                None => return Err(anyhow!("public key not registered in any session roster")),
            };

            // Allow re-authentication by removing existing connection
            if inner.conns.contains_key(&uid)
            {
                println!("[server] user {} already logged in, allowing re-authentication", uid);
                inner.conns.remove(&uid);
                // Also clean up any existing tokens for this user
                inner.active_tokens.retain(|_, token_uid| *token_uid != uid);
            }

            let token = Uuid::new_v4().to_string();
            inner.active_tokens.insert(token.clone(), uid);

            println!("[server] login successful for uid {}", uid);
            inner.conns.insert(uid, tx.clone());
            *session_uid = Some(uid);
            *access_token = Some(token.clone());

            let _ = tx.send(Message::Text(serde_json::to_string(&ServerMsg::LoginOk {
                user_id: uid,
                access_token: token,
            })?));
        }
        ClientMsg::Logout => {
            if let Some(uid) = session_uid {
                let mut inner = state.inner.lock().await;
                inner.conns.remove(uid);
                if let Some(token) = access_token {
                    inner.active_tokens.remove(token);
                }
                *session_uid = None;
                *access_token = None;
                let _ = tx.send(Message::Text(serde_json::to_string(&ServerMsg::Info {
                    message: "logged out".to_string(),
                })?));
            }
        }
        ClientMsg::JoinSession { session } => {
            let uid = session_uid.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            // Variables to use after dropping borrow
            let mut notify_all = false;
            let mut session_name = String::new();
            let mut group_label = String::new();
            let mut min_s = 0u16;
            let mut max_s = 0u16;
            let mut roster_vec = Vec::new();

            {
                let s = inner
                    .sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown session"))?;
                if !s.participants.contains(&uid) {
                    return Err(anyhow!("user not in allowed participants"));
                }
                s.joined.insert(uid);
                let joined_count = s.joined.len();
                let total_count = s.participants.len();
                if joined_count == total_count {
                    notify_all = true;
                    session_name = s.session.clone();
                    group_label = s.group_id.clone();
                    min_s = s.min_signers;
                    max_s = s.max_signers;
                    // build roster: (uid, id_hex, ecdsa_pub_sec1_hex)
                    let mut roster = Vec::new();
                    for uid_i in &s.participants {
                        let id_hex = hex::encode(bincode::serialize(&s.idmap[uid_i]).unwrap());
                        let pk_hex = hex::encode(s.ecdsa_pubs[uid_i].to_encoded_point(true).as_bytes());
                        roster.push((*uid_i, id_hex, pk_hex));
                    }
                    roster_vec = roster;
                } else {
                    let _ = tx.send(Message::Text(serde_json::to_string(&ServerMsg::Info {
                        message: format!("joined {}/{}", joined_count, total_count),
                    })?));
                }
            }

            if notify_all {
                for uid_i in inner.sessions[&session].participants.clone() {
                    if let Some(tx_i) = inner.conns.get(&uid_i) {
                        let id_hex_for = hex::encode(
                            bincode::serialize(&inner.sessions[&session].idmap[&uid_i]).unwrap(),
                        );
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
        ClientMsg::Round1Submit { session, id_hex, pkg_bincode_hex, sig_ecdsa_hex } => {
            let uid = session_uid.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            let packages: Vec<(String, String, String)>;

            {
                let s = inner
                    .sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown session"))?;
                let id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                let pkg: frost::keys::dkg::round1::Package =
                    bincode::deserialize(&hex::decode(&pkg_bincode_hex)?)?;
                // Ensure the sender's session uid matches the declared FROST identifier
                let expected_id = s.idmap.get(&uid).ok_or_else(|| anyhow!("no frost id for uid"))?;
                if *expected_id != id {
                    return Err(anyhow!("identifier/uid mismatch"));
                }
                // verify ECDSA
                let payload = auth_payload_round1(&session, &id, &pkg);
                let sig = parse_sig_hex(&sig_ecdsa_hex)?;
                let vk = s.ecdsa_pubs.get(&uid).ok_or_else(|| anyhow!("no ECDSA vk for uid"))?;
                vk.verify_digest(Keccak256::new().chain_update(&payload), &sig)
                    .map_err(|_| anyhow!("ECDSA verify failed (round1)"))?;
                s.r1_pkgs.insert(id, pkg);
                s.r1_sigs.insert(id, sig_ecdsa_hex);
                let have = s.r1_pkgs.len();
                let need = s.participants.len();
                println!("[server] R1 submit: have {have}/{need} (session={})", s.session);
                if s.r1_pkgs.len() != s.participants.len() {
                    return Ok(());
                }
                let session_name = s.session.clone();
                let recipients = s.participants.clone();
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
                println!(
                    "[server] Broadcasting Round1All: {} packages (session={})",
                    packages.len(),
                    s.session
                );

                for uid_i in recipients {
                    if let Some(tx_i) = inner.conns.get(&uid_i) {
                        let msg = ServerMsg::Round1All { session: session_name.clone(), packages: packages.clone() };
                        let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                        let _ = tx_i.send(Message::Text(serde_json::to_string(&ServerMsg::ReadyRound2 { session: session_name.clone() })?));
                    }
                }
            }
        }
        ClientMsg::Round2Submit { session, id_hex, pkgs_cipher_hex } => {
            let mut inner = state.inner.lock().await;

            {
                let s = inner
                    .sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown session"))?;
                let from_id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                let uid = session_uid.ok_or_else(|| anyhow!("must login first"))?;
                // Ensure the sender's session uid matches the declared FROST identifier
                let expected_id = s.idmap.get(&uid).ok_or_else(|| anyhow!("no frost id for uid"))?;
                if *expected_id != from_id {
                    return Err(anyhow!("identifier/uid mismatch"));
                }
                let vk = s.ecdsa_pubs.get(&uid).ok_or_else(|| anyhow!("no ECDSA vk for uid"))?;
                // Insert each outgoing encrypted pkg into recipient inbox
                for (rid_hex, eph_pub_hex, nonce_hex, ct_hex, sig_hex) in pkgs_cipher_hex {
                    let rid: frost::Identifier = bincode::deserialize(&hex::decode(&rid_hex)?)?;
                    let eph_pub = hex::decode(&eph_pub_hex)?;
                    let nonce = hex::decode(&nonce_hex)?;
                    let ct = hex::decode(&ct_hex)?;
                    // verify ECDSA over the encrypted envelope
                    let payload = auth_payload_round2(&session, &from_id, &rid, &eph_pub, &nonce, &ct);
                    let sig = parse_sig_hex(&sig_hex)?;
                    vk.verify_digest(Keccak256::new().chain_update(&payload), &sig)
                        .map_err(|_| anyhow!("ECDSA verify failed (round2)"))?;
                    // Store ciphertext triplet for targeted dispatch
                    s.r2_inbox
                        .entry(rid)
                        .or_insert_with(BTreeMap::new)
                        .insert(from_id, (eph_pub_hex, nonce_hex, ct_hex));
                    s.r2_sigs
                        .entry(rid)
                        .or_insert_with(BTreeMap::new)
                        .insert(from_id, sig_hex);
                }

                // Debug: show per-recipient inbox sizes so clients can see progress
                for (uid_i, rid) in s.participants.iter().map(|uid_i| (*uid_i, s.idmap[uid_i])) {
                    let cur = s.r2_inbox.get(&rid).map(|m| m.len()).unwrap_or(0);
                    println!(
                        "[server] R2 inbox for uid {uid_i} (rid={}): {}/?",
                        hex::encode(bincode::serialize(&rid).unwrap()),
                        cur
                    );
                }

                // Check if every recipient has N-1 packages (from all other participants)
                let need = s.participants.len().saturating_sub(1);
                let ready_for_all = s
                    .idmap
                    .values()
                    .all(|rid| s.r2_inbox.get(rid).map(|m| m.len()).unwrap_or(0) == need);

                if ready_for_all {
                    let session_name = s.session.clone();
                    // Snapshot recipients with their frost identifiers for targeted dispatch
                    let recipients: Vec<(u32, frost::Identifier)> = s
                        .participants
                        .iter()
                        .map(|uid_i| (*uid_i, s.idmap[uid_i]))
                        .collect();
                    println!(
                        "[server] All R2 ready: dispatching targeted Round2All (session={})",
                        s.session
                    );

                    // Targeted broadcast: each participant receives only the packages destined for them
                    for (uid_i, rid) in recipients {
                        if let Some(tx_i) = inner.conns.get(&uid_i) {
                            if let Some(map_for_me) = inner
                                .sessions
                                .get(&session_name)
                                .and_then(|s| s.r2_inbox.get(&rid))
                            {
                                let sigs_for_me = inner
                                    .sessions
                                    .get(&session_name)
                                    .and_then(|s| s.r2_sigs.get(&rid))
                                    .cloned()
                                    .unwrap_or_default();
                                println!(
                                    "[server] Sending R2 packages to uid {} (rid={}): {} entries",
                                    uid_i,
                                    hex::encode(bincode::serialize(&rid).unwrap()),
                                    map_for_me.len()
                                );
                                let packages: Vec<(String, String, String, String, String)> = map_for_me
                                    .iter()
                                    .map(|(from_id, (eph_hex, nonce_hex, ct_hex))| {
                                        let sig_hex = sigs_for_me.get(from_id).cloned().unwrap_or_default();
                                        (
                                            hex::encode(bincode::serialize(from_id).unwrap()),
                                            eph_hex.clone(),
                                            nonce_hex.clone(),
                                            ct_hex.clone(),
                                            sig_hex,
                                        )
                                    })
                                    .collect();
                                let msg = ServerMsg::Round2All { session: session_name.clone(), packages };
                                let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                            }
                        }
                    }
                }
            }
        }
        ClientMsg::FinalizeSubmit { session, id_hex, group_vk_sec1_hex, sig_ecdsa_hex } => {
            let uid = session_uid.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            {
                let s = inner
                    .sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown session"))?;
                // verify signed finalize
                let id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                // Ensure the sender's session uid matches the declared FROST identifier
                let expected_id = s.idmap.get(&uid).ok_or_else(|| anyhow!("no frost id for uid"))?;
                if *expected_id != id {
                    return Err(anyhow!("identifier/uid mismatch"));
                }
                let vk = s.ecdsa_pubs.get(&uid).ok_or_else(|| anyhow!("no ECDSA vk for uid"))?;
                let vk_bytes = hex::decode(&group_vk_sec1_hex)?;
                let payload = auth_payload_finalize(&session, &id, &vk_bytes);
                let sig = parse_sig_hex(&sig_ecdsa_hex)?;
                vk.verify_digest(Keccak256::new().chain_update(&payload), &sig)
                    .map_err(|_| anyhow!("ECDSA verify failed (finalize)"))?;

                // First finalize decides the VK; subsequent ones must match it
                if let Some(vk) = &s.agreed_vk {
                    if vk != &group_vk_sec1_hex {
                        println!(
                            "[server] WARNING: finalize mismatch from uid {}: got {}, expected {}",
                            uid, group_vk_sec1_hex, vk
                        );
                        return Err(anyhow!("group VK mismatch"));
                    }
                } else {
                    s.agreed_vk = Some(group_vk_sec1_hex.clone());
                }

                s.finalized_uids.insert(uid);
                println!(
                    "[server] Finalize progress: {}/{} (session={})",
                    s.finalized_uids.len(),
                    s.participants.len(),
                    s.session
                );

                if s.finalized_uids.len() == s.participants.len() {
                    let session_name = s.session.clone();
                    let recipients = s.participants.clone();
                    let finalized_vk = s.agreed_vk.clone();

                    if let Some(vk) = finalized_vk {
                        for uid_i in recipients {
                            if let Some(tx_i) = inner.conns.get(&uid_i) {
                                let msg = ServerMsg::Finalized { session: session_name.clone(), group_vk_sec1_hex: vk.clone() };
                                let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                            }
                        }
                    }
                }
            }
        }

        // ---- Interactive signing handlers ----
        ClientMsg::AnnounceSignSession { group_id, threshold, participants, participants_pubs, group_vk_sec1_hex, message_hex } => {
            let mut inner = state.inner.lock().await;
            if participants.is_empty() { return Err(anyhow!("participants cannot be empty")); }
            if threshold as usize > participants.len() { return Err(anyhow!("threshold cannot exceed participants")); }

            // Parse roster and build per-session map
            let mut session_ecdsa_pubs = BTreeMap::new();
            for (uid, pk_hex) in &participants_pubs {
                let bytes = hex::decode(pk_hex).context("roster pubkey hex")?;
                let vk = EcdsaVerifyingKey::from_sec1_bytes(&bytes)
                    .map_err(|_| anyhow!("bad ECDSA pub for uid {}", uid))?;
                if let Some(existing_uid) = inner.roster.get(&vk) {
                    if existing_uid != uid { return Err(anyhow!("pubkey for uid {} already registered for {}", uid, existing_uid)); }
                } else {
                    inner.roster.insert(vk.clone(), *uid);
                }
                session_ecdsa_pubs.insert(*uid, vk);
            }
            if !participants.iter().all(|u| session_ecdsa_pubs.contains_key(u)) {
                return Err(anyhow!("participants_pubs must include all uids"));
            }
            // Assign identifiers 1..=n for the session; actual KeyPackage ids must match in Join
            let mut idmap = HashMap::new();
            for (i, uid) in participants.iter().enumerate() {
                let fid: frost::Identifier = ((i + 1) as u16).try_into().unwrap();
                idmap.insert(*uid, fid);
            }
            // message digest (Keccak256)
            let msg_bytes = if let Some(h) = message_hex.strip_prefix("0x") { hex::decode(h)? } else { hex::decode(&message_hex)? };
            let msg32_vec = Keccak256::digest(&msg_bytes).to_vec();
            let mut msg32 = [0u8; 32];
            msg32.copy_from_slice(&msg32_vec);

            // Build roster snapshot for clients
            let mut roster_vec = Vec::new();
            for uid in &participants {
                let id_hex = hex::encode(bincode::serialize(&idmap[uid]).unwrap());
                let pk_hex = hex::encode(session_ecdsa_pubs[uid].to_encoded_point(true).as_bytes());
                roster_vec.push((*uid, id_hex, pk_hex));
            }

            let session = Uuid::new_v4().to_string();
            inner.sign_sessions.insert(session.clone(), SignSession {
                session: session.clone(),
                group_id: group_id.clone(),
                threshold,
                participants: participants.clone(),
                idmap,
                joined: HashSet::new(),
                ecdsa_pubs: session_ecdsa_pubs,
                vmap: BTreeMap::new(),
                commitments: BTreeMap::new(),
                sign_shares: BTreeMap::new(),
                group_vk_sec1_hex,
                msg32,
                roster_snapshot: roster_vec,
            });
            let _ = tx.send(Message::Text(serde_json::to_string(&ServerMsg::SignSessionCreated { session: session.clone() })?));
            // Start a 3-minute timeout for this signing session
            start_session_timeout(state.clone(), session.clone(), true);
        }
        ClientMsg::JoinSignSession { session, signer_id_bincode_hex, verifying_share_bincode_hex } => {
            let uid = session_uid.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            // Prepare broadcast data outside the mutable borrow scope
            let mut notify_all = false;
            let mut recipients: Vec<u32> = Vec::new();
            let mut msg_to_send: Option<ServerMsg> = None;

            {
                let s = inner
                    .sign_sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown signing session"))?;
                if !s.participants.contains(&uid) {
                    return Err(anyhow!("user not in allowed participants"));
                }
                // Parse id & verifying share
                let id: frost::Identifier = bincode::deserialize(&hex::decode(&signer_id_bincode_hex)?)?;
                // Ensure uid->id matches session idmap
                if let Some(exp) = s.idmap.get(&uid) {
                    if *exp != id {
                        return Err(anyhow!("identifier/uid mismatch in join"));
                    }
                } else {
                    s.idmap.insert(uid, id);
                }
                let vshare: frost::keys::VerifyingShare =
                    bincode::deserialize(&hex::decode(&verifying_share_bincode_hex)?)?;
                s.vmap.insert(id, vshare);
                s.joined.insert(uid);

                if s.joined.len() == s.participants.len() {
                    notify_all = true;
                    recipients = s.participants.clone();
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
                    for uid_i in recipients {
                        if let Some(tx_i) = inner.conns.get(&uid_i) {
                            let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                        }
                    }
                }
            }
        }
        ClientMsg::SignRound1Submit { session, id_hex, commitments_bincode_hex, sig_ecdsa_hex } => {
            let uid = session_uid.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            // Collect broadcast data after mutation
            let mut recipients: Vec<u32> = Vec::new();
            let mut session_name = String::new();
            let mut sp_hex = String::new();
            let mut ready = false;

            {
                let s = inner
                    .sign_sessions
                    .get_mut(&session)
                    .ok_or_else(|| anyhow!("unknown signing session"))?;
                let id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                let expected_id = s.idmap.get(&uid).ok_or_else(|| anyhow!("no id for uid"))?;
                if *expected_id != id {
                    return Err(anyhow!("identifier/uid mismatch"));
                }
                let vk = s
                    .ecdsa_pubs
                    .get(&uid)
                    .ok_or_else(|| anyhow!("no ECDSA vk for uid"))?;
                let payload = auth_payload_sign_r1(&session, &s.group_id, &id_hex, &commitments_bincode_hex);
                let sig = parse_sig_hex(&sig_ecdsa_hex)?;
                vk.verify_digest(Keccak256::new().chain_update(&payload), &sig)
                    .map_err(|_| anyhow!("ECDSA verify failed (sign r1)"))?;
                let commits: frost::round1::SigningCommitments =
                    bincode::deserialize(&hex::decode(&commitments_bincode_hex)?)?;
                s.commitments.insert(id, commits);
                if s.commitments.len() == s.participants.len() {
                    // Build SigningPackage and prepare for broadcast
                    let sp = frost::SigningPackage::new(s.commitments.clone(), &s.msg32);
                    sp_hex = hex::encode(bincode::serialize(&sp)?);
                    recipients = s.participants.clone();
                    session_name = s.session.clone();
                    ready = true;
                }
            }

            if ready {
                for uid_i in recipients {
                    if let Some(tx_i) = inner.conns.get(&uid_i) {
                        let msg = ServerMsg::SignSigningPackage { session: session_name.clone(), signing_package_bincode_hex: sp_hex.clone() };
                        let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                    }
                }
            }
        }
        ClientMsg::SignRound2Submit { session, id_hex, signature_share_bincode_hex, sig_ecdsa_hex } => {
            let uid = session_uid.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            // Split borrow scopes, prepare aggregation and broadcast payloads
            let (group_id, threshold, msg32_hex, group_vk_sec1_hex) = {
                let s = inner
                    .sign_sessions
                    .get(&session)
                    .ok_or_else(|| anyhow!("unknown signing session"))?;
                (
                    s.group_id.clone(),
                    s.threshold,
                    format!("0x{}", hex::encode(s.msg32)),
                    s.group_vk_sec1_hex.clone(),
                )
            };

            // Will collect broadcast payloads here
            let mut recipients: Vec<u32> = Vec::new();
            let mut session_name = String::new();
            let mut final_fields: Option<(String, String, String, String, String, String)> = None; // (sig_hex, px, py, rx, ry, s)

            {
                let s = inner.sign_sessions.get_mut(&session).unwrap();
                let id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                let expected_id = s.idmap.get(&uid).ok_or_else(|| anyhow!("no id for uid"))?;
                if *expected_id != id {
                    return Err(anyhow!("identifier/uid mismatch"));
                }
                let vk = s
                    .ecdsa_pubs
                    .get(&uid)
                    .ok_or_else(|| anyhow!("no ECDSA vk for uid"))?;
                let payload = auth_payload_sign_r2(&session, &group_id, &id_hex, &signature_share_bincode_hex, &msg32_hex);
                let sig = parse_sig_hex(&sig_ecdsa_hex)?;
                vk.verify_digest(Keccak256::new().chain_update(&payload), &sig)
                    .map_err(|_| anyhow!("ECDSA verify failed (sign r2)"))?;
                let sshare: frost::round2::SignatureShare =
                    bincode::deserialize(&hex::decode(&signature_share_bincode_hex)?)?;
                s.sign_shares.insert(id, sshare);

                if s.sign_shares.len() >= threshold as usize {
                    // Aggregate and prepare broadcast payload
                    let group_vk_bytes = hex::decode(&group_vk_sec1_hex)?;
                    let group_vk = frost::VerifyingKey::deserialize(&group_vk_bytes)
                        .map_err(|e| anyhow!("group verifying key deserialize failed: {e}"))?;
                    let pubkey_package = frost::keys::PublicKeyPackage::new(s.vmap.clone(), group_vk);
                    let sp = frost::SigningPackage::new(s.commitments.clone(), &s.msg32);
                    let sig_final = frost::aggregate(&sp, &s.sign_shares, &pubkey_package)?;
                    let sig_hex = hex::encode(bincode::serialize(&sig_final)?);
                    // Extract px,py,rx,ry,s similar to offchain-verify
                    let vk_parsed = k256::PublicKey::from_sec1_bytes(&group_vk_bytes)?;
                    let vk_unc = vk_parsed.to_encoded_point(false);
                    let px = format!("0x{}", hex::encode(vk_unc.x().unwrap()));
                    let py = format!("0x{}", hex::encode(vk_unc.y().unwrap()));
                    let r_aff = sig_final.R().to_affine();
                    let r_pt = r_aff.to_encoded_point(false);
                    let rx = format!("0x{}", hex::encode(r_pt.x().unwrap()));
                    let ry = format!("0x{}", hex::encode(r_pt.y().unwrap()));
                    let s_field = {
                        let z_bytes = frost::Secp256K1ScalarField::serialize(sig_final.z());
                        format!("0x{}", hex::encode(z_bytes))
                    };
                    recipients = s.participants.clone();
                    session_name = s.session.clone();
                    final_fields = Some((sig_hex, px, py, rx, ry, s_field));
                }
            }

            if let Some((sig_hex, px, py, rx, ry, s_field)) = final_fields {
                for uid_i in recipients {
                    if let Some(tx_i) = inner.conns.get(&uid_i) {
                        let msg = ServerMsg::SignatureReady {
                            session: session_name.clone(),
                            signature_bincode_hex: sig_hex.clone(),
                            px: px.clone(),
                            py: py.clone(),
                            rx: rx.clone(),
                            ry: ry.clone(),
                            s: s_field.clone(),
                            message: format!("0x{}", hex::encode(hex::decode(msg32_hex.trim_start_matches("0x")).unwrap())),
                        };
                        let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                    }
                }
            }
        }
    }
    Ok(())
}
