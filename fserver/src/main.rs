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
use frost_secp256k1 as frost;
use futures::{sink::SinkExt, stream::StreamExt};
use k256::ecdsa::{Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use signature::DigestVerifier;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, Notify};
use tokio::time::{sleep, Duration};
use uuid::Uuid;

// -------- ECDSA auth helpers (source integrity & authentication) --------
fn auth_payload_round1(
    topic: &str,
    id: &frost::Identifier,
    pkg: &frost::keys::dkg::round1::Package,
) -> Vec<u8> {
    let mut v = b"TOKAMAK_FROST_DKG_R1|".to_vec();
    v.extend_from_slice(topic.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(id).unwrap());
    v.extend_from_slice(&bincode::serialize(pkg).unwrap());
    v
}
fn auth_payload_round2(
    topic: &str,
    from: &frost::Identifier,
    to: &frost::Identifier,
    eph_pub_sec1: &[u8],
    nonce: &[u8],
    ct: &[u8],
) -> Vec<u8> {
    // Sign the encrypted envelope (not the plaintext): topic | from | to | eph_pub | nonce | ct
    let mut v = b"TOKAMAK_FROST_DKG_R2|".to_vec();
    v.extend_from_slice(topic.as_bytes());
    v.extend_from_slice(b"|");
    v.extend_from_slice(&bincode::serialize(from).unwrap());
    v.extend_from_slice(&bincode::serialize(to).unwrap());
    v.extend_from_slice(eph_pub_sec1);
    v.extend_from_slice(nonce);
    v.extend_from_slice(ct);
    v
}
fn auth_payload_finalize(topic: &str, id: &frost::Identifier, group_vk_sec1: &[u8]) -> Vec<u8> {
    let mut v = b"TOKAMAK_FROST_DKG_FIN|".to_vec();
    v.extend_from_slice(topic.as_bytes());
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
    AnnounceTopic {
        topic: String,
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
    JoinTopic {
        topic: String,
    },

    // DKG round messages
    Round1Submit {
        topic: String,
        id_hex: String,
        pkg_bincode_hex: String,
        sig_ecdsa_hex: String,
    },
    Round2Submit {
        topic: String,
        id_hex: String,
        // encrypted triples: (recipient_id_hex, eph_pub_sec1_hex, nonce_hex, ct_hex, sig_hex)
        pkgs_cipher_hex: Vec<(String, String, String, String, String)>,
    },
    FinalizeSubmit {
        topic: String,
        id_hex: String,
        group_vk_sec1_hex: String,
        sig_ecdsa_hex: String,
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
    LoginOk {
        user_id: u32,
        access_token: String,
    },

    // Signals
    ReadyRound1 {
        topic: String,
        id_hex: String,
        min_signers: u16,
        max_signers: u16,
        group_id: String,
        // (uid, id_hex, ecdsa_pub_sec1_hex)
        roster: Vec<(u32, String, String)>,
    },
    Round1All {
        topic: String,
        // (id_hex, pkg_bincode_hex, sig_ecdsa_hex)
        packages: Vec<(String, String, String)>,
    },
    ReadyRound2 {
        topic: String,
    },
    Round2All {
        topic: String,
        // encrypted tuples: (from_id_hex, eph_pub_sec1_hex, nonce_hex, ct_hex, sig_ecdsa_hex)
        packages: Vec<(String, String, String, String, String)>,
    },
    Finalized {
        topic: String,
        group_vk_sec1_hex: String,
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
    // This is populated when topics are created.
    roster: BTreeMap<EcdsaVerifyingKey, u32>,

    // active connections by uid
    conns: HashMap<u32, Tx>,

    // active challenges to prevent reuse
    challenges: HashSet<String>,

    // active tokens
    active_tokens: HashMap<String, u32>, // token -> uid

    // topics
    topics: HashMap<String, Topic>,
}

struct Topic {
    topic: String,
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
        BTreeMap<frost::Identifier, (String, String, String)>,>,

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

impl Default for Inner {
    fn default() -> Self {
        Self {
            roster: BTreeMap::new(),
            conns: HashMap::new(),
            challenges: HashSet::new(),
            active_tokens: HashMap::new(),
            topics: HashMap::new(),
        }
    }
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
        .route("/close", get(close_handler)) // NEW
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
        ClientMsg::AnnounceTopic {
            topic,
            min_signers,
            max_signers,
            group_id,
            participants,
            participants_pubs,
        } => {
            let mut inner = state.inner.lock().await;
            if inner.topics.contains_key(&topic) {
                return Err(anyhow!("topic already exists"));
            }
            if participants.len() != max_signers as usize {
                return Err(anyhow!("participants length must equal max_signers"));
            }

            // Populate server-wide roster and topic-specific key map.
            let mut topic_ecdsa_pubs = BTreeMap::new();
            for (p_uid, p_pk_hex) in &participants_pubs {
                let p_pk_bytes = hex::decode(p_pk_hex).context("roster pubkey hex")?;
                let p_vk = EcdsaVerifyingKey::from_sec1_bytes(&p_pk_bytes)
                    .map_err(|_| anyhow!("bad ECDSA pub for uid {}", p_uid))?;

                // Add to server-wide roster if not present, or verify consistency.
                if let Some(existing_uid) = inner.roster.get(&p_vk) {
                    if existing_uid != p_uid {
                        return Err(anyhow!(
                            "pubkey for uid {} is already registered with a different uid {}",
                            p_uid,
                            existing_uid
                        ));
                    }
                } else {
                    inner.roster.insert(p_vk.clone(), *p_uid);
                }
                topic_ecdsa_pubs.insert(*p_uid, p_vk);
            }

            if !participants.iter().all(|u| topic_ecdsa_pubs.contains_key(u)) {
                return Err(anyhow!("participants_pubs must include all uids"));
            }

            // build id map 1..=n based on order
            let mut idmap = HashMap::new();
            for (i, uid_i) in participants.iter().enumerate() {
                let fid: frost::Identifier = ((i + 1) as u16).try_into().unwrap();
                idmap.insert(*uid_i, fid);
            }
            let topic_obj = Topic {
                topic: topic.clone(),
                min_signers,
                max_signers,
                group_id,
                participants: participants.clone(),
                idmap,
                joined: HashSet::new(),
                r1_pkgs: BTreeMap::new(),
                r2_inbox: BTreeMap::new(),
                // finalization tracking
                finalized_uids: HashSet::new(),
                agreed_vk: None,
                ecdsa_pubs: topic_ecdsa_pubs,
                r1_sigs: BTreeMap::new(),
                r2_sigs: BTreeMap::new(),
            };
            inner.topics.insert(topic.clone(), topic_obj);
            println!("[server] Announced topic '{}'", topic);
        }
        ClientMsg::RequestChallenge => {
            let mut inner = state.inner.lock().await;
            let challenge = Uuid::new_v4().to_string();
            inner.challenges.insert(challenge.clone());

            let _ = tx.send(Message::Text(serde_json::to_string(&ServerMsg::Challenge {
                challenge,
            })?));
        }
        ClientMsg::Login {
            challenge,
            pubkey_hex,
            signature_hex,
        } => {
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
                None => return Err(anyhow!("public key not registered in any topic roster")),
            };

            if inner.conns.contains_key(&uid) {
                return Err(anyhow!("user {} is already logged in", uid));
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
        ClientMsg::JoinTopic { topic } => {
            let uid = session_uid.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            // Variables we will use after dropping the mutable borrow of the topic entry
            let mut notify_all = false;
            let mut topic_name = String::new();
            let mut group_label = String::new();
            let mut min_s = 0u16;
            let mut max_s = 0u16;
            let mut roster_vec = Vec::new();

            {
                let t = inner
                    .topics
                    .get_mut(&topic)
                    .ok_or_else(|| anyhow!("unknown topic"))?;
                if !t.participants.contains(&uid) {
                    return Err(anyhow!("user not in allowed participants"));
                }
                t.joined.insert(uid);
                let joined_count = t.joined.len();
                let total_count = t.participants.len();
                if joined_count == total_count {
                    notify_all = true;
                    topic_name = t.topic.clone();
                    group_label = t.group_id.clone();
                    min_s = t.min_signers;
                    max_s = t.max_signers;
                    // build roster: (uid, id_hex, ecdsa_pub_sec1_hex)
                    let mut roster = Vec::new();
                    for uid_i in &t.participants {
                        let id_hex = hex::encode(bincode::serialize(&t.idmap[uid_i]).unwrap());
                        let pk_hex = hex::encode(
                            t.ecdsa_pubs[uid_i].to_encoded_point(true).as_bytes()
                        );
                        roster.push((*uid_i, id_hex, pk_hex));
                    }
                    roster_vec = roster;
                } else {
                     let _ = tx.send(Message::Text(serde_json::to_string(&ServerMsg::Info {
                        message: format!("joined {}/{}", joined_count, total_count),
                    })?));
                }
            } // drop mutable borrow of the topic

            if notify_all {
                // Snapshot data and roster for all
                for uid_i in inner.topics[&topic].participants.clone() {
                    if let Some(tx_i) = inner.conns.get(&uid_i) {
                        // each recipient's own id_hex
                        let id_hex_for = hex::encode(
                            bincode::serialize(&inner.topics[&topic].idmap[&uid_i]).unwrap()
                        );
                        let msg = ServerMsg::ReadyRound1 {
                            topic: topic_name.clone(),
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
        ClientMsg::Round1Submit {
            topic,
            id_hex,
            pkg_bincode_hex,
            sig_ecdsa_hex,
        } => {
            let uid = session_uid.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            let packages: Vec<(String, String, String)>;

            {
                let t = inner
                    .topics
                    .get_mut(&topic)
                    .ok_or_else(|| anyhow!("unknown topic"))?;
                let id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                let pkg: frost::keys::dkg::round1::Package =
                    bincode::deserialize(&hex::decode(&pkg_bincode_hex)?)?;
                // Ensure the sender's session uid matches the declared FROST identifier
                let expected_id = t.idmap.get(&uid).ok_or_else(|| anyhow!("no frost id for uid"))?;
                if *expected_id != id {
                    return Err(anyhow!("identifier/uid mismatch"));
                }
                // verify ECDSA
                let payload = auth_payload_round1(&topic, &id, &pkg);
                let sig = parse_sig_hex(&sig_ecdsa_hex)?;
                let vk = t.ecdsa_pubs.get(&uid).ok_or_else(|| anyhow!("no ECDSA vk for uid"))?;
                vk.verify_digest(Keccak256::new().chain_update(&payload), &sig)
                    .map_err(|_| anyhow!("ECDSA verify failed (round1)"))?;
                t.r1_pkgs.insert(id, pkg);
                t.r1_sigs.insert(id, sig_ecdsa_hex);
                let have = t.r1_pkgs.len();
                let need = t.participants.len();
                println!("[server] R1 submit: have {have}/{need} (topic={})", t.topic);
                if t.r1_pkgs.len() != t.participants.len() {
                    return Ok(());
                }
                let topic_name = t.topic.clone();
                let recipients = t.participants.clone();
                packages = t
                    .r1_pkgs
                    .iter()
                    .map(|(i, p)| {
                        let sig_hex = t.r1_sigs.get(i).cloned().unwrap_or_default();
                        (
                            hex::encode(bincode::serialize(i).unwrap()),
                            hex::encode(bincode::serialize(p).unwrap()),
                            sig_hex,
                        )
                    })
                    .collect();
                println!(
                    "[server] Broadcasting Round1All: {} packages (topic={})",
                    packages.len(),
                    t.topic
                );

                for uid_i in recipients {
                    if let Some(tx_i) = inner.conns.get(&uid_i) {
                        let msg = ServerMsg::Round1All {
                            topic: topic_name.clone(),
                            packages: packages.clone(),
                        };
                        let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                        let _ = tx_i.send(Message::Text(serde_json::to_string(
                            &ServerMsg::ReadyRound2 {
                                topic: topic_name.clone(),
                            },
                        )?));
                    }
                }
            } // drop t
        }
        ClientMsg::Round2Submit {
            topic,
            id_hex,
            // encrypted triples: (recipient_id_hex, eph_pub_sec1_hex, nonce_hex, ct_hex, sig_hex)
            pkgs_cipher_hex,
        } => {
            let mut inner = state.inner.lock().await;

            {
                let t = inner
                    .topics
                    .get_mut(&topic)
                    .ok_or_else(|| anyhow!("unknown topic"))?;
                let from_id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                let uid = session_uid.ok_or_else(|| anyhow!("must login first"))?;
                // Ensure the sender's session uid matches the declared FROST identifier
                let expected_id = t.idmap.get(&uid).ok_or_else(|| anyhow!("no frost id for uid"))?;
                if *expected_id != from_id {
                    return Err(anyhow!("identifier/uid mismatch"));
                }
                let vk = t.ecdsa_pubs.get(&uid).ok_or_else(|| anyhow!("no ECDSA vk for uid"))?;
                // Insert each outgoing encrypted pkg into recipient inbox
                for (rid_hex, eph_pub_hex, nonce_hex, ct_hex, sig_hex) in pkgs_cipher_hex {
                    let rid: frost::Identifier = bincode::deserialize(&hex::decode(&rid_hex)?)?;
                    let eph_pub = hex::decode(&eph_pub_hex)?;
                    let nonce = hex::decode(&nonce_hex)?;
                    let ct = hex::decode(&ct_hex)?;
                    // verify ECDSA over the encrypted envelope
                    let payload = auth_payload_round2(&topic, &from_id, &rid, &eph_pub, &nonce, &ct);
                    let sig = parse_sig_hex(&sig_hex)?;
                    vk.verify_digest(Keccak256::new().chain_update(&payload), &sig)
                        .map_err(|_| anyhow!("ECDSA verify failed (round2)"))?;
                    // Store ciphertext triplet for targeted dispatch
                    t.r2_inbox
                        .entry(rid)
                        .or_insert_with(BTreeMap::new)
                        .insert(from_id, (eph_pub_hex, nonce_hex, ct_hex));
                    t.r2_sigs
                        .entry(rid)
                        .or_insert_with(BTreeMap::new)
                        .insert(from_id, sig_hex);
                }

                // Debug: show per-recipient inbox sizes so clients can see progress
                for (uid_i, rid) in t.participants.iter().map(|uid_i| (*uid_i, t.idmap[uid_i])) {
                    let cur = t.r2_inbox.get(&rid).map(|m| m.len()).unwrap_or(0);
                    println!(
                        "[server] R2 inbox for uid {uid_i} (rid={}): {}/?",
                        hex::encode(bincode::serialize(&rid).unwrap()),
                        cur
                    );
                }

                // Check if every recipient has N-1 packages (from all other participants)
                let need = t.participants.len().saturating_sub(1);
                let ready_for_all = t
                    .idmap
                    .values()
                    .all(|rid| t.r2_inbox.get(rid).map(|m| m.len()).unwrap_or(0) == need);

                if ready_for_all {
                    let topic_name = t.topic.clone();
                    // Snapshot recipients with their frost identifiers for targeted dispatch
                    let recipients: Vec<(u32, frost::Identifier)> = t
                        .participants
                        .iter()
                        .map(|uid_i| (*uid_i, t.idmap[uid_i]))
                        .collect();
                    println!(
                        "[server] All R2 ready: dispatching targeted Round2All (topic={})",
                        t.topic
                    );

                    // Targeted broadcast: each participant receives only the packages destined for them
                    for (uid_i, rid) in recipients {
                        if let Some(tx_i) = inner.conns.get(&uid_i) {
                            if let Some(map_for_me) = inner
                                .topics
                                .get(&topic_name)
                                .and_then(|t| t.r2_inbox.get(&rid))
                            {
                                let sigs_for_me = inner
                                    .topics
                                    .get(&topic_name)
                                    .and_then(|t| t.r2_sigs.get(&rid))
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
                                let msg = ServerMsg::Round2All {
                                    topic: topic_name.clone(),
                                    packages,
                                };
                                let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                            }
                        }
                    }
                }
            } // drop t
        }
        ClientMsg::FinalizeSubmit {
            topic,
            id_hex,
            group_vk_sec1_hex,
            sig_ecdsa_hex,
        } => {
            let uid = session_uid.ok_or_else(|| anyhow!("must login first"))?;
            let mut inner = state.inner.lock().await;

            {
                let t = inner
                    .topics
                    .get_mut(&topic)
                    .ok_or_else(|| anyhow!("unknown topic
"))?;
                // verify signed finalize
                let id: frost::Identifier = bincode::deserialize(&hex::decode(&id_hex)?)?;
                // Ensure the sender's session uid matches the declared FROST identifier
                let expected_id = t.idmap.get(&uid).ok_or_else(|| anyhow!("no frost id for uid"))?;
                if *expected_id != id {
                    return Err(anyhow!("identifier/uid mismatch"));
                }
                let vk = t.ecdsa_pubs.get(&uid).ok_or_else(|| anyhow!("no ECDSA vk for uid"))?;
                let vk_bytes = hex::decode(&group_vk_sec1_hex)?;
                let payload = auth_payload_finalize(&topic, &id, &vk_bytes);
                let sig = parse_sig_hex(&sig_ecdsa_hex)?;
                vk.verify_digest(Keccak256::new().chain_update(&payload), &sig)
                    .map_err(|_| anyhow!("ECDSA verify failed (finalize)"))?;

                // First finalize decides the VK; subsequent ones must match it
                if let Some(vk) = &t.agreed_vk {
                    if vk != &group_vk_sec1_hex {
                        println!(
                            "[server] WARNING: finalize mismatch from uid {}: got {}, expected {}",
                            uid, group_vk_sec1_hex, vk
                        );
                        return Err(anyhow!("group VK mismatch"));
                    }
                } else {
                    t.agreed_vk = Some(group_vk_sec1_hex.clone());
                }

                t.finalized_uids.insert(uid);
                println!(
                    "[server] Finalize progress: {}/{} (topic={})",
                    t.finalized_uids.len(),
                    t.participants.len(),
                    t.topic
                );

                if t.finalized_uids.len() == t.participants.len() {
                    let topic_name = t.topic.clone();
                    let recipients = t.participants.clone();
                    let finalized_vk = t.agreed_vk.clone();

                    if let Some(vk) = finalized_vk {
                        for uid_i in recipients {
                            if let Some(tx_i) = inner.conns.get(&uid_i) {
                                let msg = ServerMsg::Finalized {
                                    topic: topic_name.clone(),
                                    group_vk_sec1_hex: vk.clone(),
                                };
                                let _ = tx_i.send(Message::Text(serde_json::to_string(&msg)?));
                            }
                        }
                    }
                }
            } // drop t
        }
    }
    Ok(())
}
