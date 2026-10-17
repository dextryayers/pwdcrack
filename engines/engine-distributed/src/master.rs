//! The master: accept peers, admit them, give them work, collect results.
//!
//! # Shape
//!
//! One task owns a connection and nothing else writes to that socket. Everything
//! that wants to send something to a worker sends a [`Command`] down a channel
//! the connection task owns. That was not the previous design: the accept loop,
//! the background reaper and the result handler all wrote to the same
//! `TcpStream`, from different tasks, with no ordering between them. Two
//! `write_all` calls can interleave at any byte boundary, so a work unit and a
//! heartbeat could be written into each other. Having exactly one writer per
//! socket makes that impossible rather than unlikely.
//!
//! The background [`dispatch`] task owns the decisions: who is dead, who is
//! idle, and which chunk each idle worker gets. It holds no sockets.
//!
//! # Order of events on one connection
//!
//! 1. TLS, if configured.
//! 2. Rate limit check against the peer's source address. A refusal sends an
//!    `Error` and closes; nothing is read, so a guessing peer cannot make the
//!    master hash anything.
//! 3. `Challenge` with a fresh nonce and the master's schema version.
//! 4. `Authenticate`, if the cluster has a token.
//! 5. `Handshake`, carrying the worker's schema version. A mismatch closes here,
//!    before the peer is in the worker table.
//! 6. The master pushes any wordlists this run uses, then work.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time;

use crate::admission::{Admission, AdmissionGate};
use crate::checkpoint::{Checkpoint, CheckpointStore, InFlightState};
use crate::codec::{self, Link, ProtoError};
use crate::liveness::{self, Liveness, WorkerLiveness};
use crate::netpolicy::ClusterAuth;
use crate::protocol::{
    AttackType, Capabilities, CrackedEntry, ErrorCode, Message, TargetHash, WorkUnit,
    WorkerStats, SCHEMA_VERSION,
};
use crate::ratelimit::{Decision, RateLimiter};
use crate::scheduler::{Chunk, ChunkPolicy, Scheduler, Span};
use crate::tls::ClusterTls;
use crate::wordlist::WordlistManifest;

/// How often the dispatcher looks at the cluster.
const DISPATCH_TICK: Duration = Duration::from_millis(200);

/// Commands the dispatcher sends to a connection task.
#[derive(Debug, Clone)]
pub enum Command {
    Assign { worker_id: u64, batch_id: u64, work: WorkUnit },
    Wordlist { manifest: WordlistManifest, words: Vec<String> },
    HeartbeatAck {
        server_time_ms: u64,
        next_heartbeat_ms: u64,
        missed: u32,
    },
    Error { code: ErrorCode, detail: String },
    Shutdown { reason: String },
}

/// A wordlist this run uses, keyed by the SHA-256 of its contents.
#[derive(Debug, Clone)]
pub struct WordlistBundle {
    pub manifest: WordlistManifest,
    pub words: Vec<String>,
}

/// Tunables, all with defaults that work on loopback.
#[derive(Debug, Clone)]
pub struct ClusterPolicy {
    /// How often the dispatcher sweeps liveness and sends heartbeat acks.
    pub heartbeat: Duration,
    /// How often the checkpoint is written.
    pub checkpoint_interval: Duration,
    /// Chunk sizing. See [`crate::scheduler::ChunkPolicy`].
    pub chunk: ChunkPolicy,
    /// Largest accepted or produced frame.
    pub max_frame: usize,
    /// Sustained handshake attempts per source address.
    pub handshake_rate_per_sec: f64,
    /// Burst allowance per source address.
    pub handshake_burst: f64,
}

impl Default for ClusterPolicy {
    fn default() -> Self {
        ClusterPolicy {
            heartbeat: Duration::from_secs(5),
            checkpoint_interval: Duration::from_secs(15),
            chunk: ChunkPolicy::default(),
            max_frame: codec::DEFAULT_MAX_FRAME,
            handshake_rate_per_sec: crate::ratelimit::DEFAULT_RATE_PER_SEC,
            handshake_burst: crate::ratelimit::DEFAULT_BURST,
        }
    }
}

/// State shared by the accept loop, every connection task, and the dispatcher.
///
/// One value rather than six `Arc<Mutex<_>>` parameters, because a handler that
/// takes six of them is a handler whose parameters get transposed at some point.
#[derive(Clone)]
pub struct Shared {
    pub workers: Arc<Mutex<HashMap<String, WorkerInfo>>>,
    pub scheduler: Arc<Mutex<Scheduler>>,
    pub in_flight: Arc<Mutex<HashMap<u64, InFlightWork>>>,
    pub completed: Arc<Mutex<Vec<CrackedEntry>>>,
    /// Wordlists pushed to workers, keyed by content digest.
    pub wordlists: Arc<Mutex<HashMap<String, WordlistBundle>>>,
    pub limiter: Arc<Mutex<RateLimiter>>,
    pub store: CheckpointStore,
    pub policy: ClusterPolicy,
    token: Option<String>,
    next_batch_id: Arc<AtomicU64>,
}

impl Shared {
    pub fn new(store: CheckpointStore, policy: ClusterPolicy, token: Option<String>) -> Self {
        let scheduler = Scheduler::new(policy.chunk);
        Shared {
            workers: Arc::new(Mutex::new(HashMap::new())),
            scheduler: Arc::new(Mutex::new(scheduler)),
            in_flight: Arc::new(Mutex::new(HashMap::new())),
            completed: Arc::new(Mutex::new(Vec::new())),
            wordlists: Arc::new(Mutex::new(HashMap::new())),
            limiter: Arc::new(Mutex::new(RateLimiter::new())),
            store,
            policy,
            token,
            next_batch_id: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// Adds a wordlist to push to workers, and registers the job's use of it.
    ///
    /// Refuses a bundle whose manifest does not match its own bytes, so a
    /// mismatch is caught by the master that built it rather than by the first
    /// worker that receives it.
    pub async fn register_wordlist(
        &self,
        manifest: WordlistManifest,
        words: Vec<String>,
    ) -> Result<(), String> {
        let joined = words.join("\n");
        manifest
            .verify(joined.as_bytes())
            .map_err(|e| format!("wordlist {} does not match its manifest: {e}", manifest.name))?;
        self.wordlists
            .lock()
            .await
            .insert(manifest.sha256.clone(), WordlistBundle { manifest, words });
        Ok(())
    }

    /// Replaces the rate limiter, which [`Shared::new`] builds with defaults
    /// because it cannot see the cluster policy.
    pub fn set_limiter(&mut self, limiter: RateLimiter) {
        self.limiter = Arc::new(Mutex::new(limiter));
    }

    /// Builds a fresh gate for one connection.
    pub fn gate(&self) -> AdmissionGate {
        AdmissionGate::new(ClusterAuth::from_optional(self.token.as_deref()))
    }
}

/// A batch handed to a worker.
#[derive(Debug, Clone)]
pub struct InFlightWork {
    pub batch_id: u64,
    pub job_id: u64,
    pub worker_name: String,
    pub work: WorkUnit,
    pub span: Span,
    pub assigned_at: Instant,
}

/// What the master knows about one worker.
pub struct WorkerInfo {
    pub addr: String,
    pub caps: Capabilities,
    pub stats: WorkerStats,
    /// Smoothed throughput, the scheduler's input.
    pub rate: crate::scheduler::RateSample,
    pub live: WorkerLiveness,
    pub busy: bool,
    pub current_batch: Option<u64>,
    pub authenticated: bool,
    /// Digests already pushed on this connection.
    pub wordlists_sent: BTreeSet<String>,
    /// Where the dispatcher sends commands.
    pub tx: mpsc::Sender<Command>,
}

/// A short name for a frame, for an error message about which one arrived too
/// early.
fn frame_kind(msg: &Message) -> &'static str {
    codec::code_of(msg).name()
}

/// The master.
pub struct MasterNode {
    pub listen_addr: String,
    pub shared: Shared,
    tls: Option<ClusterTls>,
}

impl MasterNode {
    /// Builds a master.
    ///
    /// `auth` decides which connections may join. An unauthenticated cluster
    /// admits anyone who connects, which is only acceptable on loopback, and
    /// [`crate::netpolicy::BindPolicy`] is what enforces that.
    pub fn new(listen_addr: &str, checkpoint_path: &str, auth: ClusterAuth) -> Self {
        Self::with_policy(
            listen_addr,
            CheckpointStore::new(checkpoint_path),
            ClusterPolicy::default(),
            auth,
        )
    }

    pub fn with_policy(
        listen_addr: &str,
        store: CheckpointStore,
        policy: ClusterPolicy,
        auth: ClusterAuth,
    ) -> Self {
        let token = auth.token().map(|t| t.to_string());
        // The limiter is built from the policy rather than from defaults, so an
        // operator widening `--handshake-rate` sees the limiter follow.
        let mut limiter = RateLimiter::with_limits(
            policy.handshake_rate_per_sec,
            policy.handshake_burst,
            crate::ratelimit::DEFAULT_IDLE_TIMEOUT,
            crate::ratelimit::DEFAULT_MAX_ADDRESSES,
        );
        limiter.reset_stats();
        let mut shared = Shared::new(store, policy, token);
        // `Shared::new` stores a default limiter; swap in the configured one
        // before anything can consult it.
        shared.set_limiter(limiter);
        MasterNode {
            listen_addr: listen_addr.to_string(),
            shared,
            tls: None,
        }
    }

    /// Enables TLS, generating a certificate on the master's first run.
    pub fn with_tls(mut self, tls: ClusterTls) -> Self {
        self.tls = Some(tls);
        self
    }

    /// True when this master requires workers to prove a shared token.
    pub fn requires_authentication(&self) -> bool {
        self.shared.token().is_some()
    }

    pub async fn worker_count(&self) -> usize {
        self.shared.workers.lock().await.len()
    }

    pub async fn available_workers(&self) -> Vec<String> {
        let workers = self.shared.workers.lock().await;
        let mut names: Vec<String> = workers
            .iter()
            .filter(|(_, i)| !i.busy)
            .map(|(n, _)| n.clone())
            .collect();
        names.sort();
        names
    }

    /// Hashes found so far, deduplicated by hash value.
    pub async fn cracked(&self) -> Vec<CrackedEntry> {
        let c = self.shared.completed.lock().await;
        let mut v = c.clone();
        v.sort_by(|a, b| a.hash.cmp(&b.hash).then(a.password.cmp(&b.password)));
        v.dedup_by(|a, b| a.hash == b.hash);
        v
    }

    /// Candidates still unassigned.
    pub async fn free_total(&self) -> u64 {
        self.shared.scheduler.lock().await.free_total()
    }

    /// Overlapping spans the scheduler has issued. Zero in a clean run.
    pub async fn issued_overlaps(&self) -> u64 {
        self.shared
            .scheduler
            .lock()
            .await
            .ledger()
            .map(|l| l.overlaps())
            .unwrap_or(0)
    }

    /// Adds a job and returns its id.
    pub async fn add_job(
        &self,
        attack: AttackType,
        targets: Vec<TargetHash>,
        keyspace: u64,
    ) -> Result<u64, String> {
        let mut sched = self.shared.scheduler.lock().await;
        sched.add_job(attack, targets, keyspace)
    }

    /// Restores state from the checkpoint, returning whether anything was
    /// restored.
    pub async fn resume_from_store(&self) -> Result<bool, String> {
        let cp = match self
            .shared
            .store
            .load()
            .map_err(|e| format!("checkpoint could not be read: {e}"))?
        {
            Some(cp) => cp,
            None => return Ok(false),
        };
        self.restore(cp).await;
        Ok(true)
    }

    /// Restores an explicit checkpoint. Exposed so a test can resume without
    /// going through the filesystem.
    pub async fn restore(&self, cp: Checkpoint) {
        let next_batch_id = cp.next_batch_id;
        let next_job_id = cp.next_job_id;
        let (jobs, completed) = cp.into_jobs();
        {
            let mut sched = self.shared.scheduler.lock().await;
            sched.note_counters(next_batch_id, next_job_id);
            for j in jobs {
                sched.restore_job(j);
            }
            sched.start_ledger();
        }
        *self.shared.completed.lock().await = completed;
        log::info!(
            "Checkpoint loaded: {} previously cracked, {} candidates still to test",
            self.shared.completed.lock().await.len(),
            self.free_total().await
        );
    }

    /// Writes the checkpoint now.
    pub async fn save_checkpoint(&self) -> Result<(), String> {
        let jobs = self.shared.scheduler.lock().await.snapshot();
        let inflight: Vec<InFlightState> = self
            .shared
            .in_flight
            .lock()
            .await
            .values()
            .map(|f| InFlightState {
                batch_id: f.batch_id,
                job_id: f.job_id,
                span: f.span.into(),
                worker_name: f.worker_name.clone(),
            })
            .collect();
        let completed = self.shared.completed.lock().await.clone();
        let next_batch_id = self.shared.next_batch_id.load(Ordering::SeqCst);
        let next_job_id = self.shared.scheduler.lock().await.next_batch_id();
        let cp = Checkpoint::capture(
            &jobs,
            inflight,
            completed,
            next_batch_id,
            next_job_id,
        );
        self.shared
            .store
            .save(&cp)
            .map_err(|e| format!("checkpoint could not be written: {e}"))?;
        log::info!(
            "Checkpoint saved to {}: {} cracked, {} in flight, {} candidates left",
            self.shared.store.path().display(),
            cp.completed.len(),
            cp.in_flight.len(),
            jobs.iter().map(|j| j.free.total()).sum::<u64>()
        );
        Ok(())
    }

    /// Serves one already accepted connection through the same path the accept
    /// loop uses: rate limit, TLS, admission, work.
    ///
    /// Exposed so a test can bind its own listener on a port the OS chose and
    /// drive the real handler. A test that reimplements the path proves nothing
    /// about the accept loop, which is where the rate limit lives.
    #[doc(hidden)]
    pub async fn serve_for_test(&self, socket: TcpStream) -> Result<(), String> {
        let ip = socket.peer_addr().map(|a| a.ip()).unwrap_or(std::net::IpAddr::from([0, 0, 0, 0]));
        admit_and_serve(self.shared.clone(), self.tls.clone(), socket, ip).await
    }

    /// Accepts connections until the process ends.
    pub async fn run(&self) -> Result<(), String> {
        let listener = TcpListener::bind(&self.listen_addr)
            .await
            .map_err(|e| format!("cannot bind {}: {e}", self.listen_addr))?;
        let bound = listener
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| self.listen_addr.clone());
        log::info!("Master listening on {bound}");
        if let Some(tls) = &self.tls {
            log::info!("Cluster TLS is on, master certificate {}", tls_server_fingerprint(tls));
        }

        {
            // Start the ledger for the common single job case so deduplication
            // is checkable from a real run.
            self.shared.scheduler.lock().await.start_ledger();
        }

        self.shared
            .store
            .load()
            .map_err(|e| format!("checkpoint could not be read: {e}"))?;
        tokio::spawn(dispatch(self.shared.clone()));

        loop {
            let (socket, addr) = listener
                .accept()
                .await
                .map_err(|e| format!("accept failed: {e}"))?;
            let shared = self.shared.clone();
            let tls = self.tls.clone();
            let ip = addr.ip();
            tokio::spawn(async move {
                match admit_and_serve(shared.clone(), tls, socket, ip).await {
                    Ok(()) => {}
                    Err(e) => log::debug!("connection from {addr} closed: {e}"),
                }
            });
        }
    }
}

fn tls_server_fingerprint(tls: &ClusterTls) -> String {
    match tls {
        ClusterTls::Server(s) => s.fingerprint.clone(),
        ClusterTls::Client(_) => "<not a server>".to_string(),
    }
}

/// Rate limits, then serves one connection.
///
/// The rate limit is here rather than inside the connection task so a refused
/// peer costs one `accept` and one map lookup, and never a read, a hash or a
/// log line per frame.
async fn admit_and_serve(
    shared: Shared,
    tls: Option<ClusterTls>,
    socket: TcpStream,
    ip: std::net::IpAddr,
) -> Result<(), String> {
    let now = Instant::now();
    let decision = shared.limiter.lock().await.check(ip, now);
    if let Decision::Throttled { retry_after } = decision {
        log::warn!("cluster: refusing {ip} before admission, retry after {retry_after:?}");
        // Tell the peer why, in the clear, rather than closing silently. A
        // worker cannot act on a closed socket and will retry forever.
        let mut link = wrap(tls.clone(), socket, &shared).await?;
        let _ = codec::write_msg(
            &mut link,
            &Message::Error {
                code: ErrorCode::Throttled,
                detail: format!("too many handshake attempts, retry in {} ms", retry_after.as_millis()),
            },
        )
        .await;
        return Err(format!("throttled {ip}"));
    }

    let link = wrap(tls, socket, &shared).await?;
    let gate = shared.gate();
    let peer = link.peer_label();
    log::info!("Worker connected from {peer}");
    handle_worker(link, shared, gate, peer).await
}

/// Wraps a TCP connection in TLS when the cluster has it.
async fn wrap(
    tls: Option<ClusterTls>,
    socket: TcpStream,
    _shared: &Shared,
) -> Result<Link, String> {
    match tls {
        None => Ok(Link::Plain(socket)),
        Some(t) => t.accept(socket).await,
    }
}

/// Serves one connection to completion.
pub async fn handle_worker(
    mut link: Link,
    shared: Shared,
    mut gate: AdmissionGate,
    peer: String,
) -> Result<(), String> {
    let mut worker_name = String::new();
    let (tx, mut rx) = mpsc::channel::<Command>(8);

    if !gate.is_admitted() {
        let challenge = Message::Challenge {
            nonce: crate::netpolicy::hex_encode(gate.nonce()),
            protocol_version: SCHEMA_VERSION,
        };
        codec::write_msg(&mut link, &challenge).await?;
        log::debug!("Issued an authentication challenge to {peer}");
    }

    let result = loop {
        let frame = tokio::select! {
            biased;
            msg = codec::read_msg(&mut link) => msg,
            cmd = rx.recv() => {
                match cmd {
                    None => break Ok(()),
                    Some(Command::Assign { worker_id, batch_id, work }) => {
                        codec::write_msg(&mut link, &Message::AssignWork { worker_id, batch_id, work }).await?;
                    }
                    Some(Command::Wordlist { manifest, words }) => {
                        codec::write_msg(&mut link, &Message::Wordlist { manifest, words }).await?;
                    }
                    Some(Command::HeartbeatAck { server_time_ms, next_heartbeat_ms, missed }) => {
                        codec::write_msg(&mut link, &Message::HeartbeatAck { server_time_ms, next_heartbeat_ms, missed }).await?;
                    }
                    Some(Command::Error { code, detail }) => {
                        codec::write_msg(&mut link, &Message::Error { code, detail }).await?;
                    }
                    Some(Command::Shutdown { reason }) => {
                        codec::write_msg(&mut link, &Message::Shutdown { reason }).await?;
                    }
                }
                continue;
            }
        };

        let msg = match frame {
            Ok(Some(m)) => m,
            Ok(None) => break Ok(()),
            Err(e) => break Err(describe(&e, &peer)),
        };

        // Every frame passes the gate before it is interpreted. This is the only
        // place a peer can enter the design.
        match gate.on_message(&msg) {
            Admission::Rejected => {
                let _ = codec::write_msg(
                    &mut link,
                    &Message::Error {
                        code: ErrorCode::NotAdmitted,
                        detail: "the shared token was not accepted".to_string(),
                    },
                )
                .await;
                break Err(format!("authentication failed for {peer}"));
            }
            Admission::AwaitingAuthentication => {
                // Tell the peer which frame arrived too early. A closed socket
                // gives a worker nothing to log and nothing to act on; this
                // names the frame and the requirement.
                let detail = format!(
                    "this cluster requires a token, and {} arrived before any \
                     Authenticate frame",
                    frame_kind(&msg)
                );
                let _ = codec::write_msg(
                    &mut link,
                    &Message::Error {
                        code: ErrorCode::NotAdmitted,
                        detail,
                    },
                )
                .await;
                break Err(format!("{peer} sent {} before authenticating", frame_kind(&msg)));
            }
            _ => {}
        }

        if matches!(msg, Message::Ping) {
            codec::write_msg(&mut link, &Message::Pong).await?;
            continue;
        }

        let now = Instant::now();
        match msg {
            Message::Handshake {
                protocol_version,
                node_name,
                tier,
                caps,
            } => {
                if protocol_version != SCHEMA_VERSION {
                    let detail = format!(
                        "this master speaks protocol schema {SCHEMA_VERSION}, the worker speaks {protocol_version}"
                    );
                    let _ = codec::write_msg(
                        &mut link,
                        &Message::Error {
                            code: ErrorCode::VersionMismatch,
                            detail: detail.clone(),
                        },
                    )
                    .await;
                    break Err(detail);
                }
                if node_name.trim().is_empty() || node_name.len() > 128 {
                    break Err(format!("{peer} sent an unusable worker name"));
                }
                worker_name = node_name.clone();
                log::info!(
                    "Worker '{node_name}' joined: tier={tier}, gpu={}, fpga={}, threads={}",
                    caps.gpu, caps.fpga, caps.max_threads
                );
                let mut workers = shared.workers.lock().await;
                workers.insert(
                    node_name.clone(),
                    WorkerInfo {
                        addr: peer.clone(),
                        caps,
                        stats: WorkerStats {
                            hashes_sec: 0.0,
                            total_cracked: 0,
                            power_watts: 0.0,
                            temperature_c: 0.0,
                        },
                        rate: crate::scheduler::RateSample::default(),
                        live: WorkerLiveness::new(shared.policy.heartbeat, now),
                        busy: false,
                        current_batch: None,
                        authenticated: gate.is_authenticated(),
                        wordlists_sent: BTreeSet::new(),
                        tx: tx.clone(),
                    },
                );
                drop(workers);

                // The heartbeat schedule goes out the moment the peer is
                // admitted, not in reply to its first heartbeat. A worker cannot
                // pick a sensible period on its own: too long and the master's
                // deadline expires before the first beat arrives, which looks
                // exactly like a dead peer; too short and it beats at full rate
                // into a link the master is not reading.
                let _ = tx
                    .send(Command::HeartbeatAck {
                        server_time_ms: liveness::epoch_millis(),
                        next_heartbeat_ms: shared.policy.heartbeat.as_millis() as u64,
                        missed: 0,
                    })
                    .await;

                // And the wordlists this run uses, once per connection, before
                // any chunk that references one.
                let bundles: Vec<(WordlistManifest, Vec<String>)> = {
                    let wordlists = shared.wordlists.lock().await;
                    wordlists.values().map(|b| (b.manifest.clone(), b.words.clone())).collect()
                };
                for (manifest, words) in bundles {
                    let digest = manifest.sha256.clone();
                    let already = shared
                        .workers
                        .lock()
                        .await
                        .get(&node_name)
                        .map(|i| i.wordlists_sent.contains(&digest))
                        .unwrap_or(true);
                    if already {
                        continue;
                    }
                    if let Some(info) = shared.workers.lock().await.get_mut(&node_name) {
                        info.wordlists_sent.insert(digest);
                    }
                    let _ = tx.send(Command::Wordlist { manifest, words }).await;
                }
            }

            Message::Heartbeat { node_name, stats } => {
                let ack = {
                    let mut workers = shared.workers.lock().await;
                    match workers.get_mut(&node_name) {
                        Some(info) => {
                            info.live.seen(now);
                            info.stats = stats;
                            Some(Command::HeartbeatAck {
                                server_time_ms: liveness::epoch_millis(),
                                next_heartbeat_ms: info.live.backoff().as_millis() as u64,
                                missed: info.live.missed,
                            })
                        }
                        None => None,
                    }
                };
                if let Some(ack) = ack {
                    let _ = tx.send(ack).await;
                } else {
                    log::debug!("heartbeat from unregistered worker {node_name}, ignored");
                }
            }

            Message::WorkProgress {
                node_name,
                batch_id,
                tested,
                hashes_sec,
            } => {
                let mut workers = shared.workers.lock().await;
                if let Some(info) = workers.get_mut(&node_name) {
                    info.live.seen(now);
                    info.rate.observe(hashes_sec);
                    info.stats.hashes_sec = hashes_sec;
                }
                log::debug!("Worker {node_name} batch {batch_id}: {tested} tested ({hashes_sec:.0} H/s)");
            }

            Message::Result {
                node_name,
                batch_id,
                cracked,
                solved,
            } => {
                let known = shared.workers.lock().await.contains_key(&node_name);
                if !known {
                    log::warn!("Result from unregistered worker {node_name}, discarded");
                    continue;
                }
                handle_result(&shared, &node_name, batch_id, cracked, solved).await;
            }

            Message::Shutdown { reason } => {
                log::info!("Worker {peer} asked to shut down: {reason}");
                break Ok(());
            }

            Message::Error { code, detail } => {
                log::warn!("Worker {peer} reported {code:?}: {detail}");
            }

            Message::Authenticate { .. } => {
                log::debug!("{peer} authenticated against an open cluster");
            }

            other => {
                // A worker sending a master only frame is not an error; it is
                // logged and ignored, because dropping the connection over it
                // would turn a version mismatch into a cluster outage.
                log::debug!("{peer} sent a master frame that does not apply here: {}", frame_kind(&other));
            }
        }
    };

    // The worker is gone. Requeue whatever it held so the run does not stall on
    // a batch nobody will ever finish.
    if !worker_name.is_empty() {
        let requeued = requeue_worker(&shared, &worker_name).await;
        if requeued > 0 {
            log::info!(
                "Worker {worker_name} disconnected, requeued {requeued} batch(es) on {peer}"
            );
        }
        shared.workers.lock().await.remove(&worker_name);
    }
    // Dropping the sender closes the command channel, which ends a dispatcher
    // task that is waiting on it.
    drop(tx);
    result
}

/// Turns a codec error into a line worth reading.
fn describe(e: &ProtoError, peer: &str) -> String {
    let code = match e {
        ProtoError::BadMagic { .. } => ErrorCode::ProtocolViolation,
        ProtoError::UnsupportedFraming { .. } | ProtoError::SchemaMismatch { .. } => {
            ErrorCode::VersionMismatch
        }
        ProtoError::FrameTooLarge { .. } => ErrorCode::FrameTooLarge,
        _ => ErrorCode::ProtocolViolation,
    };
    log::warn!(
        "closing {peer}: {e} (classified as {code:?}). Any frame failure ends the \
         connection: the length field is the only thing that says where the next \
         frame starts, so a stream that lost framing cannot be resynchronised."
    );
    e.to_string()
}

/// Records a finished batch and releases the worker's slot.
async fn handle_result(
    shared: &Shared,
    node_name: &str,
    batch_id: u64,
    cracked: Vec<CrackedEntry>,
    solved: Vec<TargetHash>,
) {
    let mut workers = shared.workers.lock().await;
    let removed = shared.in_flight.lock().await.remove(&batch_id);
    if let Some(info) = workers.get_mut(node_name) {
        info.busy = false;
        info.current_batch = None;
        info.live.seen(Instant::now());
        info.stats.total_cracked += cracked.len() as u64;
    }
    drop(workers);

    let job_id = removed.as_ref().map(|f| f.job_id);

    if !cracked.is_empty() {
        log::info!(
            "Worker '{node_name}' batch {batch_id}: {} cracked: {}",
            cracked.len(),
            cracked
                .iter()
                .map(|c| format!("{} -> {}", c.hash, c.password))
                .collect::<Vec<_>>()
                .join(", ")
        );
        let mut c = shared.completed.lock().await;
        c.extend(cracked);
    }

    if let Some(job_id) = job_id {
        let mut sched = shared.scheduler.lock().await;
        match sched.complete(job_id, &solved) {
            Some(true) => {
                log::info!("Job {job_id} is finished: every target is cracked or the keyspace is exhausted");
            }
            Some(false) => {}
            None => log::warn!("Result for batch {batch_id} named an unknown job {job_id}"),
        }
    } else {
        log::warn!(
            "Result for batch {batch_id} from {node_name}, which no longer holds it; \
             most likely the batch was requeued after it was declared dead"
        );
    }
}

/// Retires a worker: closes its connection, requeues its work, forgets it.
///
/// Closing the connection matters as much as forgetting the worker. Removing
/// the entry alone leaves a ghost that is still sending heartbeats the master
/// ignores, holding a socket and a file descriptor until it gives up on its own.
async fn retire_worker(shared: &Shared, name: &str) -> usize {
    let tx = shared.workers.lock().await.get(name).map(|i| i.tx.clone());
    if let Some(tx) = tx {
        let _ = tx
            .send(Command::Shutdown {
                reason: format!(
                    "no frame from this worker for {} heartbeats",
                    liveness::MAX_MISSED_HEARTBEATS
                ),
            })
            .await;
    }
    let n = requeue_worker(shared, name).await;
    shared.workers.lock().await.remove(name);
    if n > 0 {
        log::info!("requeued {n} batch(es) from retired worker '{name}'");
    }
    n
}

/// Returns a worker's in-flight batches to the free set. Returns how many.
async fn requeue_worker(shared: &Shared, node_name: &str) -> usize {
    let orphans: Vec<InFlightWork> = {
        let mut inflight = shared.in_flight.lock().await;
        let mut taken = Vec::new();
        inflight.retain(|_, f| {
            if f.worker_name == node_name {
                taken.push(f.clone());
                false
            } else {
                true
            }
        });
        taken
    };
    if orphans.is_empty() {
        return 0;
    }
    let mut sched = shared.scheduler.lock().await;
    let mut n = 0;
    for o in &orphans {
        // A span that the scheduler still considers free is a bookkeeping bug, so
        // the refusal is logged rather than forced through.
        match sched.requeue(o.job_id, o.span) {
            Ok(()) => n += 1,
            Err(e) => log::warn!(
                "could not requeue batch {} of {node_name}: {e}. The range is left \
                 unassigned rather than being added twice.",
                o.batch_id
            ),
        }
    }
    n
}

/// The dispatch loop: liveness, work assignment, checkpointing.
async fn dispatch(shared: Shared) {
    let mut tick = time::interval(DISPATCH_TICK);
    let mut last_checkpoint = Instant::now();
    let mut last_heartbeat_beat = Instant::now() - shared.policy.heartbeat;

    loop {
        tick.tick().await;
        let now = Instant::now();

        // 1. Liveness.
        let mut dead: Vec<String> = Vec::new();
        let mut acks: Vec<(String, Command)> = Vec::new();
        {
            let mut workers = shared.workers.lock().await;
            for (name, info) in workers.iter_mut() {
                match info.live.sweep(now) {
                    Liveness::Dead { .. } => dead.push(name.clone()),
                    Liveness::Late { missed } => acks.push((
                        name.clone(),
                        Command::HeartbeatAck {
                            server_time_ms: liveness::epoch_millis(),
                            next_heartbeat_ms: info.live.backoff().as_millis() as u64,
                            missed,
                        },
                    )),
                    Liveness::Alive { .. } => {}
                }
            }
        }
        for (name, ack) in acks {
            if let Some(tx) = shared.workers.lock().await.get(&name).map(|i| i.tx.clone()) {
                let _ = tx.send(ack).await;
            }
        }
        for name in &dead {
            log::warn!(
                "Worker '{name}' missed {} heartbeats and is declared dead; requeueing its work",
                liveness::MAX_MISSED_HEARTBEATS
            );
            retire_worker(&shared, name).await;
        }

        // 2. Assignment. Round robin across jobs, chunk size by the worker's
        //    own rate. See `scheduler` for why both together would be wrong.
        if now.duration_since(last_heartbeat_beat) >= shared.policy.heartbeat {
            last_heartbeat_beat = now;
        }
        let idle: Vec<(String, Option<f64>)> = {
            let workers = shared.workers.lock().await;
            workers
                .iter()
                .filter(|(_, i)| !i.busy)
                .map(|(n, i)| (n.clone(), i.rate.rate()))
                .collect()
        };
        for (name, rate) in idle {
            let chunk: Option<Chunk> = {
                let mut sched = shared.scheduler.lock().await;
                sched.next_chunk(&name, rate)
            };
            let Some(chunk) = chunk else { continue };
            let tx = {
                let mut workers = shared.workers.lock().await;
                match workers.get_mut(&name) {
                    Some(info) => {
                        info.busy = true;
                        info.current_batch = Some(chunk.batch_id);
                        info.tx.clone()
                    }
                    None => continue,
                }
            };
            shared.in_flight.lock().await.insert(
                chunk.batch_id,
                InFlightWork {
                    batch_id: chunk.batch_id,
                    job_id: chunk.job_id,
                    worker_name: name.clone(),
                    work: chunk.work.clone(),
                    span: chunk.span,
                    assigned_at: now,
                },
            );
            let command = Command::Assign {
                worker_id: 0,
                batch_id: chunk.batch_id,
                work: chunk.work,
            };
            if tx.send(command).await.is_err() {
                log::debug!("Worker '{name}' vanished while being given work");
                shared.in_flight.lock().await.remove(&chunk.batch_id);
                if let Some(i) = shared.workers.lock().await.get_mut(&name) {
                    i.busy = false;
                    i.current_batch = None;
                }
                if let Err(e) = shared
                    .scheduler
                    .lock()
                    .await
                    .requeue(chunk.job_id, chunk.span)
                {
                    log::warn!("could not requeue batch {}: {e}", chunk.batch_id);
                }
            }
        }

        // 3. Checkpoint.
        if now.duration_since(last_checkpoint) >= shared.policy.checkpoint_interval {
            last_checkpoint = now;
            if let Err(e) = write_checkpoint(&shared).await {
                log::error!("{e}");
            }
        }
    }
}

async fn write_checkpoint(shared: &Shared) -> Result<(), String> {
    let jobs = shared.scheduler.lock().await.snapshot();
    let inflight: Vec<InFlightState> = shared
        .in_flight
        .lock()
        .await
        .values()
        .map(|f| InFlightState {
            batch_id: f.batch_id,
            job_id: f.job_id,
            span: f.span.into(),
            worker_name: f.worker_name.clone(),
        })
        .collect();
    let completed = shared.completed.lock().await.clone();
    let cp = Checkpoint::capture(&jobs, inflight, completed, 1, 1);
    shared
        .store
        .save(&cp)
        .map_err(|e| format!("checkpoint could not be written: {e}"))
}

/// Serves one connection from a raw socket, for tests that drive the gate over a
/// real socket.
///
/// The integration tests in `tests/admission_over_socket.rs` need to exercise the
/// same admission path the accept loop uses, without starting a whole master.
/// Exposing the handler rather than duplicating the gate check in the test is the
/// point: a test that reimplements the check proves nothing about the handler.
#[doc(hidden)]
pub async fn serve_connection_for_test(
    socket: TcpStream,
    shared: Shared,
    gate: AdmissionGate,
) -> Result<(), String> {
    let peer = socket
        .peer_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| "<test>".to_string());
    handle_worker(Link::Plain(socket), shared, gate, peer).await
}

/// Runs the dispatcher for the lifetime of a test or a run.
///
/// Exposed because the dispatcher is where assignment happens; a test that only
/// ever called `scheduler.next_chunk` directly would be testing the scheduler and
/// not the master.
#[doc(hidden)]
pub fn spawn_dispatcher(shared: Shared) -> tokio::task::JoinHandle<()> {
    tokio::spawn(dispatch(shared))
}

/// Declares a worker dead now and retires it, exactly as the dispatcher would.
///
/// For a test that cannot wait three heartbeat periods. It goes through
/// [`retire_worker`], so a test that kills a worker exercises the same requeue
/// path a real timeout does rather than a simplified copy.
#[doc(hidden)]
pub async fn expire_worker(shared: &Shared, name: &str) -> bool {
    let now = Instant::now();
    let swept = {
        let mut workers = shared.workers.lock().await;
        match workers.get_mut(name) {
            Some(info) => {
                // Backdate past the third deadline, then sweep.
                info.live.last_seen = now - shared.policy.heartbeat * 10;
                matches!(info.live.sweep(now), Liveness::Dead { .. })
            }
            None => false,
        }
    };
    if swept {
        retire_worker(shared, name).await;
    }
    swept
}

/// A worker's smoothed rate, for tests and for a status line.
pub async fn worker_rate(shared: &Shared, name: &str) -> Option<f64> {
    shared.workers.lock().await.get(name).and_then(|i| i.rate.rate())
}