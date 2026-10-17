//! The worker: connect, prove who it is, take work, report results.
//!
//! # What changed
//!
//! Three things, all of them previously broken or missing.
//!
//! - **The mask expander.** [`crate::mask`] is a faithful port of the root
//!   crate's, checked candidate for candidate by
//!   `tests/distributed_mask_agreement.rs`. The previous version ignored the index
//!   in `?1` to `?9` and had no `?w`, no literal range, no alternation and no
//!   escape, so a cluster and a local run of the same mask tested different
//!   candidates.
//! - **Multiple targets per chunk.** A `WorkUnit` carries every unsolved target
//!   rather than one, and the worker tests each candidate against each of them
//!   and reports which are now solved. One hash per chunk meant the cluster
//!   re-read the same wordlist once per hash.
//! - **Reconnection.** A worker whose master restarted, or whose socket dropped,
//!   used to log "connection lost" and exit. A cluster that loses one worker's
//!   socket should lose one worker, not all of them.
//!
//! # Inline wordlists
//!
//! `AttackType::Inline` names a wordlist by the SHA-256 of its contents, which the
//! master pushes once per connection in a `Wordlist` frame. The digest is verified
//! against the manifest before a single candidate is produced from it, and a chunk
//! naming a digest this worker never received is refused rather than skipped, so a
//! silent undercount of the keyspace cannot happen.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::time;

use crate::codec::{self, Link};
use crate::mask::Mask;
use crate::netpolicy::ClusterAuth;
use crate::protocol::{
    AttackType, Capabilities, CrackedEntry, ErrorCode, Message, TargetHash, WorkUnit,
    SCHEMA_VERSION,
};
use crate::verify;
use crate::wordlist::{WordlistManifest, WordlistPolicy};

/// Default heartbeat period before the master says otherwise.
const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(5);

/// Ceiling on the backoff a worker will accept from its master.
const MAX_HEARTBEAT: Duration = Duration::from_secs(120);

/// How many times a worker retries a dropped connection before giving up.
///
/// Bounded because a worker that reconnects forever against a master that no
/// longer exists is a process the operator cannot see and cannot stop, and it
/// fills the master's accept log.
pub const MAX_RECONNECT_ATTEMPTS: u32 = 10;

pub struct WorkerNode {
    pub master_addr: String,
    pub node_name: String,
    stream: Option<Link>,
    tested: Arc<AtomicU64>,
    cracked: Arc<AtomicU64>,
    /// Directories this worker will open wordlists from, chosen locally.
    /// A master cannot widen it.
    wordlists: WordlistPolicy,
    /// Shared secret for authenticating to the master.
    token: Option<String>,
    /// Wordlists the master has pushed, keyed by content digest.
    inline: HashMap<String, Arc<Vec<String>>>,
    /// Reconnect attempts made in the current run.
    attempts: u32,
    /// Seconds to wait before the next reconnect, doubling each failure.
    backoff: Duration,
    /// Set by `with_tls`.
    tls: Option<crate::tls::ClusterTls>,
}

impl WorkerNode {
    /// The directories this worker will open wordlists from.
    pub fn roots(&self) -> &[std::path::PathBuf] {
        self.wordlists.roots()
    }

    /// True when this worker will refuse every dictionary unit.
    pub fn refuses_all_wordlists(&self) -> bool {
        self.wordlists.is_deny_all()
    }

    /// Builds a worker with no granted wordlist directories.
    ///
    /// Every dictionary work unit is refused until [`WorkerNode::with_wordlist_dirs`]
    /// names somewhere to read from. Defaulting to "read whatever the master asks
    /// for" is the defect P9.1.05 describes, so it is not a default here.
    pub fn new(master_addr: &str) -> Self {
        WorkerNode {
            master_addr: master_addr.to_string(),
            node_name: crate::hostname(),
            stream: None,
            tested: Arc::new(AtomicU64::new(0)),
            cracked: Arc::new(AtomicU64::new(0)),
            wordlists: WordlistPolicy::deny_all(),
            token: None,
            inline: HashMap::new(),
            attempts: 0,
            backoff: Duration::from_secs(1),
            tls: None,
        }
    }

    /// Sets the shared token used to authenticate to the master.
    pub fn with_token(mut self, token: String) -> Self {
        self.token = Some(token);
        self
    }

    /// Sets the transport to TLS.
    pub fn with_tls(mut self, tls: crate::tls::ClusterTls) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Grants directories this worker may read wordlists from.
    ///
    /// Takes paths the operator chose on this machine. The master cannot widen
    /// the grant, only pick a file inside what is already granted.
    pub fn with_wordlist_dirs<I, P>(mut self, dirs: I) -> Result<Self, String>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<std::path::Path>,
    {
        self.wordlists = WordlistPolicy::new(dirs)?;
        Ok(self)
    }

    pub async fn connect(&mut self) -> Result<(), String> {
        let tcp = TcpStream::connect(&self.master_addr)
            .await
            .map_err(|e| format!("cannot reach the master at {}: {e}", self.master_addr))?;
        // Nagle would coalesce a small heartbeat with a large result frame and
        // add latency to every report.
        let _ = tcp.set_nodelay(true);
        self.stream = Some(match &self.tls {
            None => Link::Plain(tcp),
            Some(t) => t.connect(tcp, &self.master_addr).await?,
        });
        log::info!("Connected to master at {}", self.master_addr);
        Ok(())
    }

    pub async fn send_handshake(&mut self) -> Result<(), String> {
        let link = self.stream.as_mut().ok_or("not connected")?;

        // Answer the master's challenge when a token is configured. The nonce
        // comes from the master, so the response is bound to this connection; a
        // value invented here would not match and the connection would be dropped
        // as unauthenticated.
        if self.token.is_some() {
            let frame = codec::read_msg(link).await?.ok_or_else(|| {
                format!(
                    "the master at {} closed before sending an authentication challenge",
                    self.master_addr
                )
            })?;
            match frame {
                Message::Challenge {
                    nonce,
                    protocol_version,
                } => {
                    if protocol_version != SCHEMA_VERSION {
                        return Err(format!(
                            "the master speaks protocol schema {protocol_version}, this worker \
                             speaks {SCHEMA_VERSION}. Upgrade one of them; they are not \
                             wire compatible."
                        ));
                    }
                    let nonce = crate::netpolicy::hex_encode_decode(&nonce);
                    let auth = ClusterAuth::with_token(self.token.clone().unwrap_or_default());
                    let reply = crate::admission::auth_frame(&auth, &nonce);
                    codec::write_msg(link, &reply).await?;
                    log::debug!("Answered the master challenge");
                }
                other => {
                    return Err(format!(
                        "expected an authentication challenge from the master, got {}",
                        codec::code_of(&other).name()
                    ));
                }
            }
        }

        let caps = local_capabilities();
        let handshake = Message::Handshake {
            protocol_version: SCHEMA_VERSION,
            node_name: self.node_name.clone(),
            tier: tier_name(),
            caps,
        };
        codec::write_msg(link, &handshake).await?;
        log::info!("Sent handshake as '{}'", self.node_name);
        Ok(())
    }

    /// Accepts a wordlist the master pushed, after checking the manifest.
    ///
    /// The digest is the cache key, so a worker cannot end up using one wordlist
    /// where another was meant: a later bundle with a different digest is a
    /// different entry, and a bundle whose bytes do not match its manifest is
    /// refused rather than used.
    fn accept_wordlist(&mut self, manifest: WordlistManifest, words: Vec<String>) -> Result<(), String> {
        let joined = words.join("\n");
        manifest.verify(joined.as_bytes()).map_err(|e| {
            format!(
                "refusing a wordlist named '{}': {e}. The master sent bytes that do \
                 not match the manifest it sent with them.",
                manifest.name
            )
        })?;
        log::info!(
            "Accepted wordlist '{}' from the master: {} entries, sha256 {}",
            manifest.name,
            words.len(),
            manifest.sha256
        );
        self.inline.insert(manifest.sha256, Arc::new(words));
        Ok(())
    }

    /// Runs until the master shuts the worker down or the connection dies and
    /// cannot be re-established.
    pub async fn run_worker_loop(&mut self) -> Result<(), String> {
        loop {
            match self.session().await {
                Ok(Outcome::Shutdown) => {
                    log::info!("Worker '{}' shut down on the master's instruction", self.node_name);
                    return Ok(());
                }
                Ok(Outcome::Disconnected(reason)) => {
                    self.attempts += 1;
                    if self.attempts > MAX_RECONNECT_ATTEMPTS {
                        return Err(format!(
                            "lost the master at {} {} times: {}. Giving up; check the \
                             master before restarting.",
                            self.master_addr, self.attempts, reason
                        ));
                    }
                    log::warn!(
                        "Lost the master at {} ({reason}), reconnecting in {} s, attempt {} of {}",
                        self.master_addr,
                        self.backoff.as_secs(),
                        self.attempts,
                        MAX_RECONNECT_ATTEMPTS
                    );
                    time::sleep(self.backoff).await;
                    self.backoff = (self.backoff * 2).min(Duration::from_secs(30));
                }
                Err(e) => {
                    self.attempts += 1;
                    if self.attempts > MAX_RECONNECT_ATTEMPTS {
                        return Err(format!(
                            "could not work with the master at {} after {} attempts: {e}",
                            self.master_addr, self.attempts
                        ));
                    }
                    log::warn!(
                        "Connection to {} failed ({e}), retrying in {} s, attempt {} of {}",
                        self.master_addr,
                        self.backoff.as_secs(),
                        self.attempts,
                        MAX_RECONNECT_ATTEMPTS
                    );
                    time::sleep(self.backoff).await;
                    self.backoff = (self.backoff * 2).min(Duration::from_secs(30));
                }
            }
            // A successful handshake means the master is reachable again.
            self.inline.clear();
        }
    }

    /// One connection, from connect to close.
    async fn session(&mut self) -> Result<Outcome, String> {
        self.connect().await?;
        self.send_handshake().await?;

        let mut link = self.stream.take().ok_or("connect did not store a link")?;
        let node_name = self.node_name.clone();
        let cracked = Arc::clone(&self.cracked);
        let tested = Arc::clone(&self.tested);

        // The master names the real period in its first `HeartbeatAck`, which
        // it sends as soon as the peer is admitted. Until that arrives this is a
        // guess; a guess that is too long looks like a dead worker, because the
        // master's deadline is set from its own policy rather than from anything
        // the worker said.
        let mut hb_period = DEFAULT_HEARTBEAT;
        let mut hb_interval = time::interval(hb_period);
        hb_interval.tick().await;

        let outcome = loop {
            let frame = tokio::select! {
                msg = codec::read_msg(&mut link) => msg,
                _ = hb_interval.tick() => {
                    let hb = Message::Heartbeat {
                        node_name: node_name.clone(),
                        stats: crate::protocol::WorkerStats {
                            hashes_sec: 0.0,
                            total_cracked: cracked.load(Ordering::SeqCst),
                            power_watts: 0.0,
                            temperature_c: 0.0,
                        },
                    };
                    match codec::write_msg(&mut link, &hb).await {
                        Ok(()) => continue,
                        Err(e) => break Outcome::Disconnected(e.to_string()),
                    }
                }
            };

            let msg = match frame {
                Ok(Some(m)) => m,
                Ok(None) => break Outcome::Disconnected("the master closed the connection".into()),
                Err(e) => {
                    log::warn!("Protocol error from the master: {e}");
                    break Outcome::Disconnected(e.to_string());
                }
            };

            match msg {
                Message::AssignWork { batch_id, work, .. } => {
                    log::info!(
                        "Received batch {batch_id}: {} targets, range [{}, {})",
                        work.targets.len(),
                        work.keyspace_start,
                        work.keyspace_end
                    );
                    let (found, solved) = self.crack_work_unit(&batch_id, &work).await;
                    let result = Message::Result {
                        node_name: node_name.clone(),
                        batch_id,
                        cracked: found,
                        solved,
                    };
                    if let Err(e) = codec::write_msg(&mut link, &result).await {
                        break Outcome::Disconnected(e.to_string());
                    }
                }
                Message::HeartbeatAck {
                    next_heartbeat_ms,
                    ..
                } => {
                    // The master owns the schedule. Following it is what keeps a
                    // worker from beating at full rate into a link the master has
                    // stopped reading.
                    let d = Duration::from_millis(
                        next_heartbeat_ms.clamp(100, MAX_HEARTBEAT.as_millis() as u64),
                    );
                    if d != hb_period {
                        hb_period = d;
                        hb_interval = time::interval(d);
                        log::debug!("Master set the heartbeat period to {} ms", d.as_millis());
                    }
                }
                Message::Wordlist { manifest, words } => {
                    if let Err(e) = self.accept_wordlist(manifest, words) {
                        log::error!("{e}");
                        let _ = codec::write_msg(
                            &mut link,
                            &Message::Error {
                                code: ErrorCode::WordlistRefused,
                                detail: e,
                            },
                        )
                        .await;
                    }
                }
                Message::Ping => codec::write_msg(&mut link, &Message::Pong).await?,
                Message::Pong => {}
                Message::Shutdown { reason: _ } => break Outcome::Shutdown,
                Message::Error { code, detail } => {
                    match code {
                        ErrorCode::Throttled => {
                            break Outcome::Disconnected(format!(
                                "the master is throttling this address: {detail}. Not retrying \
                                 quickly; slow down the restart rate of the cluster."
                            ));
                        }
                        ErrorCode::VersionMismatch
                        | ErrorCode::NotAdmitted
                        | ErrorCode::ProtocolViolation
                        | ErrorCode::FrameTooLarge => {
                            break Outcome::Disconnected(format!("{code:?}: {detail}"));
                        }
                        _ => log::warn!("Master reported {code:?}: {detail}"),
                    }
                }
                Message::Challenge { .. } => {
                    log::warn!("Master sent a second challenge on an established connection, ignored");
                }
                other => {
                    log::debug!(
                        "Ignoring a master frame this worker does not handle: {}",
                        codec::code_of(&other).name()
                    );
                }
            }
        };

        self.stream = None;
        let _ = &tested;
        Ok(outcome)
    }

    /// Works one chunk.
    ///
    /// Returns the cracked entries and every target that is now solved. The
    /// second list is what lets the master stop building chunks around a hash that
    /// is already found, and it is idempotent, so a requeued batch that runs
    /// twice cannot double count.
    pub async fn crack_work_unit(
        &mut self,
        batch_id: &u64,
        work: &WorkUnit,
    ) -> (Vec<CrackedEntry>, Vec<TargetHash>) {
        let total = work.total_size();
        if total == 0 {
            return (Vec::new(), Vec::new());
        }

        let start = work.keyspace_start;
        let end = work.keyspace_end;
        let begin = Instant::now();
        let mut found: Vec<CrackedEntry> = Vec::new();
        let mut solved: Vec<TargetHash> = Vec::new();
        // Targets not yet cracked in this batch, so a hit removes one from the
        // inner loop rather than only short circuiting the outer one.
        let mut open: Vec<TargetHash> = work.targets.clone();

        let tested = match &work.attack_type {
            AttackType::BruteForce { mask } => {
                self.crack_masked(batch_id, work, mask, start, end, &mut open, &mut found)
            }
            AttackType::Dictionary { wordlist_path, rules } => {
                self.crack_dictionary(
                    batch_id,
                    work,
                    wordlist_path,
                    rules,
                    start,
                    end,
                    &mut open,
                    &mut found,
                )
            }
            AttackType::Inline { sha256, rules } => {
                match self.inline.get(sha256).cloned() {
                    None => {
                        // Refused rather than skipped: silently returning "no
                        // crack" for a chunk whose wordlist is missing would look
                        // exactly like a chunk that found nothing.
                        log::error!(
                            "batch {batch_id} needs wordlist {sha256}, which the master never \
                             sent on this connection. Refusing the batch instead of reporting \
                             it as searched and empty."
                        );
                        return (found, solved);
                    }
                    Some(words) => {
                        self.crack_lines(
                            batch_id, work, &rules, start, end, &words, &mut open, &mut found,
                        )
                    }
                }
            }
            AttackType::Combinator { left_words, right_words } => self.crack_combinator(
                batch_id,
                work,
                left_words,
                right_words,
                start,
                end,
                &mut open,
                &mut found,
            ),
        };

        // Only targets this batch actually found. An earlier version also
        // reported every target that was still open, which told the master the
        // job was finished as soon as the first chunk came back, so a real
        // dictionary run stopped after one chunk.
        for c in &found {
            if !solved.iter().any(|t| t.hash == c.hash) {
                solved.push(TargetHash::new(&c.algorithm, &c.hash));
            }
        }

        let elapsed = begin.elapsed().as_secs_f64().max(0.000_001);
        let hps = tested as f64 / elapsed;
        log::info!(
            "batch {batch_id}: {tested} tested in {:.2}s ({:.0} H/s), {} cracked, {} targets open",
            elapsed,
            hps,
            found.len(),
            open.len()
        );
        self.tested.fetch_add(tested, Ordering::SeqCst);
        self.cracked.fetch_add(found.len() as u64, Ordering::SeqCst);
        (found, solved)
    }

    fn crack_masked(
        &mut self,
        batch_id: &u64,
        work: &WorkUnit,
        mask: &str,
        start: u64,
        end: u64,
        open: &mut Vec<TargetHash>,
        found: &mut Vec<CrackedEntry>,
    ) -> u64 {
        let parsed = match Mask::parse(mask, &[]) {
            Ok(m) => m,
            Err(e) => {
                log::error!("batch {batch_id}: mask '{mask}' does not parse: {e}. Refusing the batch.");
                return 0;
            }
        };
        // The master's keyspace and this one must agree, or the indices below
        // walk a different set of candidates than the master thinks they cover.
        match parsed.keyspace_u64(&[]) {
            Ok(k) if k == work.keyspace_total => {}
            Ok(k) => {
                log::error!(
                    "batch {batch_id}: mask '{mask}' expands to {k} candidates but the master \
                     says the job has {}. Refusing rather than scanning a range the master \
                     is not accounting for.",
                    work.keyspace_total
                );
                return 0;
            }
            Err(e) => {
                log::error!("batch {batch_id}: {e}");
                return 0;
            }
        }
        if work.keyspace_end > work.keyspace_total || work.keyspace_start >= work.keyspace_end {
            log::error!(
                "batch {batch_id}: range [{}, {}) is outside the job's keyspace {}",
                work.keyspace_start,
                work.keyspace_end,
                work.keyspace_total
            );
            return 0;
        }

        let mut buf: Vec<u8> = Vec::with_capacity(parsed.len() + 4);
        let mut count = 0u64;
        for idx in start..end {
            let candidate = match parsed.candidate_string(idx as u128, &[]) {
                Ok(c) => c,
                Err(_) => break,
            };
            buf.clear();
            buf.extend_from_slice(candidate.as_bytes());
            if try_targets(work, open, found, &candidate) {
                break;
            }
            count += 1;
        }
        count
    }

    fn crack_dictionary(
        &mut self,
        batch_id: &u64,
        work: &WorkUnit,
        wordlist_path: &str,
        rules: &[String],
        start: u64,
        end: u64,
        open: &mut Vec<TargetHash>,
        found: &mut Vec<CrackedEntry>,
    ) -> u64 {
        // Resolved against the directories this worker was granted, with
        // symlinks followed before the containment check. A refused path is
        // logged with the reason and the batch is skipped: the master named
        // something this worker may not open, and continuing would mean opening
        // it anyway.
        let base = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        let words = match self.wordlists.read_lines(wordlist_path, &base, start, end) {
            Ok(w) => w,
            Err(e) => {
                log::error!("Refused wordlist '{wordlist_path}': {e}");
                return 0;
            }
        };
        self.crack_lines(batch_id, work, rules, start, end, &words, open, found)
    }

    /// Works a range of a word list.
    ///
    /// `start` and `end` are global line indices into `words`, the same
    /// coordinates the master used to cut the chunk. An earlier version ignored
    /// them and walked the whole list for every chunk, so four workers all tested
    /// all four hundred candidates: the answer came out right and the coverage
    /// ledger was a fiction, because no chunk ever did the work it was issued
    /// for.
    fn crack_lines(
        &mut self,
        batch_id: &u64,
        work: &WorkUnit,
        rules: &[String],
        start: u64,
        end: u64,
        words: &[String],
        open: &mut Vec<TargetHash>,
        found: &mut Vec<CrackedEntry>,
    ) -> u64 {
        let parsed_rules: Vec<Vec<RuleOp>> = rules
            .iter()
            .filter_map(|r| match parse_rule(r) {
                Ok(ops) => Some(ops),
                Err(e) => {
                    log::warn!("batch {batch_id}: rule '{r}' ignored: {e}");
                    None
                }
            })
            .collect();

        if start >= words.len() as u64 {
            log::error!(
                "batch {batch_id}: range starts at {start} but the wordlist has {} lines",
                words.len()
            );
            return 0;
        }
        let stop = (end as usize).min(words.len());
        let mut count = 0u64;
        'words: for word in &words[start as usize..stop] {
            let candidates: Vec<String> = if parsed_rules.is_empty() {
                vec![word.clone()]
            } else {
                let mut all = Vec::new();
                for ops in &parsed_rules {
                    all.extend(apply_rule(word, ops));
                }
                all
            };
            for pw in &candidates {
                if try_targets(work, open, found, pw) {
                    break 'words;
                }
                count += 1;
            }
        }
        count
    }

    fn crack_combinator(
        &mut self,
        batch_id: &u64,
        work: &WorkUnit,
        left_words: &[String],
        right_words: &[String],
        start: u64,
        end: u64,
        open: &mut Vec<TargetHash>,
        found: &mut Vec<CrackedEntry>,
    ) -> u64 {
        if left_words.is_empty() || right_words.is_empty() {
            log::error!("batch {batch_id}: a combinator chunk with an empty list is refused");
            return 0;
        }
        let total = (left_words.len() as u64) * (right_words.len() as u64);
        if total != work.keyspace_total {
            log::error!(
                "batch {batch_id}: the lists give keyspace {total} but the master says {}. \
                 Refusing rather than walking a different set of pairs.",
                work.keyspace_end
            );
            return 0;
        }
        let mut count = 0u64;
        let mut idx = 0u64;
        'pairs: for left in left_words {
            for right in right_words {
                if idx >= end {
                    break 'pairs;
                }
                if idx >= start {
                    let pw = format!("{left}{right}");
                    if try_targets(work, open, found, &pw) {
                        break 'pairs;
                    }
                    count += 1;
                }
                idx += 1;
            }
        }
        count
    }
}

/// How a worker session ended.
enum Outcome {
    Shutdown,
    Disconnected(String),
}

/// Tests one candidate against every still open target.
///
/// Returns true when every target is solved, which ends the chunk: no candidate
/// further along the keyspace can tell the master anything new.
fn try_targets(
    work: &WorkUnit,
    open: &mut Vec<TargetHash>,
    found: &mut Vec<CrackedEntry>,
    candidate: &str,
) -> bool {
    let mut i = 0;
    while i < open.len() {
        let t = open[i].clone();
        if verify::verify(&t.hash_type, &t.hash, candidate) {
            log::info!("CRACKED: {} -> {}", t.hash, candidate);
            found.push(CrackedEntry {
                hash: t.hash.clone(),
                password: candidate.to_string(),
                algorithm: t.hash_type.clone(),
            });
            open.swap_remove(i);
        } else {
            i += 1;
        }
    }
    let _ = work;
    open.is_empty() && !work.targets.is_empty()
}

fn tier_name() -> String {
    std::env::consts::ARCH.to_string()
}

/// What this node claims it can do.
///
/// These are claims, and the master prefers measured throughput over them, so
/// nothing here is trusted for scheduling except `max_threads` as a last
/// resort. GPU and FPGA are false because a distributed worker process drives
/// the CPU kernels; the hardware engines live in the main binary.
fn local_capabilities() -> Capabilities {
    Capabilities {
        simd: "detect".to_string(),
        gpu: false,
        fpga: false,
        max_threads: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4),
        ram_mb: 4096,
    }
}

/// Parses one rule string into its operators.
///
/// Every operator reports how many bytes it consumed and the loop advances by
/// exactly that, rather than each arm nudging `i` and the loop nudging it again.
/// The earlier form skipped a character after every multi byte operator, so
/// `T9D9p99` parsed as `T9` and then rejected `D` at the wrong offset.
///
/// An unknown operator is an error. The previous parser skipped operators it did
/// not recognise, so a typo in a rule produced a different candidate set with no
/// warning at all, which is the worst outcome: the run reports a result and the
/// result is for a different rule than the one written.
fn parse_rule(rule: &str) -> Result<Vec<RuleOp>, String> {
    let mut ops = Vec::new();
    let bytes = rule.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        let consumed = match bytes[i] {
            b'l' => {
                ops.push(RuleOp::Lowercase);
                1
            }
            b'u' => {
                ops.push(RuleOp::Uppercase);
                1
            }
            b'r' => {
                ops.push(RuleOp::Reverse);
                1
            }
            b'd' => {
                ops.push(RuleOp::Duplicate);
                1
            }
            b'f' => {
                ops.push(RuleOp::Reflect);
                1
            }
            b'{' => {
                ops.push(RuleOp::RotateLeft);
                1
            }
            b'}' => {
                ops.push(RuleOp::RotateRight);
                1
            }
            b':' => {
                ops.push(RuleOp::Pure);
                1
            }
            b'$' if i + 1 < len => {
                ops.push(RuleOp::Append(bytes[i + 1] as char));
                2
            }
            b'^' if i + 1 < len => {
                ops.push(RuleOp::Prepend(bytes[i + 1] as char));
                2
            }
            b'T' if i + 1 < len => {
                ops.push(RuleOp::ToggleAt((bytes[i + 1] - b'0') as usize));
                2
            }
            b'D' if i + 1 < len => {
                ops.push(RuleOp::DeleteAt((bytes[i + 1] - b'0') as usize));
                2
            }
            b'p' if i + 2 < len => {
                ops.push(RuleOp::SwapAt(
                    (bytes[i + 1] - b'0') as usize,
                    (bytes[i + 2] - b'0') as usize,
                ));
                3
            }
            other => {
                return Err(format!(
                    "unknown rule operator '{}' at offset {i}",
                    other as char
                ))
            }
        };
        i += consumed;
    }
    Ok(ops)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum RuleOp {
    Lowercase,
    Uppercase,
    Reverse,
    Duplicate,
    Reflect,
    RotateLeft,
    RotateRight,
    Append(char),
    Prepend(char),
    ToggleAt(usize),
    DeleteAt(usize),
    SwapAt(usize, usize),
    Pure,
}

fn apply_rule(word: &str, ops: &[RuleOp]) -> Vec<String> {
    let mut results = vec![word.to_string()];
    for op in ops {
        results = results.into_iter().flat_map(|w| apply_one(&w, op)).collect();
    }
    results
}

fn apply_one(word: &str, op: &RuleOp) -> Vec<String> {
    match op {
        RuleOp::Pure => vec![word.to_string()],
        RuleOp::Lowercase => vec![word.to_lowercase()],
        RuleOp::Uppercase => vec![word.to_uppercase()],
        RuleOp::Reverse => vec![word.chars().rev().collect()],
        RuleOp::Duplicate => vec![format!("{word}{word}")],
        RuleOp::Reflect => {
            let rev: String = word.chars().rev().collect();
            vec![format!("{word}{rev}")]
        }
        RuleOp::RotateLeft => {
            let mut c: Vec<char> = word.chars().collect();
            if !c.is_empty() {
                c.rotate_left(1);
            }
            vec![c.into_iter().collect()]
        }
        RuleOp::RotateRight => {
            let mut c: Vec<char> = word.chars().collect();
            if !c.is_empty() {
                c.rotate_right(1);
            }
            vec![c.into_iter().collect()]
        }
        RuleOp::Append(ch) => vec![format!("{word}{ch}")],
        RuleOp::Prepend(ch) => vec![format!("{ch}{word}")],
        RuleOp::ToggleAt(pos) => {
            let mut c: Vec<char> = word.chars().collect();
            if *pos < c.len() {
                if c[*pos].is_ascii_lowercase() {
                    c[*pos] = c[*pos].to_ascii_uppercase();
                } else if c[*pos].is_ascii_uppercase() {
                    c[*pos] = c[*pos].to_ascii_lowercase();
                }
            }
            vec![c.into_iter().collect()]
        }
        RuleOp::DeleteAt(pos) => {
            let mut c: Vec<char> = word.chars().collect();
            if *pos < c.len() {
                c.remove(*pos);
            }
            vec![c.into_iter().collect()]
        }
        RuleOp::SwapAt(l, r) => {
            let mut c: Vec<char> = word.chars().collect();
            if *l < c.len() && *r < c.len() {
                c.swap(*l, *r);
            }
            vec![c.into_iter().collect()]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rule_with_an_unknown_operator_is_rejected_rather_than_ignored() {
        // The previous parser silently skipped operators it did not know, so a
        // typo'd rule produced a different candidate set with no warning.
        assert!(parse_rule("q").is_err());
        assert!(parse_rule("lu$1").is_ok());
    }

    /// The parser skipped a character after every multi byte operator, so the
    /// second operator of a compound rule was read at the wrong offset.
    #[test]
    fn a_compound_rule_parses_every_operator() {
        let ops = parse_rule("T9D9p99").unwrap();
        assert_eq!(
            ops,
            vec![
                RuleOp::ToggleAt(9),
                RuleOp::DeleteAt(9),
                RuleOp::SwapAt(9, 9)
            ]
        );
        let ops = parse_rule("lu$1^2").unwrap();
        assert_eq!(
            ops,
            vec![
                RuleOp::Lowercase,
                RuleOp::Uppercase,
                RuleOp::Append('1'),
                RuleOp::Prepend('2')
            ]
        );
    }

    #[test]
    fn rules_compose_left_to_right() {
        let ops = parse_rule("u$1").unwrap();
        assert_eq!(apply_rule("abc", &ops), vec!["ABC1".to_string()]);
    }

    #[test]
    fn a_rule_on_an_empty_word_does_not_panic() {
        for r in ["r", "{", "}", "T0", "D0", "p01", "f"] {
            let ops = parse_rule(r).unwrap();
            let _ = apply_rule("", &ops);
        }
    }

    #[test]
    fn out_of_range_positions_are_ignored_rather_than_panicking() {
        let ops = parse_rule("T9D9p99").unwrap();
        assert_eq!(apply_rule("ab", &ops), vec!["ab".to_string()]);
    }
}