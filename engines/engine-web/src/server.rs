//! Listener, shared state, and the security layers.
//!
//! # Where the status comes from
//!
//! The old `AppState` had `status: RwLock<AttackStatus>` and every route
//! mutated it. `start_attack` set it to `Running` without enqueueing anything, so
//! the dashboard reported a running attack while doing nothing at all.
//!
//! There is no status field now. [`AppState::status`] derives what to report
//! from the live [`AttackHandle`]: whether its control flags say stopped or
//! paused, and whether its counters are still moving. There is nothing to set,
//! so there is nothing that can disagree with reality.
//!
//! # Order of checks on a mutating request
//!
//!   1. rate limit, cheapest and the one that protects the other two
//!   2. bearer token
//!   3. CSRF header
//!
//! Token before CSRF because a token failure is worth reporting precisely and a
//! missing CSRF header on a request that had no valid token anyway is noise. The
//! order does not matter for security: every one of them must pass.

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::{Mutex, RwLock};

use crate::attack::{AttackExecutor, AttackHandle, CrackedHit, NullExecutor};
use crate::auth::{AuditLog, RateLimiter, WebBindPolicy};

/// One worker node as the dashboard sees it.
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct WorkerEntry {
    pub name: String,
    pub hashes_sec: f64,
    pub total_cracked: u64,
    pub alive: bool,
}

/// What an attack was asked to do.
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug, PartialEq)]
pub struct AttackConfig {
    pub attack_type: String,
    pub hash_type: String,
    pub target_hashes: Vec<String>,
    pub mask: Option<String>,
    pub wordlist: Option<String>,
    pub rules: Vec<String>,
}

/// What the dashboard reports.
#[derive(Clone, serde::Serialize, serde::Deserialize, Debug, PartialEq)]
pub enum AttackStatus {
    Idle,
    Running,
    Paused,
    /// The keyspace was exhausted, or the run was stopped.
    Finished,
    /// An attack is configured but the executor refused to start one.
    Error(String),
}

impl std::fmt::Display for AttackStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttackStatus::Idle => write!(f, "Idle"),
            AttackStatus::Running => write!(f, "Running"),
            AttackStatus::Paused => write!(f, "Paused"),
            AttackStatus::Finished => write!(f, "Finished"),
            AttackStatus::Error(_) => write!(f, "Error"),
        }
    }
}

/// The attack in flight, if any.
///
/// A slot rather than a bare field because start, stop and status all touch it,
/// and `stop` followed immediately by `start` must not leave two attacks
/// running.
#[derive(Default)]
pub struct AttackSlot(pub Mutex<Option<AttackHandle>>);

impl AttackSlot {
    /// Installs a new attack, stopping whatever was there.
    pub async fn replace(&self, handle: AttackHandle) {
        let mut slot = self.0.lock().await;
        if let Some(old) = slot.take() {
            // Dropping the old handle aborts its task, which is the intent: one
            // dashboard, one attack.
            drop(old);
        }
        *slot = Some(handle);
    }

    /// Stops and removes the current attack. Returns whether there was one.
    pub async fn take_and_stop(&self) -> bool {
        let mut slot = self.0.lock().await;
        match slot.take() {
            Some(handle) => {
                handle.stop();
                true
            }
            None => false,
        }
    }
}

/// Everything the routes share.
pub struct AppState {
    /// The bearer token. `None` means every mutating route answers 401.
    pub token: Option<String>,
    pub bind_policy: WebBindPolicy,
    /// The real execution path. `NullExecutor` when the binary wired none.
    pub executor: Arc<dyn AttackExecutor>,
    /// True when `executor` can actually run something.
    pub executor_wired: bool,
    pub rate_limiter: RateLimiter,
    pub audit: AuditLog,

    pub workers: RwLock<Vec<WorkerEntry>>,
    pub session_name: RwLock<String>,
    pub attack_config: RwLock<Option<AttackConfig>>,
    pub message_log: RwLock<Vec<String>>,
    pub attack: AttackSlot,
    pub start_time: Instant,
}

impl AppState {
    /// Builds state with a working executor behind it.
    pub fn new(token: Option<String>, policy: WebBindPolicy, executor: Arc<dyn AttackExecutor>) -> Self {
        // A NullExecutor is identified by its type, because it is the only
        // implementation that refuses everything. Using `is_null()` on the trait
        // object avoids a blanket impl on a foreign type.
        let wired = !executor.is_null();
        AppState {
            token,
            bind_policy: policy,
            executor,
            executor_wired: wired,
            rate_limiter: RateLimiter::dashboard_default(),
            audit: AuditLog::dashboard_default(),
            workers: RwLock::new(Vec::new()),
            session_name: RwLock::new(String::new()),
            attack_config: RwLock::new(None),
            message_log: RwLock::new(Vec::new()),
            attack: AttackSlot::default(),
            start_time: Instant::now(),
        }
    }

    /// State that cannot run an attack, for tests and for a binary that wired no
    /// executor.
    pub fn inert(token: Option<String>) -> Self {
        AppState::new(token, WebBindPolicy::default(), Arc::new(NullExecutor))
    }

    /// The status derived from the live attack, never from a stored value.
    pub async fn status(&self) -> AttackStatus {
        let slot = self.attack.0.lock().await;
        match slot.as_ref() {
            None => AttackStatus::Idle,
            Some(handle) => {
                if handle.control().is_stopped() {
                    AttackStatus::Finished
                } else if handle.control().is_paused() {
                    AttackStatus::Paused
                } else {
                    AttackStatus::Running
                }
            }
        }
    }

    /// Counters from the live attack.
    ///
    /// Zeros when nothing is running, rather than the last observed value, so a
    /// finished attack reads as finished instead of frozen at its peak.
    pub async fn counters(&self) -> (u64, u64) {
        let slot = self.attack.0.lock().await;
        match slot.as_ref() {
            None => (0, 0),
            Some(handle) => (handle.counters().tested(), handle.counters().cracked()),
        }
    }

    /// Observed rate, or zero when idle.
    pub async fn hash_rate(&self) -> f64 {
        let slot = self.attack.0.lock().await;
        match slot.as_ref() {
            None => 0.0,
            Some(handle) => handle.hashes_per_second().await,
        }
    }

    /// Everything the dashboard knows about the current attack.
    pub async fn snapshot(&self) -> AttackSnapshot {
        let (tested, cracked) = self.counters().await;
        let status = self.status().await;
        let rate = self.hash_rate().await;
        let hits: Vec<CrackedHit> = {
            let slot = self.attack.0.lock().await;
            match slot.as_ref() {
                None => Vec::new(),
                Some(handle) => handle.hits().await,
            }
        };
        AttackSnapshot {
            status,
            tested,
            cracked,
            hash_rate: rate,
            hits,
            executor_wired: self.executor_wired,
        }
    }

    pub async fn log_message(&self, msg: String) {
        let stamp = chrono::Utc::now().format("%H:%M:%S");
        let mut log = self.message_log.write().await;
        log.push(format!("[{stamp}] {msg}"));
        while log.len() > 1000 {
            log.remove(0);
        }
    }

    pub async fn add_worker(&self, name: &str, hps: f64) {
        let mut workers = self.workers.write().await;
        if let Some(w) = workers.iter_mut().find(|w| w.name == name) {
            w.hashes_sec = hps;
            w.alive = true;
        } else {
            workers.push(WorkerEntry {
                name: name.to_string(),
                hashes_sec: hps,
                total_cracked: 0,
                alive: true,
            });
        }
    }
}

/// What the status route and the websocket report.
#[derive(Clone, serde::Serialize, Debug)]
pub struct AttackSnapshot {
    pub status: AttackStatus,
    pub tested: u64,
    pub cracked: u64,
    pub hash_rate: f64,
    pub hits: Vec<CrackedHit>,
    pub executor_wired: bool,
}

/// Binds and serves on the configured address.
///
/// The bind policy is checked before the listener is created, so a refused
/// configuration never has a socket for even an instant.
pub async fn serve(
    config: crate::WebConfig,
    executor: Arc<dyn AttackExecutor>,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = resolve(&config)?;
    let listener = tokio::net::TcpListener::bind(policy.socket_addr()).await?;
    serve_on(config, executor, policy, listener).await
}

/// Binds the token, checks the policy, and reports what was decided.
///
/// Separated from `serve` so a caller can print the token before any socket
/// exists. A token printed after the listener is up can be missed by a test or
/// a script that connects immediately.
fn resolve(config: &crate::WebConfig) -> Result<WebBindPolicy, Box<dyn std::error::Error>> {
    let store = config.store();
    let (token, generated) = store.load_or_create()?;
    let policy = config.bind_policy(true);
    policy.check()?;

    let addr = policy.socket_addr();
    log::info!("dashboard on http://{addr} ({})", policy.describe());
    if generated {
        eprintln!("\n  dashboard token (shown once): {token}\n");
        log::warn!(
            "generated a new dashboard token at {}\n\
             mutating routes need: Authorization: Bearer <token>\n\
             plus header {}: {}",
            store.path().display(),
            crate::auth::CSRF_HEADER,
            crate::auth::CSRF_HEADER_VALUE,
        );
    }
    let _ = token;
    Ok(policy)
}

/// Serves on an already bound listener.
///
/// The listener is a parameter so a test can bind port 0 and learn the real port,
/// which avoids two runs of the suite colliding on a fixed one.
pub async fn serve_on(
    _config: crate::WebConfig,
    executor: Arc<dyn AttackExecutor>,
    policy: WebBindPolicy,
    listener: tokio::net::TcpListener,
) -> Result<(), Box<dyn std::error::Error>> {
    let token = _config.store().load_or_create()?.0;
    let state = Arc::new(AppState::new(Some(token), policy, executor));
    let app = crate::routes::build(Arc::clone(&state));

    // ConnectInfo is what `source_of` reads, and without it every client shares
    // one rate limit bucket. Strictly safer, but it makes the audit log useless.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attack::{AttackRequest, AttackExecutor, BatchOutcome, CrackedHit as Hit};
    use std::sync::atomic::{AtomicU64, Ordering};

    /// An executor that can be told to stall, so a test can observe Running.
    struct Stub {
        total: u64,
        calls: AtomicU64,
    }

    impl Stub {
        fn new(total: u64) -> Self {
            Stub {
                total,
                calls: AtomicU64::new(0),
            }
        }
    }

    impl AttackExecutor for Stub {
        fn candidates(&self, _r: &AttackRequest, offset: u64, count: u64) -> Result<Vec<String>, String> {
            let mut v = Vec::new();
            for i in offset..(offset + count).min(self.total) {
                v.push(format!("c{i}"));
            }
            Ok(v)
        }
        fn keyspace_size(&self, _r: &AttackRequest) -> Option<u64> {
            Some(self.total)
        }
        fn test_batch(&self, _r: &AttackRequest, c: &[String]) -> Result<BatchOutcome, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(BatchOutcome {
                tested: c.len() as u64,
                cracked: vec![Hit {
                    hash: "h".into(),
                    password: c.first().cloned().unwrap_or_default(),
                }]
                .into_iter()
                .take(if self.total == 0 { 0 } else { 1 })
                .collect(),
            })
        }
        fn batch_size(&self) -> u64 {
            4
        }
    }

    fn request() -> AttackRequest {
        AttackRequest {
            attack_type: "bruteforce".into(),
            hash_type: "MD5".into(),
            target_hashes: vec!["5d41402abc4b2a76b9719d911017c592".into()],
            mask: Some("?a".into()),
            wordlist: None,
            rules: vec![],
        }
    }

    /// An unwired dashboard must say so, because the whole point is that it
    /// cannot pretend.
    #[tokio::test]
    async fn an_unwired_executor_is_reported_as_unwired() {
        let state = AppState::inert(Some("t".into()));
        assert!(!state.executor_wired);
        assert!(!state.snapshot().await.executor_wired);
    }

    #[tokio::test]
    async fn a_wired_executor_is_reported_as_wired() {
        let state = AppState::new(
            Some("t".into()),
            WebBindPolicy::default(),
            Arc::new(Stub::new(100)),
        );
        assert!(state.executor_wired);
        assert!(state.snapshot().await.executor_wired);
    }

    #[tokio::test]
    async fn with_nothing_running_the_status_is_idle_and_the_counters_are_zero() {
        let state = AppState::new(
            Some("t".into()),
            WebBindPolicy::default(),
            Arc::new(Stub::new(100)),
        );
        assert_eq!(state.status().await, AttackStatus::Idle);
        assert_eq!(state.counters().await, (0, 0));
        assert_eq!(state.hash_rate().await, 0.0);
        assert!(state.snapshot().await.hits.is_empty());
    }

    /// The property the old code could not have: status follows the handle.
    #[tokio::test]
    async fn the_status_follows_the_live_attack() {
        let state = AppState::new(
            Some("t".into()),
            WebBindPolicy::default(),
            Arc::new(Stub::new(1_000_000)),
        );
        let handle = crate::attack::spawn(state.executor.clone(), request()).expect("starts");
        state.attack.replace(handle).await;
        assert_eq!(state.status().await, AttackStatus::Running);

        let slot = state.attack.0.lock().await;
        let handle = slot.as_ref().expect("installed");
        handle.pause();
        drop(slot);
        assert_eq!(state.status().await, AttackStatus::Paused);

        let slot = state.attack.0.lock().await;
        slot.as_ref().expect("installed").resume();
        drop(slot);
        assert_eq!(state.status().await, AttackStatus::Running);

        let slot = state.attack.0.lock().await;
        slot.as_ref().expect("installed").stop();
        drop(slot);
        assert_eq!(state.status().await, AttackStatus::Finished);
    }

    #[tokio::test]
    async fn replacing_an_attack_stops_the_previous_one() {
        let state = AppState::new(
            Some("t".into()),
            WebBindPolicy::default(),
            Arc::new(Stub::new(1_000_000)),
        );
        let first = crate::attack::spawn(state.executor.clone(), request()).expect("starts");
        let first_control = first.control();
        state.attack.replace(first).await;

        let second = crate::attack::spawn(state.executor.clone(), request()).expect("starts");
        state.attack.replace(second).await;

        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(
            first_control.is_stopped(),
            "replacing must stop the old attack, not leave it running"
        );
    }

    #[tokio::test]
    async fn stopping_with_nothing_running_reports_that_there_was_nothing() {
        let state = AppState::inert(Some("t".into()));
        assert!(!state.attack.take_and_stop().await, "nothing to stop");
        assert_eq!(state.status().await, AttackStatus::Idle);
    }

    #[tokio::test]
    async fn stopping_removes_the_attack_so_the_status_returns_to_idle() {
        let state = AppState::new(
            Some("t".into()),
            WebBindPolicy::default(),
            Arc::new(Stub::new(1_000_000)),
        );
        let handle = crate::attack::spawn(state.executor.clone(), request()).expect("starts");
        state.attack.replace(handle).await;
        assert!(state.attack.take_and_stop().await);
        assert_eq!(state.status().await, AttackStatus::Idle);
        assert_eq!(state.counters().await, (0, 0));
    }

    /// A short run finishes and the numbers stay readable afterwards.
    #[tokio::test]
    async fn a_short_run_produces_tested_and_cracked_counts() {
        let state = AppState::new(
            Some("t".into()),
            WebBindPolicy::default(),
            Arc::new(Stub::new(40)),
        );
        let handle = crate::attack::spawn(state.executor.clone(), request()).expect("starts");
        state.attack.replace(handle).await;
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let (tested, _) = state.counters().await;
            if tested >= 40 {
                break;
            }
        }
        let (tested, cracked) = state.counters().await;
        assert_eq!(tested, 40, "every candidate was tested");
        assert!(cracked >= 1, "the stub reports a hit per batch");
    }

    #[tokio::test]
    async fn the_log_is_bounded() {
        let state = AppState::inert(Some("t".into()));
        for _ in 0..1500 {
            state.log_message("line".into()).await;
        }
        assert_eq!(state.message_log.read().await.len(), 1000);
    }

    #[tokio::test]
    async fn a_worker_is_updated_not_duplicated() {
        let state = AppState::inert(Some("t".into()));
        state.add_worker("node-1", 100.0).await;
        state.add_worker("node-1", 250.0).await;
        let workers = state.workers.read().await;
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].hashes_sec, 250.0);
    }
}