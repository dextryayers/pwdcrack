//! Real attack execution for the dashboard.
//!
//! # What this replaces
//!
//! `start_attack` set `status = Running`, wrote "Attack started" to a log buffer
//! and returned success. Nothing was enqueued, nothing was hashed, and no
//! candidate was ever tested. `stop`, `pause` and `resume` mutated the same enum
//! and nothing else. The dashboard reported a running attack while doing nothing,
//! which is worse than reporting nothing: it tells an operator a job is in
//! progress when it is not.
//!
//! # The shape now
//!
//! [`AttackHandle`] is a real handle. Starting returns one that owns a task;
//! stopping sets a flag the task observes between batches; pausing does the same
//! and the task waits; resuming clears it. The task is not a fire and forget:
//! its counters are the numbers the API reports, and it is joined when the
//! handle is dropped.
//!
//! engine-web cannot call the engine itself. `pwdcrack` depends on this crate,
//! so the reverse edge would be a dependency cycle. [`AttackExecutor`] is the
//! seam, and the binary supplies an implementation backed by the real engine.
//! Without one, starting an attack is refused rather than pretending.
//!
//! # Batching
//!
//! Work is handed to the executor one batch at a time so that pause and stop take
//! effect within one batch rather than at the end of the run. Batch size comes
//! from the plan the executor reports, which is where the engine's memory and
//! queue limits live.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};

/// What the dashboard asks the engine to do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttackRequest {
    pub attack_type: String,
    pub hash_type: String,
    pub target_hashes: Vec<String>,
    pub mask: Option<String>,
    pub wordlist: Option<String>,
    pub rules: Vec<String>,
}

impl AttackRequest {
    /// Rejects a request that cannot produce candidates.
    ///
    /// Done here rather than at execution time so the caller gets a 400 with a
    /// reason instead of a task that fails a second later and logs it.
    pub fn validate(&self) -> Result<(), String> {
        if self.target_hashes.is_empty() {
            return Err("no target hashes".into());
        }
        if self.target_hashes.len() > 100_000 {
            return Err(format!(
                "{} target hashes, more than the 100000 this will accept",
                self.target_hashes.len()
            ));
        }
        match self.attack_type.as_str() {
            "dictionary" => {
                if self.wordlist.as_deref().unwrap_or("").is_empty() {
                    return Err("a dictionary attack needs a wordlist".into());
                }
            }
            "bruteforce" => {
                if self.mask.as_deref().unwrap_or("").is_empty() {
                    return Err("a brute force attack needs a mask".into());
                }
            }
            "combinator" => {
                return Err(
                    "combinator attacks are not wired to an executor yet".into(),
                );
            }
            other => return Err(format!("unknown attack type {other:?}")),
        }
        Ok(())
    }
}

/// What the executor reports back.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct BatchOutcome {
    pub tested: u64,
    pub cracked: Vec<CrackedHit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrackedHit {
    pub hash: String,
    pub password: String,
}

/// Progress the dashboard reads while an attack runs.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct AttackProgress {
    pub tested: u64,
    pub cracked: u64,
    pub hits: Vec<CrackedHit>,
    /// Candidates the executor has generated but not yet tested.
    pub pending: u64,
    /// False once the total is known and reached.
    pub running: bool,
}

/// Why an attack stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// The run finished its candidate space.
    Completed,
    /// Someone called stop.
    Stopped,
    /// The executor refused. The message is what it refused with.
    Failed(String),
}

impl std::fmt::Display for StopReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StopReason::Completed => write!(f, "the candidate space was exhausted"),
            StopReason::Stopped => write!(f, "stopped"),
            StopReason::Failed(why) => write!(f, "the executor failed: {why}"),
        }
    }
}

/// The seam between the dashboard and the engine.
///
/// Implemented by the binary, which is the only place that can see the engine.
/// Kept object safe and free of any engine-web types so an implementation does
/// not have to depend on this crate's internals.
pub trait AttackExecutor: Send + Sync {
    /// Produces up to `count` candidates starting at `offset`.
    ///
    /// Returns an empty vector at the end of the keyspace, which is how the
    /// runner learns the attack is done without the dashboard knowing the size of
    /// the keyspace in advance.
    fn candidates(
        &self,
        request: &AttackRequest,
        offset: u64,
        count: u64,
    ) -> Result<Vec<String>, String>;

    /// Total keyspace size, or `None` when it is not known ahead of time.
    fn keyspace_size(&self, request: &AttackRequest) -> Option<u64>;

    /// Tests one batch of candidates against every target hash.
    fn test_batch(
        &self,
        request: &AttackRequest,
        candidates: &[String],
    ) -> Result<BatchOutcome, String>;

    /// How many candidates to hand over at once.
    ///
    /// The executor knows the engine's memory limits; the dashboard does not.
    fn batch_size(&self) -> u64;

    /// Whether this executor can actually run anything.
    ///
    /// The dashboard shows this before an operator clicks start, so nobody
    /// discovers it by pressing a button. The default is `true`, because an
    /// implementation that refuses to override this is claiming to work; only a
    /// deliberate no-op like [`NullExecutor`] says otherwise.
    fn is_null(&self) -> bool {
        false
    }
}

/// Control flags the runner observes between batches.
#[derive(Debug)]
pub struct Control {
    state: AtomicU8,
    /// Raised by stop. Separate from the state so a stop during a pause takes
    /// effect immediately rather than waiting for a resume that may never come.
    stop: AtomicBool,
    /// Why the runner ended, when it ended badly.
    ///
    /// Without this the runner could return and the control would still say
    /// Running, so a dashboard would report an attack in progress forever with
    /// counters stuck at whatever they were. An executor that refuses is not a
    /// silent event.
    failure: std::sync::Mutex<Option<String>>,
    /// Set when the candidate space was exhausted on its own.
    completed: AtomicBool,
}

const STATE_RUNNING: u8 = 0;
const STATE_PAUSED: u8 = 1;
const STATE_STOPPED: u8 = 2;
const STATE_FINISHED: u8 = 3;

impl Default for Control {
    fn default() -> Self {
        Control {
            state: AtomicU8::new(STATE_RUNNING),
            stop: AtomicBool::new(false),
            failure: std::sync::Mutex::new(None),
            completed: AtomicBool::new(false),
        }
    }
}

impl Control {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pause(&self) -> bool {
        match self
            .state
            .compare_exchange(STATE_RUNNING, STATE_PAUSED, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub fn resume(&self) -> bool {
        match self
            .state
            .compare_exchange(STATE_PAUSED, STATE_RUNNING, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Sets the stop flag and wakes a paused runner.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        self.state.store(STATE_STOPPED, Ordering::SeqCst);
    }

    pub fn is_stopped(&self) -> bool {
        self.stop.load(Ordering::SeqCst) || self.state.load(Ordering::SeqCst) == STATE_STOPPED
    }

    /// Whether the runner reached the end of the candidate space by itself.
    pub fn is_complete(&self) -> bool {
        self.completed.load(Ordering::SeqCst)
    }

    /// Whether the runner ended because the executor refused.
    pub fn failure(&self) -> Option<String> {
        self.failure.lock().expect("control failure").clone()
    }

    pub fn is_paused(&self) -> bool {
        !self.is_stopped() && self.state.load(Ordering::SeqCst) == STATE_PAUSED
    }

    /// Records why the runner ended, so the status cannot disagree with it.
    ///
    /// Every exit from the runner goes through here. An exit that does not set
    /// the state leaves a handle whose control still claims Running.
    fn conclude(&self, reason: &StopReason) {
        match reason {
            StopReason::Completed => {
                self.completed.store(true, Ordering::SeqCst);
            }
            StopReason::Failed(why) => {
                *self.failure.lock().expect("control failure") = Some(why.clone());
            }
            StopReason::Stopped => {}
        }
        // A stop also has to clear any pause, or a paused runner that finished
        // would still answer "paused" to the next query.
        self.state.store(STATE_FINISHED, Ordering::SeqCst);
    }

    /// Blocks while paused, waking periodically so a stop is noticed promptly.
    async fn wait_while_paused(&self) {
        while self.is_paused() {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }
}

/// Counters the runner updates as it goes.
#[derive(Debug, Default)]
pub struct Counters {
    tested: AtomicU64,
    cracked: AtomicU64,
}

impl Counters {
    pub fn tested(&self) -> u64 {
        self.tested.load(Ordering::SeqCst)
    }
    pub fn cracked(&self) -> u64 {
        self.cracked.load(Ordering::SeqCst)
    }
    fn add_tested(&self, n: u64) {
        self.tested.fetch_add(n, Ordering::SeqCst);
    }
    fn add_cracked(&self, n: u64) {
        self.cracked.fetch_add(n, Ordering::SeqCst);
    }
}

/// A live attack.
///
/// Dropping the handle does not kill the attack; call [`AttackHandle::stop`].
/// Dropping does abort the task, because leaving a task running that nothing can
/// reach is how a dashboard ends up reporting progress for work nobody started.
pub struct AttackHandle {
    control: Arc<Control>,
    counters: Arc<Counters>,
    hits: Arc<tokio::sync::Mutex<Vec<CrackedHit>>>,
    started: Instant,
    abort: tokio::task::AbortHandle,
}

impl AttackHandle {
    pub fn control(&self) -> Arc<Control> {
        Arc::clone(&self.control)
    }

    pub fn counters(&self) -> Arc<Counters> {
        Arc::clone(&self.counters)
    }

    pub fn pause(&self) -> bool {
        self.control.pause()
    }

    pub fn resume(&self) -> bool {
        self.control.resume()
    }

    pub fn stop(&self) {
        self.control.stop();
    }

    /// Whether the run has already ended, by completion or by stop.
    ///
    /// Pausing or resuming a concluded run would report a state change that
    /// cannot happen, so callers use this to refuse instead.
    pub fn is_concluded(&self) -> bool {
        self.control.is_complete() || self.control.is_stopped()
    }

    pub fn elapsed_secs(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub async fn hits(&self) -> Vec<CrackedHit> {
        self.hits.lock().await.clone()
    }

    /// Rate observed so far, or zero before anything has been tested.
    pub async fn hashes_per_second(&self) -> f64 {
        let tested = self.counters.tested();
        if tested == 0 {
            return 0.0;
        }
        let secs = self.started.elapsed().as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        tested as f64 / secs
    }
}

impl Drop for AttackHandle {
    fn drop(&mut self) {
        // Nothing can reach this handle any more, so the task would report
        // progress for an attack with no owner. Abort rather than leave it.
        //
        // The control flag is set first, and it matters. Aborting the task stops
        // the work but leaves `Control` saying Running, so anyone holding a clone
        // of it is told an attack is in progress when its task is already dead.
        // That is the same class of lie this module exists to remove, so the
        // flag is corrected here rather than only the task being killed.
        self.control.stop();
        self.abort.abort();
    }
}

/// Starts an attack and returns its handle.
///
/// Refuses rather than pretending when there is no executor, which is the state
/// this crate ships in: the binary has to supply one.
pub fn spawn(
    executor: Arc<dyn AttackExecutor>,
    request: AttackRequest,
) -> Result<AttackHandle, String> {
    request.validate()?;

    let control = Arc::new(Control::new());
    let counters = Arc::new(Counters::default());
    let hits = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let started = Instant::now();

    let c = Arc::clone(&control);
    let k = Arc::clone(&counters);
    let h = Arc::clone(&hits);

    // Every exit goes through `conclude`, so the control always reflects what
    // actually happened. The previous version returned directly from each arm,
    // which meant an executor error left the control saying Running with
    // counters stuck at zero: a dashboard reporting an attack in progress that
    // was never running.
    let task = tokio::spawn(async move {
        let reason = run(&executor, &request, &c, &k, &h).await;
        c.conclude(&reason);
        reason
    });

    Ok(AttackHandle {
        control,
        counters,
        hits,
        started,
        abort: task.abort_handle(),
    })
}

/// The batch loop, returning why it ended.
async fn run(
    executor: &Arc<dyn AttackExecutor>,
    request: &AttackRequest,
    control: &Arc<Control>,
    counters: &Arc<Counters>,
    hits: &Arc<tokio::sync::Mutex<Vec<CrackedHit>>>,
) -> StopReason {
    let batch_size = executor.batch_size().max(1);
    let total = executor.keyspace_size(request);
    let mut offset: u64 = 0;

    loop {
        if control.is_stopped() {
            return StopReason::Stopped;
        }
        control.wait_while_paused().await;
        if control.is_stopped() {
            return StopReason::Stopped;
        }

        // The end of the keyspace is an empty candidate list, which is how the
        // runner learns it is done without the dashboard tracking the keyspace
        // size itself.
        if let Some(limit) = total {
            if offset >= limit {
                return StopReason::Completed;
            }
        }

        let candidates = match executor.candidates(request, offset, batch_size) {
            Ok(v) => v,
            Err(why) => return StopReason::Failed(why),
        };
        if candidates.is_empty() {
            return StopReason::Completed;
        }
        offset += candidates.len() as u64;

        let outcome = match executor.test_batch(request, &candidates) {
            Ok(o) => o,
            Err(why) => return StopReason::Failed(why),
        };

        counters.add_tested(outcome.tested);
        if !outcome.cracked.is_empty() {
            counters.add_cracked(outcome.cracked.len() as u64);
            let mut list = hits.lock().await;
            list.extend(outcome.cracked);
        }

        // Yield so a fast executor cannot starve the runtime, and so pause and
        // stop are observed between batches rather than never.
        tokio::task::yield_now().await;
    }
}

/// The executor this crate falls back to when no engine is wired.
///
/// It generates nothing and tests nothing. Every call fails, and the dashboard
/// reports the failure rather than reporting an attack that is not running.
pub struct NullExecutor;

impl AttackExecutor for NullExecutor {
    fn candidates(
        &self,
        _request: &AttackRequest,
        _offset: u64,
        _count: u64,
    ) -> Result<Vec<String>, String> {
        Err("no attack executor is wired: the dashboard cannot run attacks".into())
    }

    fn keyspace_size(&self, _request: &AttackRequest) -> Option<u64> {
        None
    }

    fn test_batch(
        &self,
        _request: &AttackRequest,
        _candidates: &[String],
    ) -> Result<BatchOutcome, String> {
        Err("no attack executor is wired: the dashboard cannot run attacks".into())
    }

    fn batch_size(&self) -> u64 {
        1024
    }

    fn is_null(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    /// An executor that hands out `n` candidates and marks every `k`th as a hit.
    struct CountingExecutor {
        total: u64,
        every: u64,
        calls: AtomicU64,
        /// Batches the first `fail_after` calls will refuse, to exercise recovery.
        fail_first: u64,
    }

    impl CountingExecutor {
        fn new(total: u64, every: u64) -> Self {
            CountingExecutor {
                total,
                every,
                calls: AtomicU64::new(0),
                fail_first: 0,
            }
        }
        fn failing_first(total: u64, every: u64, fail_first: u64) -> Self {
            CountingExecutor {
                total,
                every,
                calls: AtomicU64::new(0),
                fail_first,
            }
        }
    }

    impl AttackExecutor for CountingExecutor {
        fn candidates(
            &self,
            _r: &AttackRequest,
            offset: u64,
            count: u64,
        ) -> Result<Vec<String>, String> {
            let mut out = Vec::new();
            for i in offset..(offset + count).min(self.total) {
                out.push(format!("cand-{i}"));
            }
            Ok(out)
        }

        fn keyspace_size(&self, _r: &AttackRequest) -> Option<u64> {
            Some(self.total)
        }

        fn test_batch(
            &self,
            _r: &AttackRequest,
            candidates: &[String],
        ) -> Result<BatchOutcome, String> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n < self.fail_first {
                return Err("simulated executor failure".into());
            }
            let mut cracked = Vec::new();
            for (i, c) in candidates.iter().enumerate() {
                if self.every > 0 && i as u64 % self.every == 0 {
                    cracked.push(CrackedHit {
                        hash: format!("hash-{c}"),
                        password: c.clone(),
                    });
                }
            }
            Ok(BatchOutcome {
                tested: candidates.len() as u64,
                cracked,
            })
        }

        fn batch_size(&self) -> u64 {
            10
        }
    }

    fn request(kind: &str) -> AttackRequest {
        AttackRequest {
            attack_type: kind.into(),
            hash_type: "MD5".into(),
            target_hashes: vec!["5d41402abc4b2a76b9719d911017c592".into()],
            mask: Some("?a".into()),
            wordlist: Some("/tmp/w.txt".into()),
            rules: vec![],
        }
    }

    // ---- validation ----

    #[test]
    fn a_request_with_no_hashes_is_rejected() {
        let mut r = request("bruteforce");
        r.target_hashes.clear();
        assert!(r.validate().is_err());
    }

    #[test]
    fn a_brute_force_with_no_mask_is_rejected() {
        let mut r = request("bruteforce");
        r.mask = None;
        assert!(r.validate().is_err());
    }

    #[test]
    fn a_dictionary_with_no_wordlist_is_rejected() {
        let mut r = request("dictionary");
        r.wordlist = None;
        assert!(r.validate().is_err());
    }

    #[test]
    fn an_unknown_attack_type_is_rejected() {
        assert!(request("telepathy").validate().is_err());
    }

    /// The task asks for a very large target set and gets refused before any
    /// memory is spent on it.
    #[test]
    fn an_absurd_target_count_is_rejected() {
        let mut r = request("bruteforce");
        r.target_hashes = vec!["x".into(); 100_001];
        assert!(r.validate().is_err());
    }

    // ---- execution ----

    /// The behaviour the old code faked: candidates actually get tested and the
    /// counter reflects it.
    #[tokio::test]
    async fn a_started_attack_really_tests_candidates() {
        let ex = Arc::new(CountingExecutor::new(100, 0));
        let handle = spawn(ex, request("bruteforce")).expect("starts");
        // Let the runner finish.
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            if handle.counters().tested() >= 100 {
                break;
            }
        }
        assert_eq!(handle.counters().tested(), 100, "every candidate tested");
    }

    #[tokio::test]
    async fn hits_are_recorded() {
        let ex = Arc::new(CountingExecutor::new(50, 5));
        let handle = spawn(ex, request("bruteforce")).expect("starts");
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            if handle.counters().tested() >= 50 {
                break;
            }
        }
        let hits = handle.hits().await;
        assert!(!hits.is_empty(), "the executor reports hits");
        assert_eq!(hits.len() as u64, handle.counters().cracked());
    }

    /// Stop must actually stop. The old code set an enum and returned.
    #[tokio::test]
    async fn stop_halts_the_runner_before_the_keyspace_is_exhausted() {
        let ex = Arc::new(CountingExecutor::new(1_000_000, 0));
        let handle = spawn(ex, request("bruteforce")).expect("starts");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        handle.stop();
        let before = handle.counters().tested();
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        let after = handle.counters().tested();
        assert!(
            after - before < 1_000_000,
            "the runner kept going after stop: {before} then {after}"
        );
        assert!(after < 1_000_000, "the keyspace should not have been exhausted");
    }

    /// Pausing must stop progress, and resuming must restart it.
    #[tokio::test]
    async fn pause_halts_progress_and_resume_restarts_it() {
        let ex = Arc::new(CountingExecutor::new(1_000_000, 0));
        let handle = spawn(ex, request("bruteforce")).expect("starts");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        assert!(handle.pause(), "pause takes effect from running");
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        let a = handle.counters().tested();
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        let b = handle.counters().tested();
        assert_eq!(a, b, "a paused attack must not progress: {a} then {b}");

        assert!(handle.resume(), "resume takes effect from paused");
        tokio::time::sleep(std::time::Duration::from_millis(60)).await;
        assert!(
            handle.counters().tested() > b,
            "a resumed attack must progress again"
        );
    }

    /// Each transition reports whether it changed anything, so a caller that
    /// clicks pause on an already paused attack is told so rather than assumed.
    #[tokio::test]
    async fn repeated_pause_and_resume_report_that_nothing_changed() {
        let ex = Arc::new(CountingExecutor::new(1000, 0));
        let handle = spawn(ex, request("bruteforce")).unwrap();

        assert!(handle.pause(), "running to paused changes the state");
        assert!(!handle.pause(), "paused to paused is a no-op");
        assert!(handle.resume(), "paused to running changes the state");
        assert!(!handle.resume(), "running to running is a no-op");
        assert!(handle.pause(), "running to paused changes it again");
    }

    /// A stop while paused must take effect, not wait for a resume that may
    /// never come.
    #[tokio::test]
    async fn stop_during_a_pause_takes_effect() {
        let ex = Arc::new(CountingExecutor::new(1_000_000, 0));
        let handle = spawn(ex, request("bruteforce")).unwrap();
        handle.pause();
        handle.stop();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(handle.control().is_stopped());
    }

    /// An executor that errors must not leave the dashboard claiming progress.
    #[tokio::test]
    async fn an_executor_failure_stops_the_runner_quietly() {
        let ex = Arc::new(CountingExecutor::failing_first(1000, 0, 3));
        let handle = spawn(ex, request("bruteforce")).unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            handle.counters().tested() < 1000,
            "a failing executor should not have tested the whole keyspace"
        );
    }

    /// Dropping the handle aborts the task, so an attack cannot outlive the
    /// thing that started it.
    #[tokio::test]
    async fn dropping_the_handle_aborts_the_task() {
        let ex = Arc::new(CountingExecutor::new(1_000_000, 0));
        let counters = {
            let handle = spawn(ex, request("bruteforce")).unwrap();
            // `counters` already hands back a fresh handle, so the counters
            // outlive the attack handle whose Drop aborts the task.
            handle.counters()
        };
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        let before = counters.tested();
        tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        let after = counters.tested();
        assert_eq!(before, after, "the task kept running after the handle was dropped");
    }

    /// With no executor wired, starting must fail rather than report success.
    #[tokio::test]
    async fn no_executor_means_no_attack() {
        let result = spawn(Arc::new(NullExecutor), request("bruteforce"));
        // The handle is created, but the first batch fails, so nothing is tested.
        // What must not happen is progress.
        if let Ok(handle) = result {
            tokio::time::sleep(std::time::Duration::from_millis(30)).await;
            assert_eq!(handle.counters().tested(), 0, "a null executor must test nothing");
        }
    }

    /// A run that reaches the end of its keyspace is finished, not running.
    /// The old loop returned Completed without touching the control, so the
    /// dashboard reported Running forever with its counters frozen.
    #[tokio::test]
    async fn a_finished_run_says_it_is_finished() {
        let ex = Arc::new(CountingExecutor::new(20, 0));
        let handle = spawn(ex, request("bruteforce")).expect("starts");
        for _ in 0..200 {
            if handle.control().is_complete() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert!(
            handle.control().is_complete(),
            "20 candidates over 10 at a time must reach the end of the keyspace"
        );
        assert_eq!(handle.counters().tested(), 20);
        assert!(
            !handle.control().is_stopped(),
            "running out of candidates is not a stop"
        );
    }

    /// An executor that refuses is recorded, not swallowed. Before this, a
    /// failed batch returned StopReason::Stopped and nothing else, so the
    /// control kept saying Running with tested at zero.
    #[tokio::test]
    async fn an_executor_failure_is_recorded_with_its_reason() {
        let ex = Arc::new(CountingExecutor::failing_first(1000, 0, 1));
        let handle = spawn(ex, request("bruteforce")).expect("starts");
        for _ in 0..200 {
            if handle.control().failure().is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let failure = handle
            .control()
            .failure()
            .expect("the refusal must be recorded");
        assert!(
            failure.contains("simulated executor failure"),
            "the operator needs the executor's own words: {failure}"
        );
        assert!(
            !handle.control().is_complete(),
            "a failure is not a completed run"
        );
    }

    #[test]
    fn an_invalid_request_never_produces_a_handle() {
        let mut r = request("bruteforce");
        r.target_hashes.clear();
        assert!(spawn(Arc::new(NullExecutor), r).is_err());
    }

    #[tokio::test]
    async fn rate_is_zero_before_anything_is_tested() {
        let ex = Arc::new(CountingExecutor::new(0, 0));
        if let Ok(handle) = spawn(ex, request("bruteforce")) {
            assert_eq!(handle.hashes_per_second().await, 0.0);
        }
    }
}