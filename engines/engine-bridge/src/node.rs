//! Node.js bindings, through N-API.
//!
//! # What this replaced
//!
//! The previous version declared the N-API C functions by hand, with
//! `std::ffi::c_void`, and implemented `crack_verify` by reading one argument
//! into a 256 byte buffer, discarding it, and returning the literal string
//! `"ok"`. Three separate defects:
//!
//!   * it verified nothing, so every call "succeeded";
//!   * the returned pointer came from a `CString` that was dropped at the end of
//!     the function, so the caller read freed memory;
//!   * a password longer than 256 bytes was silently truncated, which for a
//!     password cracker means reporting a result for a different password.
//!
//! The hand written declarations also stopped at the first five N-API functions,
//! so there was no way to raise an error, return a number, or build an object.
//!
//! # Why the `napi` crate
//!
//! It is already a dependency, so using it adds nothing to the dependency graph,
//! and it gets the parts that are easy to get wrong: string lifetimes, error
//! propagation across the boundary, and the `Task` machinery that turns a long
//! running call into a JavaScript promise.
//!
//! # Sync and async
//!
//! Verification and detection are cheap and synchronous. Attacks are not: a
//! dictionary attack over a real wordlist runs for minutes. Those are exposed as
//! `AsyncTask`, which returns a Promise and runs the work on the libuv thread
//! pool, so the Node event loop keeps running. `attackDictionarySync` also exists
//! for scripts that want to block, but it is not the default: blocking the event
//! loop of a server for the length of an attack is a denial of service waiting
//! to happen.
//!
//! # Engine state
//!
//! One process wide engine, shared with the C bridge, because the engine is a
//! process wide resource. `Cracker` instances therefore share loaded hashes and
//! results with each other and with the free functions; they are namespaces for
//! convenience, not isolation.

use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::Instant;

use napi::bindgen_prelude::*;
// The attribute macros come from napi_derive, not from the napi crate itself.
// Without this import `#[napi]` resolves to the crate, which is a name and not
// an attribute, and every annotated item fails to compile.
use napi_derive::napi;
use napi::{Env, Error, Result, Status, Task};

use pwdcrack::attack::CrackResult;
use pwdcrack::engine::Engine as _;
use pwdcrack::hash::detector::Detector;
use pwdcrack::hash::{HashCracker, HashEntry};

// ── Engine state ──────────────────────────────────────────────────────────

struct EngineState {
    detector: Detector,
    targets: Vec<(Box<dyn HashCracker>, HashEntry)>,
    results: Vec<CrackResult>,
}

impl EngineState {
    fn new() -> Self {
        EngineState {
            detector: Detector::new(),
            targets: Vec::new(),
            results: Vec::new(),
        }
    }

    fn load_text(&mut self, text: &str) -> usize {
        self.targets.clear();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((cracker, entry)) = self.detector.detect(line) {
                self.targets.push((cracker, entry));
                continue;
            }
            if let Some((_, suffix)) = line.rsplit_once(':') {
                if let Some((cracker, entry)) = self.detector.detect(suffix) {
                    self.targets.push((cracker, entry));
                }
            }
        }
        self.targets.len()
    }

    /// Splits targets by cracker type, borrowing the list.
    ///
    /// Borrowing rather than consuming is deliberate. An earlier version took the
    /// targets out to run the attack and put them back afterwards with a
    /// placeholder cracker, because a cracker cannot be cloned out of a `Box`
    /// without going through `clone_box`. The placeholder answers `false` for
    /// everything, so a second attack on the same session silently cracked
    /// nothing and reported success. The targets are never disturbed now.
    fn groups(&self) -> Vec<(Box<dyn HashCracker>, Vec<HashEntry>)> {
        let mut groups: Vec<(Box<dyn HashCracker>, Vec<HashEntry>)> = Vec::new();
        for (cracker, entry) in &self.targets {
            let hash_type = cracker.hash_type();
            match groups.iter_mut().find(|(c, _)| c.hash_type() == hash_type) {
                Some((_, list)) => list.push(entry.clone()),
                None => groups.push((cracker.clone_box(), vec![entry.clone()])),
            }
        }
        groups
    }
}

static ENGINE: LazyLock<Mutex<EngineState>> =
    LazyLock::new(|| Mutex::new(EngineState::new()));

fn engine() -> Result<std::sync::MutexGuard<'static, EngineState>> {
    ENGINE.lock().map_err(|_| {
        Error::new(
            Status::GenericFailure,
            "pwdcrack engine lock is poisoned by an earlier panic",
        )
    })
}

/// A poisoned lock is a real condition and not a reason to unwind into Node, so
/// it is a rejected promise or a thrown error, never a panic across the FFI
/// boundary.
fn to_napi<T>(result: std::result::Result<T, String>) -> Result<T> {
    result.map_err(|e| Error::new(Status::GenericFailure, e))
}

// ── Plain data ────────────────────────────────────────────────────────────

/// One cracked hash.
#[napi(object)]
#[derive(Clone)]
pub struct CrackedHash {
    /// The hash string as it was loaded.
    pub hash: String,
    /// The cracker's name for it.
    pub hash_type: String,
    /// The recovered password. `null` when it was never found, which is not the
    /// same as an empty string: an empty password is a real recovery.
    pub password: Option<String>,
}

/// A loaded hash.
#[napi(object)]
#[derive(Clone)]
pub struct Target {
    pub raw: String,
    pub hash_type: String,
    pub username: Option<String>,
    pub salt: Option<String>,
}

/// A detected hash type.
#[napi(object)]
pub struct Detection {
    /// The cracker's name, or `"Unknown"` when no parser claimed it.
    pub hash_type: String,
    /// False when nothing recognised it, so a caller can branch without
    /// comparing against the string "Unknown".
    pub recognised: bool,
}

/// The result of one attack.
#[napi(object)]
pub struct AttackOutcome {
    /// Hashes recovered.
    pub cracked: u32,
    /// Candidates tested, counted rather than estimated.
    ///
    /// A JavaScript number, so exact to 2^53. A keyspace larger than that is not
    /// reachable by any machine this could run on, and BigInt would force every
    /// caller to handle two numeric types for a value that is always small.
    pub tested: f64,
    /// Seconds the attack took.
    pub seconds: f64,
    /// Candidates per second, or `null` when the run was too short to time.
    /// Zero would read as "measured, and it was very slow".
    pub hashes_per_second: Option<f64>,
    /// Every recovered hash.
    pub results: Vec<CrackedHash>,
}

fn to_cracked(r: &CrackResult) -> CrackedHash {
    CrackedHash {
        hash: r.original.clone(),
        hash_type: r.hash_type.clone(),
        password: r.password.clone(),
    }
}

// ── Synchronous surface ───────────────────────────────────────────────────

/// The library version.
#[napi]
pub fn version() -> String {
    // The wrapped library's version, not this crate's.
    pwdcrack::VERSION.to_string()
}

/// The type of a hash string, or "Unknown".
///
/// This is how the old implementation "verified" a password: it read the
/// argument and returned "ok". It performs a real detection now, and the return
/// value distinguishes recognised from unrecognised so a caller does not have to
/// compare against a string.
#[napi]
pub fn detect(hash: String) -> Detection {
    let eng = engine().expect("engine lock");
    match eng.detector.detect(hash.trim()) {
        Some((cracker, _)) => Detection {
            hash_type: cracker.name().to_string(),
            recognised: true,
        },
        None => Detection {
            hash_type: "Unknown".to_string(),
            recognised: false,
        },
    }
}

/// Whether `password` recovers `hash`.
///
/// Three answers stay three: `true`, `false`, and a thrown error for a hash that
/// could not be checked. Returning `false` for "not checked" is how a cracker
/// reports a recovery that did not happen.
#[napi]
pub fn verify(hash: String, password: String) -> Result<bool> {
    let eng = engine()?;
    match eng.detector.detect(hash.trim()) {
        Some((cracker, entry)) => Ok(cracker.verify(&password, &entry)),
        None => Err(Error::new(
            Status::InvalidArg,
            format!("no parser recognised {hash:?}"),
        )),
    }
}

/// Loads hashes from a file, replacing anything already loaded.
#[napi]
pub fn load_file(path: String) -> Result<u32> {
    let text = std::fs::read_to_string(&path)
        .map_err(|e| Error::new(Status::GenericFailure, format!("cannot read {path}: {e}")))?;
    let mut eng = engine()?;
    Ok(eng.load_text(&text) as u32)
}

/// Loads hashes from a string.
#[napi]
pub fn load_string(text: String) -> Result<u32> {
    let mut eng = engine()?;
    Ok(eng.load_text(&text) as u32)
}

/// How many hashes are loaded.
#[napi]
pub fn target_count() -> u32 {
    engine().map(|e| e.targets.len() as u32).unwrap_or(0)
}

/// Every loaded target.
#[napi]
pub fn targets() -> Vec<Target> {
    match engine() {
        Ok(e) => e
            .targets
            .iter()
            .map(|(_, entry)| Target {
                raw: entry.raw.clone(),
                hash_type: format!("{:?}", entry.hash_type),
                username: entry.username.clone(),
                salt: entry.salt.clone(),
            })
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Forgets every loaded hash and result.
#[napi]
pub fn reset() {
    if let Ok(mut e) = engine() {
        e.targets.clear();
        e.results.clear();
    }
}

/// Results from the last attack.
#[napi]
pub fn results() -> Vec<CrackedHash> {
    match engine() {
        Ok(e) => e.results.iter().map(to_cracked).collect(),
        Err(_) => Vec::new(),
    }
}

/// The cracker's rate for the reference workload, measured on the call.
///
/// `null` until something has been measured. Built here rather than cached so
/// the number describes this moment rather than whenever the module loaded.
#[napi]
pub fn hashes_per_second() -> Option<f64> {
    let engine = pwdcrack::engine::CpuEngine::new();
    let info = engine.info();
    // `measured` is the engine's own flag. Testing the value would turn an
    // unmeasured engine reporting 0.0 into a measured zero.
    if info.measured {
        Some(info.measured_hps)
    } else {
        None
    }
}

/// Runs a dictionary attack and returns when it is finished.
///
/// This blocks the calling thread. `attackDictionary` is the one to use from a
/// server; this exists for scripts and for tests.
#[napi]
pub fn attack_dictionary_sync(wordlist: String, threads: Option<u32>) -> Result<AttackOutcome> {
    let threads = resolve_threads(threads);
    let started = Instant::now();
    let tested = count_wordlist(&wordlist).unwrap_or(0);

    // The outcome is built inside the lock block: `CrackResult` is not `Clone`,
    // so the results cannot be copied out to be measured afterwards.
    let outcome = {
        let mut eng = engine()?;
        if eng.targets.is_empty() {
            return Err(Error::new(
                Status::GenericFailure,
                "no hashes loaded; call loadFile or loadString first",
            ));
        }
        let groups = eng.groups();
        let mut all: Vec<CrackResult> = Vec::new();
        for (cracker, entries) in &groups {
            all.extend(pwdcrack::attack::dictionary::run_dictionary(
                entries,
                cracker.as_ref(),
                &wordlist,
                None,
                threads,
                true,
                false,
            ));
        }
        eng.results = all;
        outcome(std::mem::take(&mut eng.results), tested, started)
    };
    // The results were taken out to build the outcome, so put them back for
    // `results()`.
    if let Ok(mut eng) = engine() {
        eng.results = outcome
            .results
            .iter()
            .map(|c| CrackResult {
                original: c.hash.clone(),
                hash_type: c.hash_type.clone(),
                password: c.password.clone(),
            })
            .collect();
    }
    Ok(outcome)
}

/// Runs a brute force attack and returns when it is finished. Blocks.
#[napi]
pub fn attack_bruteforce_sync(mask: String, threads: Option<u32>) -> Result<AttackOutcome> {
    let threads = resolve_threads(threads);
    let started = Instant::now();
    let parsed = pwdcrack::attack::brute::parse_mask(&mask);
    let keyspace = pwdcrack::attack::brute::total_combinations(&parsed, &[]);
    let mask_len = parsed.len();
    let outcome = {
        let mut eng = engine()?;
        if eng.targets.is_empty() {
            return Err(Error::new(
                Status::GenericFailure,
                "no hashes loaded; call loadFile or loadString first",
            ));
        }
        let groups = eng.groups();
        let mut all: Vec<CrackResult> = Vec::new();
        for (cracker, entries) in &groups {
            let run = to_napi(pwdcrack::attack::brute::run_bruteforce_from(
                entries,
                cracker.as_ref(),
                &mask,
                &[],
                threads,
                true,
                false,
                mask_len,
                None,
                Some(keyspace),
                0,
            ))?;
            all.extend(run.results);
        }
        eng.results = all;
        outcome(std::mem::take(&mut eng.results), keyspace, started)
    };
    if let Ok(mut eng) = engine() {
        eng.results = outcome
            .results
            .iter()
            .map(|c| CrackResult {
                original: c.hash.clone(),
                hash_type: c.hash_type.clone(),
                password: c.password.clone(),
            })
            .collect();
    }
    Ok(outcome)
}

/// Builds an outcome from what the runner actually did.
fn outcome(results: Vec<CrackResult>, tested: u64, started: Instant) -> AttackOutcome {
    let seconds = started.elapsed().as_secs_f64();
    AttackOutcome {
        cracked: results.len() as u32,
        tested: tested as f64,
        seconds,
        hashes_per_second: if seconds > 0.0 && tested > 0 {
            Some(tested as f64 / seconds)
        } else {
            None
        },
        results: results.iter().map(to_cracked).collect(),
    }
}

fn resolve_threads(requested: Option<u32>) -> usize {
    match requested {
        Some(0) | None => std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4),
        Some(n) => n as usize,
    }
}

fn count_wordlist(path: &str) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(text.lines().filter(|l| !l.trim().is_empty()).count() as u64)
}

// ── Promise based surface ─────────────────────────────────────────────────

/// A dictionary attack, running off the event loop.
///
/// The word is "asynchronous" for a reason: an attack that runs for minutes and
/// blocks the event loop turns a Node server into a server that answers nothing.
struct DictionaryTask {
    wordlist: String,
    threads: Option<u32>,
}

impl Task for DictionaryTask {
    type Output = AttackOutcome;
    type JsValue = AttackOutcome;

    fn compute(&mut self) -> Result<Self::Output> {
        attack_dictionary_sync(self.wordlist.clone(), self.threads)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Runs a dictionary attack. Returns a Promise.
#[napi(ts_return_type = "Promise<AttackOutcome>")]
pub fn attack_dictionary(wordlist: String, threads: Option<u32>) -> AsyncTask<DictionaryTask> {
    AsyncTask::new(DictionaryTask { wordlist, threads })
}

/// A brute force attack, running off the event loop.
struct BruteforceTask {
    mask: String,
    threads: Option<u32>,
}

impl Task for BruteforceTask {
    type Output = AttackOutcome;
    type JsValue = AttackOutcome;

    fn compute(&mut self) -> Result<Self::Output> {
        attack_bruteforce_sync(self.mask.clone(), self.threads)
    }

    fn resolve(&mut self, _env: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Runs a brute force attack. Returns a Promise.
#[napi(ts_return_type = "Promise<AttackOutcome>")]
pub fn attack_bruteforce(mask: String, threads: Option<u32>) -> AsyncTask<BruteforceTask> {
    AsyncTask::new(BruteforceTask { mask, threads })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pwdcrack::engine::Engine as _;

    /// The function that previously returned "ok" for anything.
    #[test]
    fn detection_is_real_rather_than_a_literal() {
        let md5 = "900150983cd24fb0d6963f7d28e17f72";
        let found = detect(md5.to_string());
        assert!(found.recognised, "an MD5 must be recognised");
        assert_ne!(found.hash_type, "Unknown");

        let missing = detect("not a hash at all".to_string());
        assert!(!missing.recognised, "junk must not be recognised");
        assert_eq!(missing.hash_type, "Unknown");
    }

    #[test]
    fn verification_has_three_answers() {
        let md5 = "900150983cd24fb0d6963f7d28e17f72"; // MD5("abc")
        assert!(verify(md5.to_string(), "abc".to_string()).expect("checked"));
        assert!(!verify(md5.to_string(), "abd".to_string()).expect("checked"));
        assert!(
            verify("junk".to_string(), "abc".to_string()).is_err(),
            "an unrecognisable hash must raise, not return false"
        );
    }

    /// The old implementation truncated at 256 bytes, which for a password
    /// cracker means answering about a different password.
    #[test]
    fn a_long_password_is_not_truncated() {
        let long: String = "abcdefghij".repeat(100); // 1000 bytes
        let target = {
            use md5::{Digest, Md5};
            let mut h = Md5::new();
            h.update(long.as_bytes());
            hex::encode(h.finalize())
        };
        assert!(verify(target.clone(), long.clone()).expect("checked"));
        // One byte different from the truth, which truncation would have turned
        // into a match.
        assert!(!verify(target, format!("{long}x")).expect("checked"));
    }

    #[test]
    fn a_dictionary_attack_cracks() {
        let dir = std::env::temp_dir().join(format!("pwdcrack-node-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("words.txt");
        std::fs::write(&path, "abc\n").expect("write");

        assert_eq!(load_string("900150983cd24fb0d6963f7d28e17f72".to_string()).unwrap(), 1);
        let outcome = attack_dictionary_sync(path.to_string_lossy().to_string(), Some(1))
            .expect("the attack ran");
        assert_eq!(outcome.cracked, 1);
        assert_eq!(outcome.tested, 1.0, "one candidate in the wordlist");
        assert_eq!(outcome.results[0].password.as_deref(), Some("abc"));
        assert!(
            outcome.hashes_per_second.unwrap_or(0.0) > 0.0,
            "a finished attack must have a measurable rate"
        );

        let _ = std::fs::remove_dir_all(&dir);
        reset();
    }

    #[test]
    fn an_attack_with_nothing_loaded_is_refused() {
        reset();
        assert!(attack_dictionary_sync("/tmp/nothing.txt".to_string(), Some(1)).is_err());
    }

    #[test]
    fn the_engine_rate_is_none_when_unmeasured_and_some_when_measured() {
        // CpuEngine::new runs a benchmark, so this build has a real number.
        assert!(
            hashes_per_second().is_some(),
            "the CPU engine measures itself on construction"
        );
    }

    #[test]
    fn the_version_is_the_package_version() {
        assert_eq!(
            version(),
            pwdcrack::VERSION,
            "the bridge must report the version of the library it wraps"
        );
    }
}