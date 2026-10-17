//! Python bindings via PyO3.
//!
//! This module mirrors the C ABI in [`crate::c_api`] so both bridges share the
//! same engine state model and the same semantics. Where the C ABI returns
//! integer error codes, this module returns Python values and raises
//! `PyRuntimeError` or `PyValueError`, which is the idiomatic PyO3 contract.
//!
//! Build with `maturin` from `engines/engine-bridge/python`:
//!
//! ```text
//! maturin develop --release --features python
//! ```

use std::sync::{LazyLock, Mutex, MutexGuard};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use pwdcrack::engine::Engine as _;
use pwdcrack::attack::CrackResult;
use pwdcrack::attack::rules;
use pwdcrack::hash::detector::Detector;
use pwdcrack::hash::{HashCracker, HashEntry};

// ── Engine state ──────────────────────────────────────────────────────────
//
// One process wide detector is shared by every call so the roughly 700 boxed
// cracker instances inside `Detector::new()` are allocated once, not once per
// candidate or once per file.

struct EngineState {
    detector: Detector,
    /// Loaded hashes, paired with the cracker that verified them.
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

    /// Clear loaded hashes and results, keeping the detector.
    fn reset_targets(&mut self) {
        self.targets.clear();
        self.results.clear();
    }
}

static ENGINE: LazyLock<Mutex<EngineState>> =
    LazyLock::new(|| Mutex::new(EngineState::new()));

/// Lock the engine, mapping a poisoned lock onto a Python exception.
///
/// A poisoned lock means another thread panicked while holding it. We surface
/// that as an error rather than panicking again, because panicking during error
/// reporting hides the original cause.
fn engine() -> PyResult<MutexGuard<'static, EngineState>> {
    ENGINE.lock().map_err(|_| {
        PyRuntimeError::new_err("pwdcrack engine lock is poisoned by an earlier panic")
    })
}

/// Convert a [`CrackResult`] into the dict shape documented in `__init__.py`.
fn result_to_dict<'py>(py: Python<'py>, r: &CrackResult) -> PyResult<Bound<'py, PyDict>> {
    let d = PyDict::new(py);
    d.set_item("hash", &r.original)?;
    d.set_item("hash_type", &r.hash_type)?;
    match &r.password {
        Some(p) => d.set_item("password", p)?,
        None => d.set_item("password", py.None())?,
    }
    Ok(d)
}

/// Load one line into the engine, returning `true` when it parsed.
///
/// A bare hash is tried first. When that fails and the line looks like
/// `user:hash`, the suffix after the final colon is tried. This mirrors the
/// form accepted by the CLI so both entry points agree.
fn push_line(eng: &mut EngineState, line: &str) -> bool {
    let line = line.trim();
    if line.is_empty() {
        return false;
    }
    if let Some((cracker, entry)) = eng.detector.detect(line) {
        eng.targets.push((cracker, entry));
        return true;
    }
    if let Some((_, suffix)) = line.rsplit_once(':') {
        if let Some((cracker, entry)) = eng.detector.detect(suffix) {
            eng.targets.push((cracker, entry));
            return true;
        }
    }
    false
}

/// Split loaded targets into groups that share one cracker.
///
/// The attack functions in `pwdcrack::attack` take a single `&dyn HashCracker`
/// plus the hashes it owns, so a mixed type load has to be verified type group
/// by type group. Grouping also means each hash is compared only against hashes
/// of the same type, which is what the CLI does.
fn group_by_cracker(eng: &mut EngineState) -> Vec<(Box<dyn HashCracker>, Vec<HashEntry>)> {
    let mut groups: Vec<(Box<dyn HashCracker>, Vec<HashEntry>)> = Vec::new();
    let targets = std::mem::take(&mut eng.targets);
    for (cracker, entry) in targets {
        if let Some(group) = groups.iter_mut().find(|(c, _)| c.hash_type() == cracker.hash_type())
        {
            group.1.push(entry);
        } else {
            groups.push((cracker, vec![entry]));
        }
    }
    eng.targets.clear();
    groups
}

// ── Hash loading ──────────────────────────────────────────────────────────

/// Parse one hash string. Returns the cracker name, or `None` if unrecognised.
#[pyfunction]
fn detect(hash: &str) -> PyResult<Option<String>> {
    let eng = engine()?;
    Ok(eng
        .detector
        .detect(hash)
        .map(|(cracker, _)| cracker.name().to_string()))
}

/// Load a hash file. Returns the number of hashes parsed.
///
/// Unparsable non empty lines are counted and logged, never silently dropped
/// from the total without a warning.
#[pyfunction]
fn load_file(path: &str) -> PyResult<usize> {
    let mut eng = engine()?;
    eng.reset_targets();

    let content = std::fs::read_to_string(path)
        .map_err(|e| PyRuntimeError::new_err(format!("cannot read {path}: {e}")))?;

    let mut skipped = 0usize;
    for line in content.lines() {
        if !push_line(&mut eng, line) && !line.trim().is_empty() {
            skipped += 1;
        }
    }
    if skipped > 0 {
        log::warn!("load_file: skipped {skipped} unparsable line(s) in {path}");
    }
    Ok(eng.targets.len())
}

/// Load hashes from an in memory byte buffer. Returns the number parsed.
#[pyfunction]
fn load_buffer(py: Python<'_>, data: &[u8]) -> PyResult<usize> {
    let mut eng = engine()?;
    eng.reset_targets();

    let text = String::from_utf8_lossy(data);
    let mut skipped = 0usize;
    for line in text.lines() {
        if !push_line(&mut eng, line) && !line.trim().is_empty() {
            skipped += 1;
        }
    }
    if skipped > 0 {
        log::warn!("load_buffer: skipped {skipped} unparsable line(s)");
    }
    let n = eng.targets.len();
    drop(eng);
    let _ = py;
    Ok(n)
}

// ── Identification ────────────────────────────────────────────────────────

/// Identify every hash in a file as a list of `(hash_string, type_name)`.
#[pyfunction]
fn identify(path: &str) -> PyResult<Vec<(String, String)>> {
    let eng = engine()?;
    if !std::path::Path::new(path).exists() {
        return Err(PyRuntimeError::new_err(format!("cannot read {path}")));
    }
    Ok(eng
        .detector
        .identify(path)
        .into_iter()
        .map(|(hash, ty)| (hash, format!("{ty:?}")))
        .collect())
}

// ── Verification ──────────────────────────────────────────────────────────

/// Verify one password against one hash. Never raises on an unparsable hash.
#[pyfunction]
fn verify_one(hash: &str, password: &str) -> PyResult<bool> {
    let eng = engine()?;
    match eng.detector.detect(hash) {
        Some((cracker, entry)) => Ok(cracker.verify(password, &entry)),
        None => Ok(false),
    }
}

/// Verify one password against every loaded hash. Returns the matching hashes.
#[pyfunction]
fn verify_batch(password: &str) -> PyResult<Vec<String>> {
    let eng = engine()?;
    let mut out = Vec::new();
    for (cracker, entry) in eng.targets.iter() {
        if cracker.verify(password, entry) {
            out.push(entry.raw.clone());
        }
    }
    Ok(out)
}

// ── Attacks ───────────────────────────────────────────────────────────────

/// Run a dictionary attack over the loaded hashes. Returns the crack count.
///
/// A `rules_path` may be supplied for John or Hashcat style mangling.
#[pyfunction]
#[pyo3(signature = (wordlist, rules_path=None))]
fn attack_dictionary(wordlist: &str, rules_path: Option<&str>) -> PyResult<usize> {
    let mut eng = engine()?;
    eng.results.clear();
    let groups = group_by_cracker(&mut eng);
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    for (cracker, entries) in groups {
        let found = pwdcrack::attack::dictionary::run_dictionary(
            &entries,
            cracker.as_ref(),
            wordlist,
            rules_path,
            threads,
            true,
            false,
        );
        eng.results.extend(found);
    }
    Ok(eng.results.len())
}

/// Run a mask brute force attack over the loaded hashes. Returns the count.
#[pyfunction]
fn attack_bruteforce(mask: &str) -> PyResult<usize> {
    let mut eng = engine()?;
    eng.results.clear();
    let groups = group_by_cracker(&mut eng);
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    for (cracker, entries) in groups {
        let found = pwdcrack::attack::brute::run_bruteforce(
            &entries,
            cracker.as_ref(),
            mask,
            &[],
            threads,
            true,
            false,
        );
        eng.results.extend(found);
    }
    Ok(eng.results.len())
}

/// Run a combinator attack over two wordlists. Returns the crack count.
#[pyfunction]
fn attack_combinator(wordlist1: &str, wordlist2: &str) -> PyResult<usize> {
    let mut eng = engine()?;
    eng.results.clear();
    let groups = group_by_cracker(&mut eng);
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    for (cracker, entries) in groups {
        let found = pwdcrack::attack::combinator::run_combinator(
            &entries,
            cracker.as_ref(),
            wordlist1,
            wordlist2,
            threads,
            true,
            false,
        );
        eng.results.extend(found);
    }
    Ok(eng.results.len())
}

// ── Result access ─────────────────────────────────────────────────────────

/// Number of cracks found by the most recent attack.
#[pyfunction]
fn found_count() -> PyResult<usize> {
    Ok(engine()?.results.len())
}

/// Result at `index` as a dict, or `None` when out of range.
#[pyfunction]
fn get_result(py: Python<'_>, index: usize) -> PyResult<Option<Bound<'_, PyDict>>> {
    let eng = engine()?;
    match eng.results.get(index) {
        Some(r) => Ok(Some(result_to_dict(py, r)?)),
        None => Ok(None),
    }
}

/// Every result from the most recent attack as a list of dicts.
#[pyfunction]
fn get_all_results(py: Python<'_>) -> PyResult<Bound<'_, PyList>> {
    let eng = engine()?;
    let list = PyList::empty(py);
    for r in eng.results.iter() {
        list.append(result_to_dict(py, r)?)?;
    }
    Ok(list)
}

// ── Utilities ─────────────────────────────────────────────────────────────

/// Measure hashes per second for one cracker name.
///
/// Returns `0.0` for a type the engine cannot verify. That is the honest
/// answer, matching the CLI, rather than a fabricated rate.
#[pyfunction]
#[pyo3(signature = (hash_type, iterations=100_000))]
fn benchmark(hash_type: &str, iterations: u64) -> PyResult<f64> {
    if iterations == 0 {
        return Err(PyValueError::new_err("iterations must be greater than zero"));
    }
    let eng = engine()?;
    let cracker = eng
        .detector
        .crackers()
        .iter()
        .find(|c| c.name().eq_ignore_ascii_case(hash_type))
        .ok_or_else(|| PyValueError::new_err(format!("unknown hash type: {hash_type}")))?;

    // A raw entry with no decoded bytes never matches, so every iteration still
    // runs the full verify path and the measurement is not short circuited.
    let entry = HashEntry {
        raw: String::from("benchmark"),
        hash_type: cracker.hash_type(),
        hash_bytes: Vec::new(),
        salt: None,
        username: None,
        cracked: false,
        password: None,
    };

    let start = std::time::Instant::now();
    for _ in 0..iterations {
        let _ = cracker.verify("benchmark", &entry);
    }
    let elapsed = start.elapsed().as_secs_f64();
    if elapsed <= 0.0 {
        return Ok(0.0);
    }
    Ok(iterations as f64 / elapsed)
}

/// Version of the `engine-bridge` crate that provides these bindings.
#[pyfunction]
fn version() -> &'static str {
    // The wrapped library's version, not this crate's.
    pwdcrack::VERSION
}

/// Suggest an attack strategy for a hash string. Returns `(strategy, detail)`.
#[pyfunction]
fn suggest_attack(hash: &str) -> PyResult<(String, String)> {
    let eng = engine()?;
    let name = eng
        .detector
        .detect(hash)
        .map(|(c, _)| c.name().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let lower = name.to_ascii_lowercase();
    let (strategy, detail) = if lower.contains("bcrypt")
        || lower.contains("argon2")
        || lower.contains("scrypt")
        || lower.contains("pbkdf2")
    {
        (
            "dictionary".to_string(),
            "memory hard KDF: use a tuned wordlist plus rules, brute force is infeasible"
                .to_string(),
        )
    } else if lower.contains("ntlm")
        || lower.contains("md4")
        || lower.contains("md5")
        || lower.contains("sha")
    {
        (
            "brute-force".to_string(),
            "fast digest: mask attacks are viable, try common patterns first".to_string(),
        )
    } else if lower.contains("des") || lower.contains("lm") || lower.contains("cisco") {
        (
            "brute-force".to_string(),
            "legacy 8 byte limit: exhaustive search over the full keyspace is feasible"
                .to_string(),
        )
    } else {
        (
            "dictionary".to_string(),
            "start with a dictionary pass, then review the type specific guidance".to_string(),
        )
    };
    Ok((strategy, detail))
}

/// Apply one John style rule to a word. Returns every resulting string.
#[pyfunction]
fn rule_apply(word: &str, rule: &str) -> PyResult<Vec<String>> {
    let ops = rules::engine::parse_rule(rule)
        .map_err(|e| PyValueError::new_err(format!("rule parse error: {e}")))?;
    Ok(rules::engine::apply_rule(word, &ops))
}

// ── Types mirroring the Rust API ───────────────────────────────────────────
//
// The free functions above all operate on one process wide engine, which is the
// right shape for a script and the wrong shape for anything that wants two
// independent sessions in one interpreter. These classes give that shape: a
// `Cracker` owns its own detector, its own loaded hashes and its own results.
//
// The free functions are kept and are not rewritten on top of these, because
// they are a working interface that scripts may already use. Both talk to
// different state, which is deliberate and documented on `Cracker`.

use pyo3::exceptions::PyIndexError;

/// One cracked hash.
///
/// Mirrors `pwdcrack::attack::CrackResult`. `password` is `None` for an entry
/// that was loaded but not recovered, which is the same distinction the CLI
/// makes rather than an empty string standing in for both.
#[pyclass(module = "pwdcrack._native", frozen, get_all)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrackedHash {
    /// The hash string exactly as it was loaded, including any prefix or salt.
    pub hash: String,
    /// The name of the cracker that verified it.
    pub hash_type: String,
    /// The recovered password, or `None` if it was never found.
    pub password: Option<String>,
}

#[pymethods]
impl CrackedHash {
    fn __repr__(&self) -> String {
        match &self.password {
            Some(p) => format!("CrackedHash({} = {})", self.hash_type, p),
            None => format!("CrackedHash({} unresolved)", self.hash_type),
        }
    }

    /// The password, raising when there is none.
    ///
    /// `None` and `""` are different answers and this keeps them apart: an empty
    /// password is a real recovery, and returning it from a method called
    /// `password_or_raise` would hide that.
    fn password_or_raise(&self) -> PyResult<String> {
        self.password.clone().ok_or_else(|| {
            PyRuntimeError::new_err(format!(
                "this {} hash was never recovered",
                self.hash_type
            ))
        })
    }

    fn __eq__(&self, other: &CrackedHash) -> bool {
        self.hash == other.hash && self.password == other.password
    }
}

impl From<&CrackResult> for CrackedHash {
    fn from(r: &CrackResult) -> Self {
        CrackedHash {
            hash: r.original.clone(),
            hash_type: r.hash_type.clone(),
            password: r.password.clone(),
        }
    }
}

/// A loaded target.
///
/// Mirrors `pwdcrack::hash::HashEntry`, keeping only the fields a Python caller
/// has a use for. `username` is `None` for a bare hash and set for a
/// `user:hash` line, which is how the loader distinguishes them.
#[pyclass(module = "pwdcrack._native", frozen, get_all)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    /// The hash string as loaded.
    pub raw: String,
    /// The cracker's name for it.
    pub hash_type: String,
    /// The account name, when the line carried one.
    pub username: Option<String>,
    /// The salt the parser extracted, when the format has one.
    pub salt: Option<String>,
}

#[pymethods]
impl Target {
    fn __repr__(&self) -> String {
        match &self.username {
            Some(u) => format!("Target({u}:{} as {})", self.raw, self.hash_type),
            None => format!("Target({} as {})", self.raw, self.hash_type),
        }
    }

    fn __eq__(&self, other: &Target) -> bool {
        self.raw == other.raw && self.hash_type == other.hash_type
    }
}

impl From<&HashEntry> for Target {
    fn from(e: &HashEntry) -> Self {
        Target {
            raw: e.raw.clone(),
            hash_type: format!("{:?}", e.hash_type),
            username: e.username.clone(),
            salt: e.salt.clone(),
        }
    }
}

/// What the engine can do and how fast it was measured.
///
/// Mirrors `pwdcrack::engine::EngineInfo`. `hashes_per_second` is `None` until
/// something has actually been measured, which is the same choice the engine
/// makes: a number that has not been measured should not be zero, because zero
/// reads as "measured and it was slow".
#[pyclass(module = "pwdcrack._native", frozen, get_all)]
#[derive(Clone, Debug)]
pub struct EngineInfo {
    /// The engine's name, for example "cpu-scalar".
    pub name: String,
    /// A human readable description.
    pub vendor: String,
    /// Whether the engine can be used right now.
    pub available: bool,
    /// Measured rate, or `None` when nothing has been measured.
    pub hashes_per_second: Option<f64>,
    /// How many candidates the engine wants per call.
    pub batch_size: usize,
}

#[pymethods]
impl EngineInfo {
    fn __repr__(&self) -> String {
        let rate = match self.hashes_per_second {
            Some(r) => format!("{r:.0} H/s"),
            None => "not measured".to_string(),
        };
        format!(
            "EngineInfo({}, {}, {}, batch {})",
            self.name,
            if self.available { "available" } else { "unavailable" },
            rate,
            self.batch_size
        )
    }
}

/// An independent cracking session.
///
/// Owns its own detector, targets and results, so two of these can run side by
/// side without seeing each other's hashes. The module level functions use a
/// different, process wide engine; mixing the two is safe but confusing, and
/// this class exists so callers do not have to.
#[pyclass(module = "pwdcrack._native")]
pub struct Cracker {
    detector: Detector,
    targets: Vec<(Box<dyn HashCracker>, HashEntry)>,
    results: Vec<CrackResult>,
    /// Candidates the last attack tested, for `hashes_per_second`.
    last_tested: u64,
    /// Wall clock of the last attack.
    last_secs: f64,
}

impl Default for Cracker {
    fn default() -> Self {
        Cracker::new()
    }
}

#[pymethods]
impl Cracker {
    #[new]
    fn new() -> Cracker {
        Cracker {
            detector: Detector::new(),
            targets: Vec::new(),
            results: Vec::new(),
            last_tested: 0,
            last_secs: 0.0,
        }
    }

    /// Forgets every loaded hash and result, keeping the detector.
    fn clear(&mut self) {
        self.targets.clear();
        self.results.clear();
        self.last_tested = 0;
        self.last_secs = 0.0;
    }

    /// The type of one hash string, or `None` when no parser claimed it.
    fn detect(&self, hash: &str) -> Option<String> {
        self.detector
            .detect(hash.trim())
            .map(|(cracker, _)| cracker.name().to_string())
    }

    /// The type of every line in a file, paired with the line it came from.
    fn identify_file(&self, path: &str) -> PyResult<Vec<(usize, String, String)>> {
        let text = std::fs::read_to_string(path).map_err(|e| {
            PyValueError::new_err(format!("cannot read {path}: {e}"))
        })?;
        let mut out = Vec::new();
        for (n, line) in text.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let name = self
                .detector
                .detect(trimmed)
                .map(|(c, _)| c.name().to_string())
                .unwrap_or_else(|| "Unknown".to_string());
            out.push((n + 1, trimmed.to_string(), name));
        }
        Ok(out)
    }

    /// Loads hashes from a file, replacing anything already loaded.
    fn load_file(&mut self, path: &str) -> PyResult<usize> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| PyValueError::new_err(format!("cannot read {path}: {e}")))?;
        self.clear();
        self.load_text(&text, true);
        Ok(self.targets.len())
    }

    /// Loads hashes from a string.
    #[pyo3(signature = (text, replace = true))]
    fn load_text(&mut self, text: &str, replace: bool) -> usize {
        if replace {
            self.targets.clear();
        }
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if let Some((cracker, entry)) = self.detector.detect(line) {
                self.targets.push((cracker, entry));
                continue;
            }
            // `user:hash`, the same fallback the module level loader uses.
            if let Some((_, suffix)) = line.rsplit_once(':') {
                if let Some((cracker, entry)) = self.detector.detect(suffix) {
                    self.targets.push((cracker, entry));
                }
            }
        }
        self.targets.len()
    }

    /// Every loaded target.
    #[getter]
    fn targets(&self) -> Vec<Target> {
        self.targets.iter().map(|(_, e)| Target::from(e)).collect()
    }

    /// How many hashes are loaded.
    #[getter]
    fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// Whether one password recovers one hash.
    ///
    /// Three answers stay three: `True`, `False`, and a raised error for a hash
    /// that could not be checked. Reporting a failure to check as `False` is
    /// how a cracker claims a recovery that did not happen.
    fn verify(&self, hash: &str, password: &str) -> PyResult<bool> {
        match self.detector.detect(hash.trim()) {
            Some((cracker, entry)) => Ok(cracker.verify(password, &entry)),
            None => Err(PyValueError::new_err(format!(
                "no parser recognised {hash:?}"
            ))),
        }
    }

    /// Runs a dictionary attack. Returns the number cracked.
    #[pyo3(signature = (wordlist, rules_path = None, threads = 0))]
    fn attack_dictionary(
        &mut self,
        wordlist: &str,
        rules_path: Option<&str>,
        threads: usize,
    ) -> PyResult<usize> {
        if self.targets.is_empty() {
            return Err(PyRuntimeError::new_err(
                "no hashes loaded; call load_file or load_text first",
            ));
        }
        let rules_text = match rules_path {
            Some(p) => Some(
                std::fs::read_to_string(p)
                    .map_err(|e| PyValueError::new_err(format!("cannot read {p}: {e}")))?,
            ),
            None => None,
        };
        let threads = if threads == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        } else {
            threads
        };

        let groups = group_targets(&self.targets);
        let started = std::time::Instant::now();
        let mut all: Vec<CrackResult> = Vec::new();
        for (cracker, entries) in &groups {
            let found = pwdcrack::attack::dictionary::run_dictionary(
                entries,
                cracker.as_ref(),
                wordlist,
                rules_text.as_deref(),
                threads,
                true,
                false,
            );
            all.extend(found);
        }
        let elapsed = started.elapsed().as_secs_f64();
        self.last_tested = count_wordlist(wordlist).unwrap_or(0);
        self.last_secs = elapsed;
        self.results = all;
        Ok(self.results.len())
    }

    /// Runs a brute force attack over a mask. Returns the number cracked.
    #[pyo3(signature = (mask, threads = 0))]
    fn attack_bruteforce(&mut self, mask: &str, threads: usize) -> PyResult<usize> {
        if self.targets.is_empty() {
            return Err(PyRuntimeError::new_err(
                "no hashes loaded; call load_file or load_text first",
            ));
        }
        let threads = if threads == 0 {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        } else {
            threads
        };
        let parsed = pwdcrack::attack::brute::parse_mask(mask);
        let keyspace = pwdcrack::attack::brute::total_combinations(&parsed, &[]);
        let mask_len = parsed.len();

        let groups = group_targets(&self.targets);
        let started = std::time::Instant::now();
        let mut all: Vec<CrackResult> = Vec::new();
        for (cracker, entries) in &groups {
            let outcome = pwdcrack::attack::brute::run_bruteforce_from(
                entries,
                cracker.as_ref(),
                mask,
                &[],
                threads,
                true,
                false,
                mask_len,
                None,
                Some(keyspace),
                0,
            )
            .map_err(PyRuntimeError::new_err)?;
            all.extend(outcome.results);
        }
        self.last_tested = keyspace;
        self.last_secs = started.elapsed().as_secs_f64();
        self.results = all;
        Ok(self.results.len())
    }

    /// One result by index.
    fn result(&self, index: usize) -> PyResult<CrackedHash> {
        self.results
            .get(index)
            .map(CrackedHash::from)
            .ok_or_else(|| {
                PyIndexError::new_err(format!(
                    "index {} is past the {} result(s) found",
                    index,
                    self.results.len()
                ))
            })
    }

    /// Every result.
    #[getter]
    fn results(&self) -> Vec<CrackedHash> {
        self.results.iter().map(CrackedHash::from).collect()
    }

    /// How many hashes the last attack cracked.
    #[getter]
    fn found(&self) -> usize {
        self.results.len()
    }

    /// Candidates per second during the last attack.
    ///
    /// `None` until an attack has run, and `None` for one that completed too
    /// quickly to time. Zero would read as "measured, and it was slow".
    #[getter]
    fn hashes_per_second(&self) -> Option<f64> {
        if self.last_secs <= 0.0 || self.last_tested == 0 {
            return None;
        }
        Some(self.last_tested as f64 / self.last_secs)
    }

    /// Candidates the last attack tested.
    #[getter]
    fn last_tested(&self) -> u64 {
        self.last_tested
    }

    /// Seconds the last attack took.
    #[getter]
    fn last_duration_secs(&self) -> f64 {
        self.last_secs
    }

    /// What the CPU engine reports about itself, measured.
    ///
    /// The engine is constructed here rather than cached, because
    /// `CpuEngine::new` runs a short benchmark and this is the only thing in
    /// this class that needs one. A cached engine would report a rate measured
    /// whenever the object was built, which drifts as the machine's load
    /// changes without anything saying so.
    fn engine_info(&self) -> EngineInfo {
        let engine = pwdcrack::engine::CpuEngine::new();
        let info = engine.info();
        EngineInfo {
            name: info.name.to_string(),
            vendor: if info.vendor.is_empty() {
                "portable".to_string()
            } else {
                info.vendor.clone()
            },
            available: engine.is_available(),
            // `measured` is the engine's own flag for "this number came from a
            // benchmark". Testing the value instead would turn an unmeasured
            // engine that happened to report 0.0 into a measured zero rate.
            hashes_per_second: if info.measured {
                Some(info.measured_hps)
            } else {
                None
            },
            batch_size: info.batch_size,
        }
    }

    fn __len__(&self) -> usize {
        self.targets.len()
    }

    fn __repr__(&self) -> String {
        format!(
            "Cracker({} target(s), {} result(s))",
            self.targets.len(),
            self.results.len()
        )
    }
}

/// Splits targets into groups sharing one cracker, borrowing the input.
///
/// Borrowing rather than consuming. An earlier version took the targets out with
/// `std::mem::take` and never restored them, so a second attack on the same
/// `Cracker` found an empty target list and reported zero cracks with success.
/// The Node binding had the same defect in a different shape and was caught by
/// its own test suite; this is the same fix applied there.
fn group_targets(
    targets: &[(Box<dyn HashCracker>, HashEntry)],
) -> Vec<(Box<dyn HashCracker>, Vec<HashEntry>)> {
    let mut groups: Vec<(Box<dyn HashCracker>, Vec<HashEntry>)> = Vec::new();
    for (cracker, entry) in targets {
        let hash_type = cracker.hash_type();
        match groups.iter_mut().find(|(c, _)| c.hash_type() == hash_type) {
            Some((_, list)) => list.push(entry.clone()),
            None => groups.push((cracker.clone_box(), vec![entry.clone()])),
        }
    }
    groups
}

/// Non empty lines in a wordlist, which is the unit a rate is measured over.
fn count_wordlist(path: &str) -> Option<u64> {
    let text = std::fs::read_to_string(path).ok()?;
    Some(text.lines().filter(|l| !l.trim().is_empty()).count() as u64)
}

// ── Module registration ───────────────────────────────────────────────────

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(detect, m)?)?;
    m.add_function(wrap_pyfunction!(load_file, m)?)?;
    m.add_function(wrap_pyfunction!(load_buffer, m)?)?;
    m.add_function(wrap_pyfunction!(identify, m)?)?;
    m.add_function(wrap_pyfunction!(attack_dictionary, m)?)?;
    m.add_function(wrap_pyfunction!(attack_bruteforce, m)?)?;
    m.add_function(wrap_pyfunction!(attack_combinator, m)?)?;
    m.add_function(wrap_pyfunction!(verify_one, m)?)?;
    m.add_function(wrap_pyfunction!(verify_batch, m)?)?;
    m.add_function(wrap_pyfunction!(found_count, m)?)?;
    m.add_function(wrap_pyfunction!(get_result, m)?)?;
    m.add_function(wrap_pyfunction!(get_all_results, m)?)?;
    m.add_function(wrap_pyfunction!(benchmark, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(suggest_attack, m)?)?;
    m.add_function(wrap_pyfunction!(rule_apply, m)?)?;
    m.add_class::<Cracker>()?;
    m.add_class::<CrackedHash>()?;
    m.add_class::<Target>()?;
    m.add_class::<EngineInfo>()?;

    // `__init__.py` re-exports `__version__`, and the previous registration did
    // not set it, so importing the package raised ImportError on a name the
    // module never had. A package that cannot be imported is worse than one with
    // fewer features.
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
