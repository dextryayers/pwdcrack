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
    env!("CARGO_PKG_VERSION")
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
    Ok(())
}
