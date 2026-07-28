//! Python bindings via PyO3 — `import pwdcrack`
//!
//! Build with maturin: `cd engines/engine-bridge && maturin develop`
//! Or with pip: `pip install engines/engine-bridge/python/`

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::Mutex;

use pwdcrack::hash::{HashCracker, HashEntry};
use pwdcrack::hash::detector::Detector;
use pwdcrack::attack::CrackResult;
use pwdcrack::potfile::Potfile;

// ── Thread-safe engine state ─────────────────────────────────

struct PyEngine {
    detector: Detector,
    hashes: Vec<(Box<dyn HashCracker>, HashEntry)>,
    results: Vec<CrackResult>,
}

impl PyEngine {
    fn new() -> Self {
        PyEngine {
            detector: Detector::new(),
            hashes: Vec::new(),
            results: Vec::new(),
        }
    }
}

use std::sync::LazyLock;
/// Global engine instance.
///
/// **Note:** `PY_ENGINE.lock()` is held for the **entire duration** of
/// `attack_dictionary` and `attack_bruteforce`, which can run for hours.
/// No other concurrent call that needs `PY_ENGINE` will be able to proceed.
static PY_ENGINE: LazyLock<Mutex<PyEngine>> =
    LazyLock::new(|| Mutex::new(PyEngine::new()));

// ── Python Module ────────────────────────────────────────────

/// pwdcrack — Python bindings to the Rust core engine.
#[pymodule]
fn _native(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(detect, m)?)?;
    m.add_function(wrap_pyfunction!(load_file, m)?)?;
    m.add_function(wrap_pyfunction!(load_buffer, m)?)?;
    m.add_function(wrap_pyfunction!(identify, m)?)?;
    m.add_function(wrap_pyfunction!(attack_dictionary, m)?)?;
    m.add_function(wrap_pyfunction!(attack_bruteforce, m)?)?;
    m.add_function(wrap_pyfunction!(verify_one, m)?)?;
    m.add_function(wrap_pyfunction!(found_count, m)?)?;
    m.add_function(wrap_pyfunction!(get_result, m)?)?;
    m.add_function(wrap_pyfunction!(benchmark, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    Ok(())
}

// ── Public API functions ─────────────────────────────────────

/// Auto-detect hardware and return tier info string.
#[pyfunction]
fn detect() -> String {
    format!("pwdcrack v{} — Rust core", env!("CARGO_PKG_VERSION"))
}

/// Load hashes from a file path.
/// Returns the number of hashes loaded.
#[pyfunction]
fn load_file(path: &str) -> PyResult<i32> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return Err(PyErr::new::<pyo3::exceptions::PyIOError, _>(e.to_string())),
    };

    let mut engine = PY_ENGINE.lock().unwrap();
    engine.hashes.clear();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((cracker, entry)) = engine.detector.detect(trimmed) {
            engine.hashes.push((cracker, entry));
        }
    }

    Ok(engine.hashes.len() as i32)
}

/// Load a single hash from a string.
/// Returns the hash index (≥0) or raises ValueError.
#[pyfunction]
fn load_buffer(hash_str: &str) -> PyResult<i32> {
    let mut engine = PY_ENGINE.lock().unwrap();
    match engine.detector.detect(hash_str) {
        Some((cracker, entry)) => {
            let id = engine.hashes.len();
            engine.hashes.push((cracker, entry));
            Ok(id as i32)
        }
        None => Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Unknown hash format: {}", hash_str),
        )),
    }
}

/// Identify hash types in a file.
/// Returns list of (hash, hash_type_name) tuples.
#[pyfunction]
fn identify(path: &str) -> PyResult<Vec<(String, String)>> {
    let detector = Detector::new();
    let results = detector.identify(path);
    Ok(results
        .into_iter()
        .map(|(h, t)| (h, t.name().to_string()))
        .collect())
}

/// Run dictionary attack.
///
/// **Note:** The internal `PY_ENGINE` lock is held for the **entire duration** of this
/// call, which may be hours long. No other concurrent call that needs `PY_ENGINE`
/// will be able to proceed.
///
/// wordlist: path to wordlist file.
/// rules: optional rule string (empty = no rules).
/// quiet: suppress progress output (default true).
/// Returns list of (hash, password) tuples for cracked passwords.
#[pyfunction]
fn attack_dictionary(
    wordlist: &str,
    rules: Option<&str>,
    quiet: Option<bool>,
) -> PyResult<Vec<(String, String)>> {
    let engine = PY_ENGINE.lock().unwrap();
    if engine.hashes.is_empty() {
        return Ok(Vec::new());
    }

    let mut hashes: Vec<HashEntry> = engine.hashes.iter().map(|(_, e)| e.clone()).collect();
    let cracker = &engine.hashes[0].0;

    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let results = pwdcrack::attack::dictionary::run_dictionary(
        &mut hashes,
        cracker.as_ref(),
        wordlist,
        rules,
        threads,
        quiet.unwrap_or(true),
    );

    let cracked: Vec<(String, String)> = results
        .into_iter()
        .filter_map(|r| r.password.map(|p| (r.original, p)))
        .collect();

    let mut engine = PY_ENGINE.lock().unwrap();
    engine.results = results;

    Ok(cracked)
}

/// Run brute-force attack.
///
/// **Note:** The internal `PY_ENGINE` lock is held for the **entire duration** of this
/// call, which may be hours long. No other concurrent call that needs `PY_ENGINE`
/// will be able to proceed.
///
/// mask: pattern (e.g., "?l?l?d?d").
/// Returns list of (hash, password) tuples.
#[pyfunction]
fn attack_bruteforce(mask: &str, quiet: Option<bool>) -> PyResult<Vec<(String, String)>> {
    let engine = PY_ENGINE.lock().unwrap();
    if engine.hashes.is_empty() {
        return Ok(Vec::new());
    }

    let mut hashes: Vec<HashEntry> = engine.hashes.iter().map(|(_, e)| e.clone()).collect();
    let cracker = &engine.hashes[0].0;

    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let results = pwdcrack::attack::brute::run_bruteforce(
        &mut hashes,
        cracker.as_ref(),
        mask,
        &[None, None, None, None],
        threads,
        quiet.unwrap_or(true),
    );

    let cracked: Vec<(String, String)> = results
        .into_iter()
        .filter_map(|r| r.password.map(|p| (r.original, p)))
        .collect();

    let mut engine = PY_ENGINE.lock().unwrap();
    engine.results = results;

    Ok(cracked)
}

/// Verify a single password against a hash.
/// Returns True if the password matches.
#[pyfunction]
fn verify_one(password: &str, hash_str: &str) -> bool {
    let detector = Detector::new();
    match detector.detect(hash_str) {
        Some((cracker, entry)) => cracker.verify(password, &entry),
        None => false,
    }
}

/// Number of cracked passwords from last attack.
#[pyfunction]
fn found_count() -> i32 {
    PY_ENGINE.lock().unwrap().results.len() as i32
}

/// Get Nth cracked result. Returns (hash, password, hash_type).
#[pyfunction]
fn get_result(idx: usize) -> Option<(String, String, String)> {
    let engine = PY_ENGINE.lock().unwrap();
    let r = engine.results.get(idx)?;
    r.password.as_ref().map(|pw| {
        (
            r.original.clone(),
            pw.clone(),
            r.hash_type.clone(),
        )
    })
}

/// Benchmark a hash type. Returns (name, hashes_per_second).
#[pyfunction]
fn benchmark(hash_type: &str) -> PyResult<Vec<(String, f64)>> {
    use std::time::Instant;

    let detector = Detector::new();
    let crackers: Vec<&dyn HashCracker> = if hash_type == "all" {
        detector.crackers().iter().map(|b| b.as_ref()).collect()
    } else {
        let mut found = Vec::new();
        for c in detector.crackers().iter() {
            if c.name().to_lowercase().contains(&hash_type.to_lowercase()) {
                found.push(c.as_ref());
            }
        }
        found
    };

    if crackers.is_empty() {
        return Err(PyErr::new::<pyo3::exceptions::PyValueError, _>(
            format!("Unknown hash type: {}", hash_type),
        ));
    }

    let test_pass = "benchmark_test_password123!";
    let mut results = Vec::new();

    for cracker in &crackers {
        let test_hash = match cracker.hash_type() {
            pwdcrack::hash::HashType::MD5 => {
                let mut h = md5::Md5::new();
                h.update(test_pass.as_bytes());
                hex::encode(h.finalize())
            }
            pwdcrack::hash::HashType::NTLM => {
                use md4::Digest;
                let utf16: Vec<u8> = test_pass.encode_utf16()
                    .flat_map(|c| c.to_le_bytes())
                    .collect();
                let mut h = md4::Md4::new();
                h.update(&utf16);
                hex::encode(h.finalize())
            }
            _ => test_pass.to_string(),
        };

        let entry = HashEntry {
            raw: test_hash,
            hash_type: cracker.hash_type(),
            hash_bytes: Vec::new(),
            salt: None,
            username: None,
            cracked: false,
            password: None,
        };

        let iterations = 100_000u64;
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = cracker.verify(test_pass, &entry);
        }
        let elapsed = start.elapsed();
        let per_sec = iterations as f64 / elapsed.as_secs_f64();
        results.push((cracker.name().to_string(), per_sec));
    }

    Ok(results)
}

/// Get version string.
#[pyfunction]
fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
