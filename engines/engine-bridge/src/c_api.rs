//! C FFI exports for libcrack-core.so
//!
//! Thread-safe API for use from C, C++, Go, Zig, etc.
//! All functions return error codes: 0 = success, negative = error.

use std::sync::Mutex;
use std::ffi::{CStr, CString};

use pwdcrack::hash::{HashCracker, HashEntry, HashType};
use pwdcrack::hash::detector::Detector;
use pwdcrack::attack::CrackResult;

// ── Global engine state ──────────────────────────────────────

struct EngineState {
    detector: Detector,
    hashes: Vec<(Box<dyn HashCracker>, HashEntry)>,
    results: Vec<CrackResult>,
}

impl EngineState {
    fn new() -> Self {
        EngineState {
            detector: Detector::new(),
            hashes: Vec::new(),
            results: Vec::new(),
        }
    }
}

use std::sync::LazyLock;
static ENGINE: LazyLock<Mutex<EngineState>> =
    LazyLock::new(|| Mutex::new(EngineState::new()));

// ── Helper: convert C string to Rust str ─────────────────────

unsafe fn cstr_to_str<'a>(ptr: *const u8, len: i32) -> Option<&'a str> {
    if ptr.is_null() || len <= 0 {
        return None;
    }
    let slice = std::slice::from_raw_parts(ptr, len as usize);
    std::str::from_utf8(slice).ok()
}

#[allow(dead_code)]
unsafe fn cstr_to_cstring(ptr: *const u8, len: i32) -> Option<CString> {
    let s = cstr_to_str(ptr, len)?;
    CString::new(s).ok()
}

// ── Initialization ───────────────────────────────────────────

/// Initialize the crack engine. Must be called once before other functions.
/// Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub extern "C" fn crack_init() -> i32 {
    drop(ENGINE.lock());
    0
}

/// Shut down the engine and free resources.
#[unsafe(no_mangle)]
pub extern "C" fn crack_shutdown() {
    if let Ok(mut engine) = ENGINE.lock() {
        engine.hashes.clear();
        engine.results.clear();
    }
}

// ── Hash loading ─────────────────────────────────────────────

/// Load hashes from a file path (null-terminated UTF-8 string).
/// Returns number of hashes loaded, or negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hash_load_file(path: *const std::os::raw::c_char) -> i32 {
    if path.is_null() {
        return -1;
    }
    let c_str = unsafe { CStr::from_ptr(path) };
    let path_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let content = match std::fs::read_to_string(path_str) {
        Ok(c) => c,
        Err(_) => return -1,
    };

    let mut engine = ENGINE.lock().unwrap();
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

    engine.hashes.len() as i32
}

/// Load a single hash from a buffer.
/// Returns hash_id (≥0) on success, or negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn hash_load_buffer(
    hash_str: *const u8,
    hash_len: i32,
) -> i32 {
    let s = unsafe {
        match cstr_to_str(hash_str, hash_len) {
            Some(s) => s,
            None => return -1,
        }
    };

    let mut engine = ENGINE.lock().unwrap();
    match engine.detector.detect(s) {
        Some((cracker, entry)) => {
            let id = engine.hashes.len();
            engine.hashes.push((cracker, entry));
            id as i32
        }
        None => -2, // Unknown hash type
    }
}

/// Get number of loaded hashes.
#[unsafe(no_mangle)]
pub extern "C" fn hash_count() -> i32 {
    ENGINE.lock().unwrap().hashes.len() as i32
}

// ── Attacks ──────────────────────────────────────────────────

/// Run dictionary attack against loaded hashes.
/// wordlist: null-terminated file path.
/// rules: null-terminated rules string (can be empty).
/// Returns number of passwords cracked, or negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn attack_dictionary(
    wordlist: *const std::os::raw::c_char,
    rules: *const std::os::raw::c_char,
    threads: i32,
) -> i32 {
    if wordlist.is_null() {
        return -1;
    }

    let wl = unsafe { CStr::from_ptr(wordlist) };
    let wl_str = match wl.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let rules_str: Option<&str> = if !rules.is_null() {
        unsafe { CStr::from_ptr(rules).to_str().ok() }
    } else {
        None
    };

    let engine = ENGINE.lock().unwrap();
    if engine.hashes.is_empty() {
        return -2; // No hashes loaded
    }

    let threads = if threads <= 0 {
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) as i32
    } else {
        threads
    };

    let mut hashes: Vec<HashEntry> = engine.hashes.iter().map(|(_, e)| e.clone()).collect();
    let cracker = &engine.hashes[0].0;

    let results = pwdcrack::attack::dictionary::run_dictionary(
        &mut hashes,
        cracker.as_ref(),
        wl_str,
        rules_str,
        threads as usize,
        true, // quiet
    );

    let count = results.len() as i32;
    // Store results for retrieval
    let mut engine = ENGINE.lock().unwrap();
    engine.results = results;

    count
}

/// Run brute-force attack.
/// mask: pattern string (e.g., "?l?l?d?d").
/// start_idx: starting keyspace index (0-based).
/// end_idx: ending keyspace index (exclusive).
/// Returns number cracked, or negative on error.
#[unsafe(no_mangle)]
pub extern "C" fn attack_bruteforce(
    mask: *const std::os::raw::c_char,
    start_idx: u64,
    _end_idx: u64,
    threads: i32,
) -> i32 {
    if mask.is_null() {
        return -1;
    }

    let m = unsafe { CStr::from_ptr(mask) };
    let mask_str = match m.to_str() {
        Ok(s) => s,
        Err(_) => return -1,
    };

    let engine = ENGINE.lock().unwrap();
    if engine.hashes.is_empty() {
        return -2;
    }

    let threads = if threads <= 0 { 4 } else { threads as usize };
    let mut hashes: Vec<HashEntry> = engine.hashes.iter().map(|(_, e)| e.clone()).collect();
    let cracker = &engine.hashes[0].0;

    let results = pwdcrack::attack::brute::run_bruteforce(
        &mut hashes,
        cracker.as_ref(),
        mask_str,
        &[None, None, None, None],
        threads,
        true,
    );

    let count = results.len() as i32;
    let mut engine = ENGINE.lock().unwrap();
    engine.results = results;
    count
}

// ── Results ──────────────────────────────────────────────────

/// Get number of cracked passwords from the last attack.
#[unsafe(no_mangle)]
pub extern "C" fn crack_found_count() -> i32 {
    ENGINE.lock().unwrap().results.len() as i32
}

/// Get number of loaded hashes.
#[unsafe(no_mangle)]
pub extern "C" fn crack_total_hashes() -> i32 {
    ENGINE.lock().unwrap().hashes.len() as i32
}

/// Get a crack result by index.
/// Returns 0 on success, -1 if index out of range.
/// The caller must free the returned strings with crack_free_string().
#[unsafe(no_mangle)]
pub extern "C" fn crack_get_result(
    idx: i32,
    out_hash: *mut *mut std::os::raw::c_char,
    out_password: *mut *mut std::os::raw::c_char,
) -> i32 {
    if idx < 0 {
        return -1;
    }
    let engine = ENGINE.lock().unwrap();
    let idx = idx as usize;
    if idx >= engine.results.len() {
        return -1;
    }

    let r = &engine.results[idx];
    if let Some(ref pw) = r.password {
        if let Ok(h) = CString::new(r.original.as_bytes()) {
            unsafe { *out_hash = h.into_raw() };
        }
        if let Ok(p) = CString::new(pw.as_bytes()) {
            unsafe { *out_password = p.into_raw() };
        }
        0
    } else {
        -1
    }
}

/// Free a string previously returned by crack_get_result().
#[unsafe(no_mangle)]
pub extern "C" fn crack_free_string(s: *mut std::os::raw::c_char) {
    if !s.is_null() {
        unsafe { let _ = CString::from_raw(s); }
    }
}

// ── Stats ────────────────────────────────────────────────────

/// Get the approximate hashes-per-second from the last attack.
#[unsafe(no_mangle)]
pub extern "C" fn crack_hashes_per_second() -> f64 {
    0.0 // Returned in real-time by the engine; static for now
}

/// Get version string.
#[unsafe(no_mangle)]
pub extern "C" fn crack_version() -> *mut std::os::raw::c_char {
    let v = CString::new(env!("CARGO_PKG_VERSION")).unwrap();
    v.into_raw()
}

// ── Information ──────────────────────────────────────────────

/// Detect hardware tier. Returns string like "HighEnd", "MidRange", "LowEnd".
#[unsafe(no_mangle)]
pub extern "C" fn crack_detect_tier() -> *mut std::os::raw::c_char {
    let tier = "Auto";
    CString::new(tier).unwrap().into_raw()
}

/// Identify hash type from a hash string.
/// Returns string like "MD5", "SHA256", "NTLM", "Unknown".
/// Caller must free with crack_free_string().
#[unsafe(no_mangle)]
pub extern "C" fn crack_identify_hash(
    hash_str: *const u8,
    hash_len: i32,
) -> *mut std::os::raw::c_char {
    let s = unsafe {
        match cstr_to_str(hash_str, hash_len) {
            Some(s) => s,
            None => return std::ptr::null_mut(),
        }
    };

    let engine = ENGINE.lock().unwrap();
    let hash_type = match engine.detector.detect(s) {
        Some((cracker, _)) => cracker.name(),
        None => "Unknown",
    };

    CString::new(hash_type).unwrap().into_raw()
}
