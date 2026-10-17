//! The C API, driven through its real entry points.
//!
//! These are the tests P11.1.07 asks for, written in Rust because the harness
//! is already here. `tests/c/test_bridge.c` is the same coverage from the
//! caller's side; both are run by `cargo test -p engine-bridge`.
//!
//! # The deadlock this guards against
//!
//! `attack_dictionary` and `attack_bruteforce` used to take the global lock at
//! the top of the function and take it again at the bottom to store results,
//! with the first guard still in scope. `std::sync::Mutex` is not reentrant, so
//! both functions completed the attack and then hung forever.
//!
//! A test that merely calls the function would hang the suite rather than fail
//! it, which is a bad way to discover the bug. So every attack here runs on its
//! own thread with a deadline, and the assertion is that the thread finishes.

// This suite drives the C ABI directly, so it links against the static library.
//
// With the `node` feature enabled the crate also contains N-API entry points,
// whose symbols (`napi_register_module_v1` and friends) are provided by the Node
// runtime rather than by any library on this machine. Linking that into a plain
// test binary fails at link time with an unresolved symbol, which says nothing
// about the C ABI. The Node surface has its own tests, in src/node.rs and
// scripts/test-node-bridge.sh.
#![cfg(not(feature = "node"))]

use std::ffi::{c_char, CStr, CString};
use std::time::Duration;

use engine_bridge::c_api::*;
use engine_bridge::abi_version;

/// The C API has one global engine by design, so tests that call it cannot run
/// in parallel: one test's `crack_init` clears the hashes another is attacking.
///
/// Cargo runs the tests in this file as concurrent threads on purpose, so the
/// serialisation has to be explicit. A `Mutex` held for the whole test is the
/// simplest thing that cannot be forgotten by a new test, because taking it is
/// the first line of every one that touches the engine.
static ENGINE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Takes the engine lock, poisoning it rather than panicking.
///
/// A test that panicked while holding it would otherwise cascade into every other
/// test as a second, misleading failure.
fn engine() -> std::sync::MutexGuard<'static, ()> {
    ENGINE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Runs `f` on its own thread and fails if it has not returned by `limit`.
fn with_deadline<T: Send + 'static>(what: &str, limit: Duration, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(limit) {
        Ok(value) => {
            // Reap the thread so a finished worker does not linger.
            drop(handle);
            value
        }
        Err(_) => {
            panic!(
                "{what} did not return within {limit:?}. The global lock is taken \
                 twice in that function, which deadlocks a non reentrant Mutex."
            );
        }
    }
}

/// A wordlist holding the plaintext for the hash below.
///
/// 8350c7ecc6d4706e12107df747eb6e71 is MD5("pwdcrack-reference-candidate").
const TARGET: &str = "8350c7ecc6d4706e12107df747eb6e71";
const PLAINTEXT: &str = "pwdcrack-reference-candidate";

struct Fixtures {
    dir: std::path::PathBuf,
    wordlist: CString,
}

impl Fixtures {
    fn new(name: &str) -> Fixtures {
        let dir = std::env::temp_dir().join(format!("pwdcrack-ffi-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("words.txt");
        std::fs::write(&path, format!("{PLAINTEXT}\n")).expect("write wordlist");
        Fixtures {
            wordlist: CString::new(path.to_string_lossy().to_string()).expect("path"),
            dir,
        }
    }
}

impl Drop for Fixtures {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn load_target() -> i32 {
    let text = format!("{TARGET}\n");
    // SAFETY: the buffer outlives the call, which only reads it.
    unsafe { hash_load_buffer(text.as_ptr(), text.len() as i32) }
}

/// Every exported symbol is reachable and callable from the outside.
#[test]
fn every_exported_symbol_answers() {
    let _guard = engine();
    assert_eq!(crack_init(), CRACK_OK);
    assert_eq!(crack_abi_version(), engine_bridge::abi_version());
    assert!(!crack_version().is_null());
    assert!(!crack_version_owned().is_null());
    assert!(!crack_detect_tier().is_null());
    assert!(!crack_detect_tier_detail().is_null());
    assert!(matches!(crack_panics_abort(), 0 | 1));
    assert!(crack_hashes_per_second() >= 0.0);
    assert_eq!(crack_last_tested(), 0);
    assert_eq!(crack_last_duration_secs(), 0.0);
    assert_eq!(crack_found_count(), 0);
    assert_eq!(crack_total_hashes(), 0);
    // SAFETY: null is an explicitly handled input for this function.
    unsafe { crack_free_string(std::ptr::null_mut()) };
    crack_shutdown();
}

/// The property P11.1.07 names for `crack_get_result`: what it hands out can be
/// released, and a refused index writes nothing.
#[test]
fn the_memory_contract_of_crack_get_result_holds() {
    let _guard = engine();
    let fixtures = Fixtures::new("memory");
    assert_eq!(crack_init(), CRACK_OK);
    assert_eq!(load_target(), 1);
    // The worker thread owns its own copy of the path, so the Fixtures drop
    // cannot delete the wordlist while the attack is reading it.
    let wordlist = fixtures.wordlist.clone();
    assert_eq!(
        with_deadline("attack_dictionary", Duration::from_secs(30), move || unsafe {
            attack_dictionary(wordlist.as_ptr(), std::ptr::null(), 1)
        }),
        1,
        "the dictionary holds the plaintext"
    );
    assert_eq!(crack_found_count(), 1);

    // A real result: both strings come back and both are released.
    let mut hash: *mut c_char = std::ptr::null_mut();
    let mut password: *mut c_char = std::ptr::null_mut();
    // SAFETY: both out params are valid writable `char *`, and both returned
    // pointers are released below exactly once each.
    let code = unsafe { crack_get_result(0, &mut hash, &mut password) };
    assert_eq!(code, CRACK_OK);
    assert!(!hash.is_null());
    assert!(!password.is_null());
    // SAFETY: both pointers come from crack_get_result, which transfers ownership.
    let got_hash = unsafe { CStr::from_ptr(hash) }.to_str().expect("utf8").to_string();
    let got_password = unsafe { CStr::from_ptr(password) }.to_str().expect("utf8").to_string();
    // SAFETY: released exactly once each.
    unsafe {
        crack_free_string(hash);
        crack_free_string(password);
    }
    assert_eq!(got_hash, TARGET);
    assert_eq!(got_password, PLAINTEXT);
    assert_eq!(md5(&got_password), got_hash, "the pair must actually match");

    // Out of range: a refusal, and both out params left null so a caller that
    // ignores the code still cannot read freed or stale memory.
    let mut h2: *mut c_char = 1usize as *mut c_char;
    let mut p2: *mut c_char = 1usize as *mut c_char;
    // SAFETY: valid writable out params.
    assert_eq!(unsafe { crack_get_result(500, &mut h2, &mut p2) }, CRACK_E_INDEX);
    assert!(h2.is_null() && p2.is_null());

    crack_shutdown();
}

/// A dictionary attack has to finish. Before the lock fix it did the work and
/// then hung.
#[test]
fn a_dictionary_attack_completes_instead_of_hanging() {
    let _guard = engine();
    let fixtures = Fixtures::new("dict");
    crack_init();
    assert_eq!(load_target(), 1);
    let wordlist = fixtures.wordlist.clone();
    let cracked = with_deadline("attack_dictionary", Duration::from_secs(30), move || unsafe {
        attack_dictionary(wordlist.as_ptr(), std::ptr::null(), 2)
    });
    assert_eq!(cracked, 1);
    crack_shutdown();
}

/// The same for brute force, which had the identical double lock.
#[test]
fn a_bruteforce_attack_completes_instead_of_hanging() {
    let _guard = engine();
    crack_init();
    // A mask of literals, so the keyspace is one candidate and the run is short
    // whatever the machine.
    let mask = CString::new(PLAINTEXT).expect("mask");
    assert_eq!(load_target(), 1);
    let cracked = with_deadline("attack_bruteforce", Duration::from_secs(30), move || unsafe {
        attack_bruteforce(mask.as_ptr(), 0, 0, 2)
    });
    assert_eq!(cracked, 1, "the literal mask is the plaintext itself");
    crack_shutdown();
}

/// P11.1.06: the rate is a measurement of an attack that ran, not a constant.
#[test]
fn the_rate_is_a_real_measurement_of_the_attack_that_ran() {
    let _guard = engine();
    let fixtures = Fixtures::new("rate");
    crack_init();
    assert_eq!(crack_hashes_per_second(), 0.0, "zero before any attack");

    assert_eq!(load_target(), 1);
    let wordlist = fixtures.wordlist.clone();
    let cracked = with_deadline("attack_dictionary", Duration::from_secs(30), move || unsafe {
        attack_dictionary(wordlist.as_ptr(), std::ptr::null(), 1)
    });
    assert_eq!(cracked, 1);

    // One candidate was tested, so the rate is 1 over the elapsed time and must
    // therefore be finite and positive.
    assert_eq!(crack_last_tested(), 1, "one word in the wordlist");
    let elapsed = crack_last_duration_secs();
    assert!(elapsed > 0.0, "a completed attack took no measurable time");
    let rate = crack_hashes_per_second();
    assert!(rate > 0.0, "a rate of {rate} after testing a candidate is wrong");
    assert!(rate.is_finite(), "the rate must not be infinite");
    // One candidate in at least a microsecond cannot exceed a million per
    // second. This is a ceiling check, not a performance claim.
    assert!(rate < 1_000_000.0, "implausible rate {rate}");

    crack_shutdown();
}

/// The brute force rate uses the runner's own tested count.
#[test]
fn the_bruteforce_rate_is_measured_too() {
    let _guard = engine();
    crack_init();
    let mask = CString::new(PLAINTEXT).expect("mask");
    assert_eq!(load_target(), 1);
    let cracked = with_deadline("attack_bruteforce", Duration::from_secs(30), move || unsafe {
        attack_bruteforce(mask.as_ptr(), 0, 0, 1)
    });
    assert_eq!(cracked, 1);
    assert_eq!(crack_last_tested(), 1, "a literal mask is one candidate");
    assert!(crack_hashes_per_second() > 0.0);
    crack_shutdown();
}

/// Null and empty inputs are refused with named codes rather than dereferenced.
#[test]
fn null_inputs_are_refused_with_named_codes() {
    let _guard = engine();
    crack_init();
    // SAFETY: each pointer is null, which every one of these handles explicitly.
    unsafe {
        assert_eq!(hash_load_file(std::ptr::null()), CRACK_E_NULL);
        assert_eq!(hash_load_buffer(std::ptr::null(), 5), CRACK_E_NULL);
        assert_eq!(hash_load_buffer(b"x".as_ptr(), 0), CRACK_E_NULL);
        assert_eq!(
            attack_dictionary(std::ptr::null(), std::ptr::null(), 1),
            CRACK_E_NULL
        );
        assert_eq!(attack_bruteforce(std::ptr::null(), 0, 0, 1), CRACK_E_NULL);
        assert!(crack_identify_hash(std::ptr::null(), 4).is_null());
        assert_eq!(
            crack_get_result(0, std::ptr::null_mut(), std::ptr::null_mut()),
            CRACK_E_NULL
        );
    }
    crack_shutdown();
}

/// Attacking with nothing loaded says so instead of running against an empty
/// set and reporting success.
#[test]
fn an_attack_with_no_hashes_is_refused() {
    let _guard = engine();
    crack_init();
    let missing = CString::new("/nonexistent/pwdcrack/words.txt").expect("path");
    // SAFETY: valid null terminated string.
    let code = unsafe { attack_dictionary(missing.as_ptr(), std::ptr::null(), 1) };
    assert_eq!(code, CRACK_E_NO_HASHES);
    crack_shutdown();
}

/// Identification goes through the detector and reports what it recognised.
#[test]
fn identification_names_the_real_type() {
    let _guard = engine();
    let input = TARGET.as_bytes();
    // SAFETY: valid for input.len() bytes.
    let ptr = unsafe { crack_identify_hash(input.as_ptr(), input.len() as i32) };
    assert!(!ptr.is_null());
    // SAFETY: transfers ownership; released once below.
    let name = unsafe { CStr::from_ptr(ptr) }.to_str().expect("utf8").to_string();
    // SAFETY: released exactly once.
    unsafe { crack_free_string(ptr) };
    assert_ne!(name, "Unknown", "an MD5 must be identified");

    let junk = b"not a hash at all";
    // SAFETY: valid for junk.len() bytes.
    let ptr = unsafe { crack_identify_hash(junk.as_ptr(), junk.len() as i32) };
    // SAFETY: transfers ownership.
    let name = unsafe { CStr::from_ptr(ptr) }.to_str().expect("utf8").to_string();
    // SAFETY: released exactly once.
    unsafe { crack_free_string(ptr) };
    assert_eq!(name, "Unknown");
}

/// P11.1.06: the tier is detected, so it must be one of the three names and must
/// not be the mode label the previous version returned.
#[test]
fn the_tier_is_detected_not_a_constant() {
    let _guard = engine();
    let ptr = crack_detect_tier();
    assert!(!ptr.is_null());
    // SAFETY: documented as borrowed for the life of the process.
    let tier = unsafe { CStr::from_ptr(ptr) }.to_str().expect("utf8").to_string();
    assert!(
        matches!(tier.as_str(), "low" | "mid" | "high"),
        "got {tier:?}; the old constant was \"Auto\", which is a mode not a tier"
    );

    let detail = crack_detect_tier_detail();
    assert!(!detail.is_null());
    // SAFETY: borrowed.
    let text = unsafe { CStr::from_ptr(detail) }.to_str().expect("utf8").to_string();
    let parts: Vec<&str> = text.split(',').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], tier, "the detail and the summary must agree");
    assert!(parts[1].parse::<usize>().expect("cpus") >= 1);
}

/// Concurrent readers must not deadlock or corrupt the state.
#[test]
fn readers_run_concurrently_without_deadlocking() {
    let _guard = engine();
    crack_init();
    let handles: Vec<_> = (0..8)
        .map(|_| {
            std::thread::spawn(|| {
                for _ in 0..200 {
                    let _ = crack_total_hashes();
                    let _ = crack_found_count();
                    let _ = crack_hashes_per_second();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("a reader thread panicked");
    }
    crack_shutdown();
}

/// MD5, for checking that a reported pair really is a match rather than two
/// agreeing implementations.
fn md5(text: &str) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(text.as_bytes());
    hex::encode(h.finalize())
}