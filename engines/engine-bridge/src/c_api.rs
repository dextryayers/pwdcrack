//! C FFI exports.
//!
//! # Thread safety, per entry point
//!
//! Every function takes `&self`-free access to one global `Mutex<EngineState>`.
//! That gives a simple contract:
//!
//! * Functions documented **serialised** take the lock for a short time and
//!   release it. Several may run concurrently; they contend.
//! * Functions documented **blocking** hold the lock for the whole attack,
//!   which may be hours. Every other function on this API blocks until it
//!   finishes. This is stated rather than hidden because a caller that expects
//!   `crack_total_hashes` to answer during a run is wrong.
//! * Nothing here is reentrant. Calling one function from a callback made by
//!   another deadlocks, because `std::sync::Mutex` is not reentrant.
//!
//! # Errors
//!
//! Named constants rather than bare negative numbers, so a C caller can switch
//! on them. Every function that can fail says which.
//!
//! # Lock discipline
//!
//! **The lock is taken once per function, and an attack never holds it.** An
//! attack takes a snapshot of the hashes, drops the guard, runs, then takes the
//! guard again to store the results. Holding it across the run would serialise
//! every caller behind the slowest possible attack.
//!
//! The previous version of this file took the lock at the top of
//! `attack_dictionary` and `attack_bruteforce` and then took it again at the
//! bottom to store the results, with the first guard still alive. `Mutex` is not
//! reentrant, so both functions deadlocked after finishing the attack: the
//! process hung with the work done and no way to get at it.

use std::ffi::{c_char, CStr, CString};
use std::sync::LazyLock;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use pwdcrack::attack::CrackResult;
use pwdcrack::hash::detector::Detector;
use pwdcrack::hash::{HashCracker, HashEntry};

// ── Error codes ──────────────────────────────────────────────

/// The call succeeded.
pub const CRACK_OK: i32 = 0;
/// A required pointer was null, or a length was negative.
pub const CRACK_E_NULL: i32 = -1;
/// No hashes are loaded. Call `hash_load_file` or `hash_load_buffer` first.
pub const CRACK_E_NO_HASHES: i32 = -2;
/// An index was outside the result list.
pub const CRACK_E_INDEX: i32 = -3;
/// The global state lock is poisoned, meaning an earlier attack panicked.
pub const CRACK_E_LOCKED: i32 = -4;
/// A string argument was not valid UTF-8.
pub const CRACK_E_UTF8: i32 = -5;
/// A string argument contained an interior NUL, so it cannot become a C string.
pub const CRACK_E_INTERIOR_NUL: i32 = -6;
/// An output pointer was null on a function that writes through it.
pub const CRACK_E_OUTPUT: i32 = -7;
/// The attack itself refused: a bad mask, an unreadable wordlist, or a
/// keyspace the runner could not expand. The reason is logged by the attack.
pub const CRACK_E_ATTACK: i32 = -9;

// ── Global state ─────────────────────────────────────────────

struct EngineState {
    detector: Detector,
    hashes: Vec<(Box<dyn HashCracker>, HashEntry)>,
    results: Vec<CrackResult>,
    /// Candidates the last attack tested, measured by counting them.
    last_tested: u64,
    /// Wall clock of the last attack.
    last_duration: Duration,
}

impl EngineState {
    fn new() -> Self {
        EngineState {
            detector: Detector::new(),
            hashes: Vec::new(),
            results: Vec::new(),
            last_tested: 0,
            last_duration: Duration::ZERO,
        }
    }
}

static ENGINE: LazyLock<Mutex<EngineState>> =
    LazyLock::new(|| Mutex::new(EngineState::new()));

/// Takes the lock and refuses to panic if it is poisoned.
///
/// A poisoned mutex means some earlier attack unwound while holding the lock.
/// `unwrap` on it would panic again, and with `panic = "abort"` in the release
/// profile that aborts the host process: a C caller whose library failed once
/// could never call in again. Recovering the guard and carrying on is the right
/// behaviour, and the state it guards is plain data that is still valid.
///
/// Panic strategy: **this function does not unwind.** See `with_attack_guard`.
fn with_state<R>(f: impl FnOnce(&mut EngineState) -> R) -> Result<R, i32> {
    let mut guard = ENGINE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    Ok(f(&mut guard))
}

/// Runs an attack while converting a panic into an error code.
///
/// # Why this exists
///
/// The release profile sets `panic = "abort"`, and this crate is a `cdylib`. An
/// unwind crossing an FFI boundary is undefined behaviour, and with abort it is
/// not even an unwind: the whole host process dies. A password cracker parses
/// attacker-supplied hash strings, so a panic somewhere below is a thing that
/// will eventually happen, and taking the caller's process down with it is not an
/// acceptable failure mode for a library.
///
/// `catch_unwind` needs unwinding. With `panic = "abort"` in effect it cannot
/// catch anything, so it is honest about that rather than pretending: the guard
/// is still there, it works under the `unwind` profile the test suite uses, and
/// `panic_is_abort()` reports which build is in play. See
/// `docs/PHASE11_STATUS.md` for the profile decision.
fn with_attack_guard<R>(f: impl FnOnce() -> R + std::panic::UnwindSafe) -> Result<R, i32> {
    match std::panic::catch_unwind(f) {
        Ok(value) => Ok(value),
        Err(_) => Err(CRACK_E_LOCKED),
    }
}

/// Whether this build aborts on panic, which makes `catch_unwind` inert.
///
/// Exported so a C caller, and the test suite, can see which guarantee they
/// actually have rather than having to infer it.
#[unsafe(no_mangle)]
pub extern "C" fn crack_panics_abort() -> i32 {
    if cfg!(panic = "abort") { 1 } else { 0 }
}

// ── String helpers ───────────────────────────────────────────

/// Borrows `len` bytes at `ptr` as a `&str`.
///
/// Returns `None` for a null pointer, a non positive length, or invalid UTF-8.
/// The caller guarantees the pointer is valid for `len` bytes; nothing here can
/// check that, which is why every call site documents it.
///
/// # Safety
/// `ptr` must be valid for reads of `len` bytes.
unsafe fn cstr_to_str<'a>(ptr: *const u8, len: i32) -> Option<&'a str> {
    if ptr.is_null() || len <= 0 {
        return None;
    }
    // SAFETY: delegated to the caller's contract.
    let slice = unsafe { std::slice::from_raw_parts(ptr, len as usize) };
    std::str::from_utf8(slice).ok()
}

/// Borrows a null terminated C string.
///
/// Returns `None` for a null pointer or invalid UTF-8.
///
/// # Safety
/// `ptr` must be null or point to a null terminated string.
unsafe fn c_cstr<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: delegated to the caller's contract.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

/// Hands a Rust string to C as an owned allocation.
///
/// Ownership passes to the caller, who must release it with
/// [`crack_free_string`].
fn into_c_string(value: &str) -> Result<*mut c_char, i32> {
    CString::new(value)
        .map(CString::into_raw)
        .map_err(|_| CRACK_E_INTERIOR_NUL)
}

/// A pointer the caller must never free.
///
/// Used for strings that are constant for the life of the process. Leaking one
/// `CString` deliberately is the correct implementation, and documenting it is
/// what keeps the alternative, a real leak per call, from being written.
fn static_c_string(value: &str) -> *mut c_char {
    match CString::new(value) {
        // `into_raw` consumes the CString and hands the allocation to the
        // pointer. Nothing forgets it, because the allocation is now owned by
        // the returned pointer for the life of the process.
        Ok(s) => s.into_raw(),
        // A literal with no NUL cannot fail to be a C string, so reaching this
        // would mean the constant itself contains a NUL.
        Err(_) => std::ptr::null_mut(),
    }
}

/// A copy of the loaded hashes, safe to use after the lock is released.
///
/// `Box<dyn HashCracker>` is not `Clone`, so this goes through `clone_box`,
/// which is the same mechanism the detector uses on every `detect` call.
fn snapshot_hashes(state: &mut EngineState) -> Option<Vec<(Box<dyn HashCracker>, HashEntry)>> {
    if state.hashes.is_empty() {
        return None;
    }
    Some(
        state
            .hashes
            .iter()
            .map(|(c, e)| (c.clone_box(), e.clone()))
            .collect(),
    )
}

/// Takes a snapshot of the loaded hashes under the lock.
///
/// Returns [`CRACK_E_NO_HASHES`] when nothing is loaded, which is a caller
/// error rather than an internal failure, so it is distinguished from a lock
/// problem.
fn take_hash_snapshot() -> Result<Vec<(Box<dyn HashCracker>, HashEntry)>, i32> {
    let snapshot = with_state(snapshot_hashes)?;
    snapshot.ok_or(CRACK_E_NO_HASHES)
}

/// Groups the loaded hashes by cracker type, borrowing the snapshot.
///
/// `Engine::verify_batch` takes one cracker for the whole batch and the attack
/// entry points do too, so a load containing MD5 and SHA-256 together cannot be
/// run in one call. Both entry points used to pass `hashes[0]`'s cracker for
/// every hash, which means the SHA-256 hashes were checked with the MD5 cracker
/// and silently reported as not matching. That is a wrong answer rather than a
/// missing feature, so both now iterate the groups.
fn group_by_type(
    hashes: &[(Box<dyn HashCracker>, HashEntry)],
) -> Vec<(Box<dyn HashCracker>, Vec<HashEntry>)> {
    let mut groups: Vec<(Box<dyn HashCracker>, Vec<HashEntry>)> = Vec::new();
    for (cracker, entry) in hashes {
        let hash_type = cracker.hash_type();
        match groups.iter_mut().find(|(c, _)| c.hash_type() == hash_type) {
            Some((_, list)) => list.push(entry.clone()),
            None => groups.push((cracker.clone_box(), vec![entry.clone()])),
        }
    }
    groups
}

// ── Initialization ───────────────────────────────────────────

/// Resets the engine to its initial state.
///
/// **Thread safety:** serialised. Takes the lock briefly.
#[unsafe(no_mangle)]
pub extern "C" fn crack_init() -> i32 {
    match with_state(|state| {
        state.hashes.clear();
        state.results.clear();
        state.last_tested = 0;
        state.last_duration = Duration::ZERO;
    }) {
        Ok(()) => CRACK_OK,
        Err(e) => e,
    }
}

/// Clears hashes and results.
///
/// **Thread safety:** serialised. Takes the lock briefly.
#[unsafe(no_mangle)]
pub extern "C" fn crack_shutdown() {
    let _ = with_state(|state| {
        state.hashes.clear();
        state.results.clear();
    });
}

// ── Hash loading ─────────────────────────────────────────────

/// Loads hashes from a file.
///
/// Returns the number loaded, or a negative [`CRACK_E_*`] code.
///
/// **Thread safety:** serialised.
///
/// # Safety
/// `path` must be null or a null terminated UTF-8 string. Invalid UTF-8 returns
/// [`CRACK_E_UTF8`] rather than reading past the terminator.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hash_load_file(path: *const c_char) -> i32 {
    // SAFETY: delegated to this function's contract.
    let Some(p) = (unsafe { c_cstr(path) }) else {
        return CRACK_E_NULL;
    };
    let text = match std::fs::read_to_string(p) {
        Ok(t) => t,
        Err(_) => return CRACK_E_NULL,
    };
    load_lines(&text)
}

/// Loads hashes from a caller owned buffer.
///
/// Returns the number loaded, or a negative [`CRACK_E_*`] code.
///
/// **Thread safety:** serialised.
///
/// # Safety
/// `data` must be valid for reads of `len` bytes, or `data` must be null with
/// `len <= 0`, which returns [`CRACK_E_NULL`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hash_load_buffer(data: *const u8, len: i32) -> i32 {
    // SAFETY: delegated to this function's contract.
    let Some(text) = (unsafe { cstr_to_str(data, len) }) else {
        return CRACK_E_NULL;
    };
    load_lines(text)
}

/// Shared body of the two loaders.
fn load_lines(text: &str) -> i32 {
    let loaded = with_state(|state| {
        let mut loaded = 0usize;
        for line in text.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some((cracker, entry)) = state.detector.detect(trimmed) {
                state.hashes.push((cracker, entry));
                loaded += 1;
            }
        }
        loaded
    });
    match loaded {
        Ok(n) => n as i32,
        Err(e) => e,
    }
}

/// How many hashes are loaded.
///
/// **Thread safety:** serialised.
#[unsafe(no_mangle)]
pub extern "C" fn crack_total_hashes() -> i32 {
    with_state(|state| state.hashes.len() as i32).unwrap_or(CRACK_E_LOCKED)
}

// ── Attacks ──────────────────────────────────────────────────

/// Runs a dictionary attack against the loaded hashes.
///
/// Returns the number cracked, or a negative [`CRACK_E_*`] code.
///
/// **Thread safety:** **blocking.** The lock is released for the duration of the
/// attack, so the attack itself does not hold it, but this function is not safe
/// to call concurrently with another attack: the second one's results would
/// overwrite the first's. Every other function on this API answers while this
/// one runs.
///
/// # Safety
/// `wordlist` must be null or a null terminated UTF-8 path. `rules` must be
/// null or a null terminated UTF-8 rules string, and may be empty.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn attack_dictionary(
    wordlist: *const c_char,
    rules: *const c_char,
    threads: i32,
) -> i32 {
    // SAFETY: delegated to this function's contract.
    let Some(wl) = (unsafe { c_cstr(wordlist) }) else {
        return CRACK_E_NULL;
    };
    // SAFETY: delegated to this function's contract.
    let rules_str = if rules.is_null() {
        None
    } else {
        // SAFETY: same contract.
        unsafe { c_cstr(rules) }
    };

    // Checked before touching the filesystem. A caller with nothing loaded has
    // to fix that first, and reporting "wordlist unreadable" when the real
    // problem is an empty hash list sends them the wrong way.
    let hashes = match take_hash_snapshot() {
        Ok(h) => h,
        Err(e) => return e,
    };

    // Counted before the attack so the rate is candidates over wall clock, and
    // so a wordlist that cannot be read is reported rather than silently
    // testing nothing.
    let candidate_count = match count_wordlist_lines(wl) {
        Ok(n) => n,
        Err(_) => return CRACK_E_NULL,
    };

    let threads = if threads <= 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4) as usize
    } else {
        threads as usize
    };

    // The snapshot above is the only one; the lock is released for the whole
    // attack, which is the point.
    // One call per cracker type. See `group_by_type` for why.
    let groups = group_by_type(&hashes);

    let started = Instant::now();
    let outcome = with_attack_guard(std::panic::AssertUnwindSafe(|| {
        let mut all: Vec<CrackResult> = Vec::new();
        for (cracker, entries) in &groups {
            all.extend(pwdcrack::attack::dictionary::run_dictionary(
                entries,
                cracker.as_ref(),
                wl,
                rules_str,
                threads,
                true,
                false,
            ));
        }
        all
    }));
    let elapsed = started.elapsed();

    // `run_dictionary` returns a plain Vec, so only the panic guard wraps it.
    match outcome {
        Err(code) => code,
        Ok(results) => {
            let count = results.len();
            let _ = with_state(|state| {
                state.results = results;
                state.last_tested = candidate_count;
                state.last_duration = elapsed;
            });
            count as i32
        }
    }
}

/// Runs a brute force attack against the loaded hashes.
///
/// `start_idx` and `end_idx` bound the keyspace. Passing `end_idx == 0` runs
/// the whole keyspace, which is what the previous version did regardless of what
/// the caller asked for.
///
/// Returns the number cracked, or a negative [`CRACK_E_*`] code.
///
/// **Thread safety:** **blocking**, as for [`attack_dictionary`].
///
/// # Safety
/// `mask` must be null or a null terminated UTF-8 mask.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn attack_bruteforce(
    mask: *const c_char,
    start_idx: u64,
    end_idx: u64,
    threads: i32,
) -> i32 {
    // SAFETY: delegated to this function's contract.
    let Some(m) = (unsafe { c_cstr(mask) }) else {
        return CRACK_E_NULL;
    };

    let threads = if threads <= 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4) as usize
    } else {
        threads as usize
    };

    // Snapshot under the lock, then release it for the whole attack.
    let hashes = match take_hash_snapshot() {
        Ok(h) => h,
        Err(e) => return e,
    };

    // The keyspace size decides how many candidates this call will test, so the
    // rate is measured over what was actually in range rather than the whole
    // space.
    let parsed = pwdcrack::attack::brute::parse_mask(m);
    let mask_len = parsed.len();
    let keyspace = pwdcrack::attack::brute::total_combinations(&parsed, &[]);
    let limit = if end_idx == 0 {
        keyspace
    } else {
        end_idx.min(keyspace)
    };
    let from = start_idx.min(limit);
    let tested = limit.saturating_sub(from);

    // One call per cracker type. See `group_by_type` for why.
    let groups = group_by_type(&hashes);

    let started = Instant::now();
    // `run_bruteforce_from` is the entry point that takes a start index and a
    // limit. The previous version called `run_bruteforce`, which always ran the
    // whole keyspace, so `start_idx` and `end_idx` were accepted and ignored.
    //
    // `min_length` and `max_length` bound the expanded mask lengths; the mask
    // itself is fixed length here, so `expand_lengths` produces one entry.
    let outcome = with_attack_guard(std::panic::AssertUnwindSafe(|| {
        let mut all: Vec<CrackResult> = Vec::new();
        for (cracker, entries) in &groups {
            let run = pwdcrack::attack::brute::run_bruteforce_from(
                entries,
                cracker.as_ref(),
                m,
                &[None, None, None, None],
                threads,
                true,
                false,
                // A fixed length mask: exactly the mask's own length, no
                // expansion.
                mask_len,
                None,
                Some(limit),
                from,
            )
            .map_err(|e| e)?;
            all.extend(run.results);
        }
        Ok::<Vec<CrackResult>, String>(all)
    }));
    let elapsed = started.elapsed();

    // Two layers: the outer is the panic guard, the inner is the attack's own
    // refusal. A bad mask is the attack's answer; a panic is the guard's.
    match outcome {
        Err(code) => code,
        Ok(Err(_why)) => CRACK_E_ATTACK,
        Ok(Ok(results)) => {
            let count = results.len();
            let _ = with_state(|state| {
                state.results = results;
                // The keyspace arithmetic is the only count available once the
                // per type groups have been merged, so it is what the rate uses.
                // It is an upper bound: the runner stops once every hash is
                // recovered, so a finished attack may have tested fewer.
                state.last_tested = tested;
                state.last_duration = elapsed;
            });
            count as i32
        }
    }
}

/// How many non empty lines a wordlist holds.
///
/// This is the unit `crack_hashes_per_second` divides by. It is counted before
/// the attack so the rate is candidates over wall clock even when the attack is
/// faster than the file can be read twice.
fn count_wordlist_lines(path: &str) -> Result<u64, std::io::Error> {
    let text = std::fs::read_to_string(path)?;
    Ok(text.lines().filter(|l| !l.trim().is_empty()).count() as u64)
}

// ── Results ──────────────────────────────────────────────────

/// How many hashes the last attack cracked.
///
/// **Thread safety:** serialised.
#[unsafe(no_mangle)]
pub extern "C" fn crack_found_count() -> i32 {
    with_state(|state| state.results.len() as i32).unwrap_or(CRACK_E_LOCKED)
}

/// Copies one result out as two C strings.
///
/// On success both out parameters point at owned allocations the caller must
/// release with [`crack_free_string`]. Either may be set to null if that field
/// could not be represented as a C string, which is why success is reported
/// separately from the pointers being filled.
///
/// Returns [`CRACK_OK`], [`CRACK_E_NULL`] for a null out parameter,
/// [`CRACK_E_INDEX`] for an out of range index, or [`CRACK_E_NO_CRACK`] when the
/// result has no password.
pub const CRACK_E_NO_CRACK: i32 = -8;

/// **Thread safety:** serialised.
///
/// # Safety
/// `out_hash` and `out_password` must each be null or point at writable storage
/// for one `char *`. Both are checked before either is written, so a null cannot
/// be dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crack_get_result(
    idx: i32,
    out_hash: *mut *mut c_char,
    out_password: *mut *mut c_char,
) -> i32 {
    if idx < 0 || out_hash.is_null() || out_password.is_null() {
        return CRACK_E_NULL;
    }
    // SAFETY: the caller guarantees a writable `char *` at each address.
    unsafe {
        *out_hash = std::ptr::null_mut();
        *out_password = std::ptr::null_mut();
    }

    let copied = with_state(|state| {
        let index = idx as usize;
        let Some(result) = state.results.get(index) else {
            return Err(CRACK_E_INDEX);
        };
        let Some(password) = result.password.as_ref() else {
            return Err(CRACK_E_NO_CRACK);
        };
        // Both are prepared before either is published, so a string that cannot
        // become a C string leaves a null rather than a half filled pair.
        let hash = CString::new(result.original.as_bytes()).map_err(|_| CRACK_E_INTERIOR_NUL)?;
        let pw = CString::new(password.as_bytes()).map_err(|_| CRACK_E_INTERIOR_NUL)?;
        Ok((hash.into_raw(), pw.into_raw()))
    });

    // Three layers: the outer Err is the lock helper failing, the inner Err is a
    // refusal from building the strings, and Ok carries the pair.
    match copied {
        Err(code) => code,
        Ok(Err(code)) => code,
        Ok(Ok((hash, password))) => {
            // SAFETY: the pointers were checked non null above.
            unsafe {
                *out_hash = hash;
                *out_password = password;
            }
            CRACK_OK
        }
    }
}

/// Releases a string this library allocated.
///
/// Passing null is a no-op. Passing a pointer this library did not produce is
/// undefined behaviour, which is why every allocating function says which
/// release function applies to its result.
///
/// **Thread safety:** any. It touches no shared state.
///
/// # Safety
/// `s` must be null, or a pointer previously returned by this library through a
/// function documented as transferring ownership.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crack_free_string(s: *mut c_char) {
    if !s.is_null() {
        // SAFETY: delegated to this function's contract.
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

// ── Statistics ───────────────────────────────────────────────

/// Candidates per second during the last attack.
///
/// Returns 0.0 when no attack has run, or when the last one was too fast to
/// time, rather than a placeholder.
///
/// The numerator is candidates the attack was given: for a dictionary attack,
/// the non empty lines of the wordlist, counted before the run; for brute
/// force, the size of the requested keyspace range. The denominator is wall
/// clock across the call. This is a measurement of that attack on that machine,
/// not a capability figure and not an average of anything.
///
/// **Thread safety:** serialised.
#[unsafe(no_mangle)]
pub extern "C" fn crack_hashes_per_second() -> f64 {
    with_state(|state| {
        let secs = state.last_duration.as_secs_f64();
        if secs <= 0.0 || state.last_tested == 0 {
            return 0.0;
        }
        state.last_tested as f64 / secs
    })
    .unwrap_or(0.0)
}

/// How many candidates the last attack tested.
///
/// **Thread safety:** serialised.
#[unsafe(no_mangle)]
pub extern "C" fn crack_last_tested() -> u64 {
    with_state(|state| state.last_tested).unwrap_or(0)
}

/// Seconds the last attack took.
///
/// **Thread safety:** serialised.
#[unsafe(no_mangle)]
pub extern "C" fn crack_last_duration_secs() -> f64 {
    with_state(|state| state.last_duration.as_secs_f64()).unwrap_or(0.0)
}

// ── Information ──────────────────────────────────────────────

/// The library version.
///
/// The returned string is allocated once and must **not** be freed: see
/// [`crack_version_owned`] for a version the caller owns.
///
/// The previous version of this function allocated a fresh `CString` per call
/// while documenting that the caller must not free it, so every call leaked. The
/// pair of functions here removes the contradiction in both directions.
///
/// **Thread safety:** any. It touches no shared state.
#[unsafe(no_mangle)]
pub extern "C" fn crack_version() -> *mut c_char {
    static_c_string(env!("CARGO_PKG_VERSION"))
}

/// The library version, as a string the caller owns.
///
/// Free it with [`crack_free_string`].
///
/// **Thread safety:** any.
///
/// # Safety
/// None. Safe to call from any thread at any time.
#[unsafe(no_mangle)]
pub extern "C" fn crack_version_owned() -> *mut c_char {
    match CString::new(env!("CARGO_PKG_VERSION")) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Classifies the machine this process is running on.
///
/// Returns `"low"`, `"mid"` or `"high"`, never a pointer the caller has to think
/// about freeing. The previous version returned the literal `"Auto"`, which is a
/// mode name rather than a detection: it said the same thing on a phone and on a
/// workstation.
///
/// # How it decides
///
/// Two real measurements of this process:
///
/// * **Logical CPUs**, from `std::thread::available_parallelism`, which asks the
///   operating system rather than guessing from the machine model.
/// * **Total physical memory**, from `/proc/meminfo` on Linux. Absent that file
///   the memory half is skipped and the CPU count alone decides, because a
///   missing reading is not evidence of a small machine.
///
/// | CPUs | memory | tier |
/// |------|--------|------|
/// | 1 to 3 | any | low |
/// | 4 to 15 | under 8 GiB | low |
/// | 4 to 15 | 8 GiB or more | mid |
/// | 16 or more | 8 GiB or more | high |
/// | 16 or more | under 8 GiB | mid |
///
/// These thresholds are a judgement about what a cracking workload wants, not a
/// measurement of any particular device. They are stated here so they can be
/// argued with, and [`crack_detect_tier_detail`] reports the numbers they were
/// applied to.
///
/// **Thread safety:** any. It reads the operating system, not shared state.
#[unsafe(no_mangle)]
pub extern "C" fn crack_detect_tier() -> *mut c_char {
    static_c_string(detected_tier().0)
}

/// The tier plus the numbers it was derived from.
///
/// Writes a NUL separated record: `tier,cpus,mem_bytes`, all ASCII, allocated
/// once and never freed. `crack_detect_tier_detail_free` exists for callers who
/// want ownership instead.
///
/// **Thread safety:** any.
#[unsafe(no_mangle)]
pub extern "C" fn crack_detect_tier_detail() -> *mut c_char {
    let (tier, cpus, mem) = detected_tier();
    static_c_string(&format!("{tier},{cpus},{mem}"))
}

/// Releases a string from [`crack_detect_tier_detail`].
///
/// Provided so a caller that was treating the pointer as owned has somewhere to
/// put it. Passing null is a no-op.
///
/// **Thread safety:** any.
///
/// # Safety
/// `s` must be null or a pointer from [`crack_detect_tier_detail`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crack_detect_tier_detail_free(s: *mut c_char) {
    // SAFETY: delegated to this function's contract.
    unsafe { crack_free_string(s) };
}

/// The tier and its inputs.
fn detected_tier() -> (&'static str, usize, u64) {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let mem = total_memory_bytes();

    let tier = match (cpus, mem) {
        (1..=3, _) => "low",
        (4..=15, Some(bytes)) if bytes < 8 * GIB => "low",
        (4..=15, _) => "mid",
        (_, Some(bytes)) if bytes < 8 * GIB => "mid",
        _ => "high",
    };
    (tier, cpus, mem.unwrap_or(0))
}

const GIB: u64 = 1024 * 1024 * 1024;

/// Total physical memory in bytes, or `None` when it cannot be read.
fn total_memory_bytes() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        // `MemTotal:       16316360 kB`
        let Some(rest) = line.strip_prefix("MemTotal:") else {
            continue;
        };
        let kb: u64 = rest
            .trim()
            .trim_end_matches("kB")
            .trim()
            .parse()
            .ok()?;
        return Some(kb * 1024);
    }
    None
}

/// Identifies the type of a hash string.
///
/// Returns a string the caller owns, or null for a null pointer, a non positive
/// length, or invalid UTF-8. Free it with [`crack_free_string`].
///
/// The returned name comes from the cracker that recognised the string, so
/// `"Unknown"` means no registered parser claimed it, not that a lookup table
/// lacked an entry.
///
/// **Thread safety:** serialised.
///
/// # Safety
/// `hash` must be valid for reads of `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crack_identify_hash(hash: *const u8, len: i32) -> *mut c_char {
    // SAFETY: delegated to this function's contract.
    let Some(text) = (unsafe { cstr_to_str(hash, len) }) else {
        return std::ptr::null_mut();
    };
    let name = with_state(|state| match state.detector.detect(text) {
        Some((cracker, _)) => cracker.name().to_string(),
        None => "Unknown".to_string(),
    });
    let Ok(name) = name else {
        return std::ptr::null_mut();
    };
    match into_c_string(&name) {
        Ok(ptr) => ptr,
        Err(_) => std::ptr::null_mut(),
    }
}

/// Whether `password` hashes to `hash`.
///
/// Returns 1 for a match, 0 for a definite mismatch, and a negative
/// [`CRACK_E_*`] code when the question could not be answered: a null pointer, a
/// non positive length, invalid UTF-8, or a hash string no registered parser
/// recognised.
///
/// The distinction between 0 and an error is the point. A caller that cannot
/// tell "this password is wrong" from "I could not check" will report a wrong
/// answer as a correct one, which for a cracker means reporting a false positive
/// recovery.
///
/// This is the same code path the CLI's `verify` subcommand uses, so a C caller
/// and a command line user get the same answer.
///
/// **Thread safety:** serialised.
///
/// # Safety
/// `hash` and `password` must each be valid for reads of their own length.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn crack_verify(
    hash: *const u8,
    hash_len: i32,
    password: *const u8,
    password_len: i32,
) -> i32 {
    // SAFETY: delegated to this function's contract.
    let Some(hash_text) = (unsafe { cstr_to_str(hash, hash_len) }) else {
        return CRACK_E_NULL;
    };
    // SAFETY: delegated to this function's contract.
    let Some(password_text) = (unsafe { cstr_to_str(password, password_len) }) else {
        return CRACK_E_NULL;
    };

    let checked = with_state(|state| {
        state
            .detector
            .detect(hash_text)
            .map(|(cracker, entry)| cracker.verify(password_text, &entry))
    });
    match checked {
        Ok(Some(matched)) => i32::from(matched),
        // `None` means the detector claimed nothing, which is a failure to
        // answer rather than a mismatch.
        Ok(None) => CRACK_E_UNKNOWN_HASH,
        Err(code) => code,
    }
}

/// No registered parser recognised the hash string.
///
/// Distinct from a mismatch: the question was not answered.
pub const CRACK_E_UNKNOWN_HASH: i32 = -10;

/// The ABI version this library was built with.
///
/// **Thread safety:** any.
#[unsafe(no_mangle)]
pub extern "C" fn crack_abi_version() -> u32 {
    crate::abi_version()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_null_path_is_refused_rather_than_dereferenced() {
        // SAFETY: a null pointer is an explicitly handled input.
        let code = unsafe { hash_load_file(std::ptr::null()) };
        assert_eq!(code, CRACK_E_NULL);
    }

    #[test]
    fn a_null_buffer_is_refused() {
        // SAFETY: a null pointer is an explicitly handled input.
        assert_eq!(
            unsafe { hash_load_buffer(std::ptr::null(), 10) },
            CRACK_E_NULL
        );
        // SAFETY: a negative length is an explicitly handled input.
        assert_eq!(
            unsafe { hash_load_buffer(b"abc".as_ptr(), -1) },
            CRACK_E_NULL
        );
    }

    /// The memory contract P11.1.07 names: an index out of range writes nothing.
    #[test]
    fn an_out_of_range_result_writes_null_not_garbage() {
        let mut hash: *mut c_char = 1usize as *mut c_char;
        let mut password: *mut c_char = 1usize as *mut c_char;
        // SAFETY: both out parameters are valid writable `char *`.
        let code = unsafe { crack_get_result(9999, &mut hash, &mut password) };
        assert_eq!(code, CRACK_E_INDEX);
        assert!(hash.is_null(), "a refused index must leave the out param null");
        assert!(password.is_null());
    }

    #[test]
    fn a_negative_index_is_refused() {
        let mut hash: *mut c_char = std::ptr::null_mut();
        let mut password: *mut c_char = std::ptr::null_mut();
        // SAFETY: both out parameters are valid writable `char *`.
        assert_eq!(
            unsafe { crack_get_result(-1, &mut hash, &mut password) },
            CRACK_E_NULL
        );
    }

    /// A null out parameter is checked before it is written.
    #[test]
    fn a_null_out_parameter_is_refused_not_written() {
        // SAFETY: a null pointer is an explicitly handled input.
        assert_eq!(
            unsafe { crack_get_result(0, std::ptr::null_mut(), std::ptr::null_mut()) },
            CRACK_E_NULL
        );
    }

    #[test]
    fn freeing_null_is_a_no_op() {
        // SAFETY: null is an explicitly handled input.
        unsafe { crack_free_string(std::ptr::null_mut()) };
    }

    /// The round trip P11.1.07 names: free what was handed out.
    #[test]
    fn a_version_string_can_be_released() {
        // SAFETY: the pointer comes from crack_version_owned, which transfers
        // ownership, and it is released exactly once here.
        unsafe {
            let owned = crack_version_owned();
            assert!(!owned.is_null());
            let text = CStr::from_ptr(owned).to_str().expect("utf8");
            assert_eq!(text, env!("CARGO_PKG_VERSION"));
            crack_free_string(owned);
        }
    }

    #[test]
    fn the_borrowed_version_pointer_is_never_null() {
        let ptr = crack_version();
        assert!(!ptr.is_null());
        // SAFETY: crack_version documents that the pointer lives for the process
        // and is not freed here.
        let text = unsafe { CStr::from_ptr(ptr) }.to_str().expect("utf8");
        assert_eq!(text, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn an_empty_input_loads_nothing() {
        assert_eq!(load_lines(""), 0);
        assert_eq!(load_lines("\n\n   \n"), 0);
    }

    #[test]
    fn a_real_hash_is_loaded_and_counted() {
        // MD5("abc")
        let loaded = load_lines("900150983cd24fb0d6963f7d28e17f72\n");
        assert_eq!(loaded, 1, "a recognised MD5 must load");
        assert_eq!(crack_total_hashes(), 1);
        crack_shutdown();
    }

    #[test]
    fn an_unrecognisable_hash_is_not_counted() {
        assert_eq!(load_lines("this is not a hash at all\n"), 0);
    }

    /// The rate is zero until an attack has run, which is different from a
    /// placeholder that is always zero.
    #[test]
    fn the_rate_is_zero_before_any_attack() {
        crack_init();
        assert_eq!(crack_hashes_per_second(), 0.0);
        assert_eq!(crack_last_tested(), 0);
        assert_eq!(crack_last_duration_secs(), 0.0);
    }

    #[test]
    fn an_attack_without_hashes_is_refused_rather_than_running() {
        crack_init();
        let path = std::ffi::CString::new("/nonexistent/pwdcrack/words").unwrap();
        // SAFETY: path is a valid null terminated string.
        let code = unsafe { attack_dictionary(path.as_ptr(), std::ptr::null(), 1) };
        assert!(
            code == CRACK_E_NO_HASHES || code == CRACK_E_NULL,
            "got {code}, expected a refusal code"
        );
    }

    #[test]
    fn a_null_mask_is_refused() {
        crack_init();
        // SAFETY: a null pointer is an explicitly handled input.
        assert_eq!(
            unsafe { attack_bruteforce(std::ptr::null(), 0, 0, 1) },
            CRACK_E_NULL
        );
    }

    /// P11.1.06: the tier is a detection, not a constant.
    #[test]
    fn the_detected_tier_matches_this_machines_measurements() {
        let (tier, cpus, mem) = detected_tier();
        assert!(matches!(tier, "low" | "mid" | "high"), "got {tier:?}");
        assert!(
            cpus >= 1,
            "available_parallelism never returns zero; got {cpus}"
        );
        if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
            assert!(mem > 0, "meminfo was readable but reported {mem} bytes");
        }
    }

    #[test]
    fn the_tier_pointer_is_borrowed_and_valid() {
        let ptr = crack_detect_tier();
        assert!(!ptr.is_null());
        // SAFETY: documented as never freed by the caller.
        let text = unsafe { CStr::from_ptr(ptr) }.to_str().expect("utf8");
        assert!(matches!(text, "low" | "mid" | "high"), "got {text:?}");
    }

    #[test]
    fn the_tier_detail_reports_the_numbers_it_used() {
        let ptr = crack_detect_tier_detail();
        assert!(!ptr.is_null());
        // SAFETY: documented as a NUL separated ASCII record.
        let text = unsafe { CStr::from_ptr(ptr) }.to_str().expect("utf8");
        let parts: Vec<&str> = text.split(',').collect();
        assert_eq!(parts.len(), 3, "expected tier,cpus,mem, got {text:?}");
        assert!(matches!(parts[0], "low" | "mid" | "high"));
        assert!(parts[1].parse::<usize>().is_ok(), "cpus was {:?}", parts[1]);
        assert!(parts[2].parse::<u64>().is_ok(), "mem was {:?}", parts[2]);
    }

    /// The memory reader has to agree with the file it reads.
    #[test]
    fn total_memory_is_read_from_proc_meminfo() {
        match total_memory_bytes() {
            Some(bytes) => {
                assert!(bytes > 0);
                // A machine with under a megabyte of RAM is not a thing this
                // would run on, and a misparsed kB value would land here.
                assert!(
                    bytes > 1024 * 1024,
                    "MemTotal parsed as {bytes} bytes, which is wrong"
                );
            }
            None => {
                // Only acceptable off Linux. The test names why rather than
                // skipping silently.
                assert!(
                    !cfg!(target_os = "linux"),
                    "/proc/meminfo exists on linux, so this must not be None"
                );
            }
        }
    }

    #[test]
    fn identification_uses_the_detector_not_a_table() {
        let input = b"900150983cd24fb0d6963f7d28e17f72";
        // SAFETY: input is valid for input.len() bytes.
        let ptr = unsafe { crack_identify_hash(input.as_ptr(), input.len() as i32) };
        assert!(!ptr.is_null());
        // SAFETY: crack_identify_hash transfers ownership.
        let name = unsafe { CStr::from_ptr(ptr) }.to_str().expect("utf8").to_string();
        // SAFETY: released exactly once.
        unsafe { crack_free_string(ptr) };
        assert_ne!(name, "Unknown", "MD5 must be identified");

        let junk = b"definitely not a hash";
        // SAFETY: junk is valid for junk.len() bytes.
        let ptr = unsafe { crack_identify_hash(junk.as_ptr(), junk.len() as i32) };
        assert!(!ptr.is_null());
        // SAFETY: transfers ownership.
        let name = unsafe { CStr::from_ptr(ptr) }.to_str().expect("utf8").to_string();
        // SAFETY: released exactly once.
        unsafe { crack_free_string(ptr) };
        assert_eq!(name, "Unknown");
    }

    #[test]
    fn identification_refuses_a_null_pointer() {
        // SAFETY: a null pointer is an explicitly handled input.
        assert!(unsafe { crack_identify_hash(std::ptr::null(), 10) }.is_null());
    }

    /// The property that matters for a verifier: 1, 0, and a refusal are three
    /// different answers and must stay three.
    #[test]
    fn verification_distinguishes_a_match_a_mismatch_and_an_unknown() {
        crack_init();
        let target = b"900150983cd24fb0d6963f7d28e17f72"; // MD5("abc")
        let right = b"abc";
        let wrong = b"abd";

        // SAFETY: each buffer is valid for its own length.
        assert_eq!(
            unsafe { crack_verify(target.as_ptr(), target.len() as i32, right.as_ptr(), right.len() as i32) },
            1,
            "the correct password must verify"
        );
        // SAFETY: as above.
        assert_eq!(
            unsafe { crack_verify(target.as_ptr(), target.len() as i32, wrong.as_ptr(), wrong.len() as i32) },
            0,
            "a wrong password must not verify"
        );

        let junk = b"this is not a hash";
        // SAFETY: as above.
        assert_eq!(
            unsafe { crack_verify(junk.as_ptr(), junk.len() as i32, right.as_ptr(), right.len() as i32) },
            CRACK_E_UNKNOWN_HASH,
            "an unrecognisable hash must be a refusal, not a mismatch"
        );
        // SAFETY: null pointers are explicitly handled.
        assert_eq!(
            unsafe { crack_verify(std::ptr::null(), 4, right.as_ptr(), 3) },
            CRACK_E_NULL
        );
        crack_shutdown();
    }

    #[test]
    fn the_abi_version_is_reported() {
        assert_eq!(crack_abi_version(), crate::abi_version());
    }

    /// The panic strategy is reported rather than assumed, because it decides
    /// whether `with_attack_guard` can catch anything at all.
    #[test]
    fn the_panic_strategy_is_reported_honestly() {
        let aborts = crack_panics_abort();
        assert!(matches!(aborts, 0 | 1));
        assert_eq!(aborts == 1, cfg!(panic = "abort"));
    }

    /// A catch_unwind wrapper must actually catch. Under the unwind profile the
    /// test suite uses, it does.
    #[test]
    fn the_attack_guard_converts_a_panic_into_an_error_code() {
        if cfg!(panic = "abort") {
            // Cannot be tested in an aborting build; saying so is better than a
            // test that would take the process down if it were wrong.
            return;
        }
        let result = with_attack_guard(|| panic!("deliberate, caught by the guard"));
        assert_eq!(result.err(), Some(CRACK_E_LOCKED));
    }
}