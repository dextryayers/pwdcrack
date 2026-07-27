//! C FFI exports for libcrack-core.so
//!
//! All functions are `extern "C"` with `#[unsafe(no_mangle)]`.
//! Error handling via return codes (never panic across FFI).

/// Initialize the crack engine
#[unsafe(no_mangle)]
pub extern "C" fn crack_init() -> i32 {
    0
}

/// Shutdown the crack engine
#[unsafe(no_mangle)]
pub extern "C" fn crack_shutdown() {}

/// Load hash file
#[unsafe(no_mangle)]
pub extern "C" fn hash_load_file(path: *const u8, len: i32) -> i32 {
    if path.is_null() { return -1; }
    let slice = unsafe { std::slice::from_raw_parts(path, len as usize) };
    let _path_str = String::from_utf8_lossy(slice);
    0
}

/// Start dictionary attack
#[unsafe(no_mangle)]
pub extern "C" fn attack_dictionary(
    _wordlist: *const u8,
    _wl_len: i32,
    _rules: *const u8,
    _rules_len: i32,
) -> i32 {
    0
}

/// Start brute-force attack
#[unsafe(no_mangle)]
pub extern "C" fn attack_bruteforce(
    _mask: *const u8,
    _mask_len: i32,
    _start: u64,
    _end: u64,
) -> i32 {
    0
}

/// Get number of cracked passwords
#[unsafe(no_mangle)]
pub extern "C" fn crack_found_count() -> i32 {
    0
}

/// Get hashes per second
#[unsafe(no_mangle)]
pub extern "C" fn crack_hashes_per_second() -> f64 {
    0.0
}
