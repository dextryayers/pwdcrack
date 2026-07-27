//! C FFI exports for libcrack-core.so
//!
//! When compiled as part of pwdcrack binary (feature "engine-bridge"),
//! these functions provide access to the Rust cracking engine.
//! When compiled standalone, returns stubs.

#[unsafe(no_mangle)]
pub extern "C" fn crack_init() -> i32 {
    #[cfg(feature = "integrated")]
    {
        // Initialize global engine state
        return 0;
    }
    #[cfg(not(feature = "integrated"))]
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn crack_shutdown() {
}

#[unsafe(no_mangle)]
pub extern "C" fn hash_load_file(path: *const u8, len: i32) -> i32 {
    if path.is_null() || len <= 0 {
        return -1;
    }
    let _slice = unsafe { std::slice::from_raw_parts(path, len as usize) };
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn attack_dictionary(
    _wordlist: *const u8,
    _wl_len: i32,
    _rules: *const u8,
    _rules_len: i32,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn attack_bruteforce(
    _mask: *const u8,
    _mask_len: i32,
    _start: u64,
    _end: u64,
) -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn crack_found_count() -> i32 {
    0
}

#[unsafe(no_mangle)]
pub extern "C" fn crack_hashes_per_second() -> f64 {
    0.0
}

#[unsafe(no_mangle)]
pub extern "C" fn crack_get_result(idx: i32, out_buf: *mut u8, out_len: *mut i32) -> i32 {
    if idx < 0 { return -1; }
    let _buf = unsafe { std::slice::from_raw_parts_mut(out_buf, *out_len as usize) };
    -1
}
