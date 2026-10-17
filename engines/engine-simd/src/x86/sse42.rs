//! SSE4.2 hash verification.
//!
//! # Status: not implemented
//!
//! SSE4.2 arrived with Nehalem in 2008 and is present on every mainstream CPU.
//! Its relevance to hashing is mostly negative for this crate: the instruction
//! set adds no hash primitives. SHA-NI is the extension that matters and it is
//! handled in [`super::shani`]. A four lane kernel here would duplicate the SSE2
//! work for no instruction set gain.
//!
//! Every function here is a pass through to the scalar implementation.

use crate::dispatch::scalar_md5_verify;

/// Whether SSE4.2 is available.
pub fn sse42_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("sse4.2")
    }
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        false
    }
}

/// MD5 verification. Falls through to the scalar implementation.
pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}

/// Batched MD5 verification.
pub fn md5_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords
        .iter()
        .zip(targets)
        .map(|(pw, t)| md5_verify(pw, t))
        .collect()
}