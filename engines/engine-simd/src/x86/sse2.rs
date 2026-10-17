//! SSE2 hash verification.
//!
//! # Status: not implemented
//!
//! SSE2 is baseline on every x86_64 CPU, so this is the fallback for machines
//! without AVX2, mainly pre-2013 Intel and early AMD parts. A four lane MD5
//! kernel over `__m128i` would be the same code as [`super::avx2_md5`] with half
//! the lanes and 128 bit registers, so there is no structural obstacle.
//!
//! Nothing here is vectorised yet. Every function is a pass through to the
//! scalar implementation, and unlike the AVX2 case there is no multi-buffer
//! kernel to fall back to, so the honest description is "scalar with an SSE2
//! module name".

use crate::dispatch::scalar_md5_verify;

/// Whether SSE2 is available. Always true on x86_64, reported for symmetry with
/// the other feature predicates.
pub fn sse2_available() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        true
    }
    #[cfg(not(target_arch = "x86_64"))]
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