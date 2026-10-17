//! AVX-512 hash verification.
//!
//! # Status: not implemented
//!
//! AVX-512 gives sixteen 32 bit lanes per register against AVX2's eight, so the
//! same multi-buffer MD5 kernel would process sixteen candidates per pass. The
//! expected gain over the measured 2.3x of the AVX2 kernel is not sixteen
//! divided by eight: MD5 is 64 dependent steps, so widening the vectors does
//! not shorten the critical path. Real measurements are required before any
//! claim is made here, and there are none.
//!
//! Every function here is a pass through to the scalar implementation. The
//! working multi-buffer kernel is [`super::avx2_md5`].
//!
//! Note also that on many client parts AVX-512 causes frequency throttling, so
//! an AVX-512 kernel can be slower than the AVX2 one in wall clock terms even
//! when its instruction count is lower.

use crate::dispatch::scalar_md5_verify;

/// Whether AVX-512 Foundation is available.
pub fn avx512_available() -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        std::is_x86_feature_detected!("avx512f")
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