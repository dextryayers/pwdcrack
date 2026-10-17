//! ARM NEON on 32 bit ARM (ARMv7 and later).
//!
//! # Status: not implemented
//!
//! NEON gives four 32 bit lanes per `uint32x4_t`, so the kernel shape is the
//! same as the AVX2 one with a quarter of the lanes. ARMv7 is mostly present in
//! older phones and embedded boards now, so this path is low priority compared
//! with aarch64.
//!
//! Every function here is a pass through to the scalar implementation.

use crate::dispatch::scalar_md5_verify;

/// Whether NEON is available.
pub fn neon32_available() -> bool {
    #[cfg(target_arch = "arm")]
    {
        std::arch::is_arm_feature_detected!("neon")
    }
    #[cfg(not(target_arch = "arm"))]
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