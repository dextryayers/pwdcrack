//! AArch64 dispatch.
//!
//! # Status: not implemented
//!
//! AArch64 has the ARMv8 cryptographic extensions, two instructions
//! `vsha256hq_u32` and `vsha256h2q_u32` for SHA-256 and the equivalent pair for
//! SHA-1. They operate on four 32 bit lanes, so a real implementation is a
//! four lane multi-buffer kernel in the same shape as
//! [`crate::x86::avx2_md5`].
//!
//! Everything below is a pass through to the scalar implementation.
//!
//! # Why `target_feature` alone is not enough
//!
//! An earlier version of this file wrapped the scalar calls in
//! `#[target_feature(enable = "sha2")]` and claimed the compiler would emit the
//! ARM hash instructions for them. That claim is wrong. The attribute declares
//! that the caller guarantees the feature is present, which is what lets
//! intrinsics such as `vsha256hq_u32` compile. It does not vectorise scalar code
//! and it does not introduce instructions the source never mentions.

use crate::dispatch::{scalar_md5_verify, scalar_sha1_verify, scalar_sha256_verify};

/// Whether the host reports the ARMv8 SHA-256 instructions.
#[cfg(target_arch = "aarch64")]
pub fn arm_sha256_available() -> bool {
    std::arch::is_aarch64_feature_detected!("sha2")
}

/// Whether the host reports the ARMv8 SHA-1 instructions.
#[cfg(target_arch = "aarch64")]
pub fn arm_sha1_available() -> bool {
    std::arch::is_aarch64_feature_detected!("sha1")
}

/// MD5 verification. Falls through to the scalar implementation.
pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}

/// SHA-256 verification. Falls through to the scalar implementation.
pub fn sha256_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_sha256_verify(password, target_hex)
}

/// SHA-1 verification. Falls through to the scalar implementation.
pub fn sha1_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_sha1_verify(password, target_hex)
}

/// Batched SHA-256 verification.
pub fn sha256_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords
        .iter()
        .zip(targets)
        .map(|(pw, t)| sha256_verify(pw, t))
        .collect()
}

/// Batched SHA-1 verification.
pub fn sha1_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords
        .iter()
        .zip(targets)
        .map(|(pw, t)| sha1_verify(pw, t))
        .collect()
}

/// Batched MD5 verification.
pub fn md5_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords
        .iter()
        .zip(targets)
        .map(|(pw, t)| md5_verify(pw, t))
        .collect()
}