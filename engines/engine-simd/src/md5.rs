//! SIMD-accelerated MD5 verification
//!
//! Provides multi-way MD5 verification using SIMD:
//! - AVX2: 8-way (256-bit)
//! - AVX-512: 16-way (512-bit)
//! - NEON: 4-way (128-bit)
//! - Scalar: 1-way (all platforms)

use crate::dispatch::scalar_md5_verify;

/// Verify MD5 — picks best available SIMD path
pub fn verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}
