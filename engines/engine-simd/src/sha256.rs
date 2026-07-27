//! SIMD-accelerated SHA-256 verification

use crate::dispatch::scalar_sha256_verify;

pub fn verify(password: &[u8], target_hex: &str) -> bool {
    scalar_sha256_verify(password, target_hex)
}
