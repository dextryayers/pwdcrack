//! SIMD-accelerated SHA-1 verification

use crate::dispatch::scalar_sha1_verify;

pub fn verify(password: &[u8], target_hex: &str) -> bool {
    scalar_sha1_verify(password, target_hex)
}
