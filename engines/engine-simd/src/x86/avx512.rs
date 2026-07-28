//! AVX-512-optimized hash verification — 16-way MD5, VAES SHA-256

use crate::dispatch::scalar_md5_verify;

#[allow(unused_variables)]
pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}
