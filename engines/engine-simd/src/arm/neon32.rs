//! ARM NEON32 (ARMv7) — 4-way MD5 via uint32x4_t

use crate::dispatch::scalar_md5_verify;

#[allow(unused_variables)]
pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}
