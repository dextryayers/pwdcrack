//! ARM SVE (Scalable Vector Extension) — vector-length-agnostic multi-hash

use crate::dispatch::scalar_md5_verify;

pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}
