//! SSE4.2-optimized hash verification

use crate::dispatch::scalar_md5_verify;

#[allow(unused_variables)]
pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}
