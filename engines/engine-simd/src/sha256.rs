use crate::dispatch;

pub fn verify(password: &[u8], target_hex: &str) -> bool {
    dispatch::sha256_verify(password, target_hex)
}
