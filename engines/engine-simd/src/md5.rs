use crate::dispatch;

pub fn verify(password: &[u8], target_hex: &str) -> bool {
    dispatch::md5_verify(password, target_hex)
}
