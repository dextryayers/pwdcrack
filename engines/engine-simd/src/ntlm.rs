use crate::dispatch;

pub fn verify(password: &[u8], target_hex: &str) -> bool {
    dispatch::ntlm_verify(password, target_hex)
}
