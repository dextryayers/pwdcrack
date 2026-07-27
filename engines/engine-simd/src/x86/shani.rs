use crate::dispatch::{scalar_sha256_verify, scalar_sha1_verify};

pub fn sha256_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_sha256_verify(password, target_hex)
}

pub fn sha1_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_sha1_verify(password, target_hex)
}

pub fn sha256_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords.iter().zip(targets).map(|(pw, t)| sha256_verify(pw, t)).collect()
}

pub fn sha1_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords.iter().zip(targets).map(|(pw, t)| sha1_verify(pw, t)).collect()
}
