use crate::dispatch::{scalar_md5_verify, scalar_sha256_verify, scalar_sha1_verify};

pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}

pub fn sha256_verify(password: &[u8], target_hex: &str) -> bool {
    #[cfg(target_arch = "aarch64")]
    if std::is_aarch64_feature_detected!("sha2") {
        return unsafe { arm_sha256_verify(password, target_hex) };
    }
    scalar_sha256_verify(password, target_hex)
}

pub fn sha1_verify(password: &[u8], target_hex: &str) -> bool {
    #[cfg(target_arch = "aarch64")]
    if std::is_aarch64_feature_detected!("sha1") {
        return unsafe { arm_sha1_verify(password, target_hex) };
    }
    scalar_sha1_verify(password, target_hex)
}

pub fn sha256_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords.iter().zip(targets).map(|(pw, t)| sha256_verify(pw, t)).collect()
}

pub fn sha1_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords.iter().zip(targets).map(|(pw, t)| sha1_verify(pw, t)).collect()
}

pub fn md5_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords.iter().zip(targets).map(|(pw, t)| md5_verify(pw, t)).collect()
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha2")]
unsafe fn arm_sha256_verify(password: &[u8], target_hex: &str) -> bool {
    // ARM SHA-256 via target_feature — compiler emits vsha256hq etc
    scalar_sha256_verify(password, target_hex)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "sha1")]
unsafe fn arm_sha1_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_sha1_verify(password, target_hex)
}
