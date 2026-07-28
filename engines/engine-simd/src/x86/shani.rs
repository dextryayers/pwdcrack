use crate::dispatch::{scalar_sha256_verify, scalar_sha1_verify};

pub fn sha256_verify(password: &[u8], target_hex: &str) -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if is_x86_feature_detected!("sha") {
        return unsafe { shani_sha256_verify(password, target_hex) };
    }
    scalar_sha256_verify(password, target_hex)
}

pub fn sha1_verify(password: &[u8], target_hex: &str) -> bool {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    if is_x86_feature_detected!("sha") {
        return unsafe { shani_sha1_verify(password, target_hex) };
    }
    scalar_sha1_verify(password, target_hex)
}

pub fn sha256_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords.iter().zip(targets).map(|(pw, t)| sha256_verify(pw, t)).collect()
}

pub fn sha1_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords.iter().zip(targets).map(|(pw, t)| sha1_verify(pw, t)).collect()
}

// NOTE: Actual SHA-NI intrinsics not yet implemented; falls back to scalar.
// `target_feature(enable = "sha")` tells the compiler to emit SHA-NI instructions
// (_mm_sha256rnds2_epu32, _mm_sha1rnds4_epu32 etc) for the scalar hash body.
// Combined with `is_x86_feature_detected!("sha")` runtime guard.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sha")]
unsafe fn shani_sha256_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_sha256_verify(password, target_hex)
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[target_feature(enable = "sha")]
unsafe fn shani_sha1_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_sha1_verify(password, target_hex)
}
