//! SHA extensions (SHA-NI) dispatch for x86 and x86_64.
//!
//! # Status: not implemented
//!
//! The SHA extension was introduced with Goldmont and is present on most Zen
//! cores and every Ice Lake and later part. It contains fixed function
//! instructions for exactly the two round primitives SHA-1 and SHA-256 need,
//! `_mm_sha1rnds4_epu32` and `_mm_sha256rnds2_epu32`, so a real implementation is
//! a multi-buffer kernel in the same shape as [`crate::x86::avx2_md5`], using
//! four and two lanes respectively.
//!
//! Nothing here uses those instructions yet. Every function below is a
//! documented pass through to the scalar implementation.
//!
//! # Why `target_feature` alone is not enough
//!
//! An earlier version of this file wrapped the scalar calls in
//! `#[target_feature(enable = "sha")]` and claimed the compiler would emit
//! SHA-NI for them. That claim is wrong. The attribute only declares that the
//! *caller* guarantees the feature is present, which is what lets intrinsics
//! such as `_mm_sha256rnds2_epu32` compile at all. It does not vectorise scalar
//! code and it does not introduce instructions the source never mentions. A
//! function that only calls into a digest library will keep calling into that
//! library, whatever features are enabled, so the attribute bought nothing but
//! the runtime check that guards it.

use crate::dispatch::{scalar_sha1_verify, scalar_sha256_verify};

/// Whether the host reports the SHA extension.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub fn shani_available() -> bool {
    std::is_x86_feature_detected!("sha")
}

/// SHA-256 verification. Falls through to the scalar implementation.
pub fn sha256_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_sha256_verify(password, target_hex)
}

/// SHA-1 verification. Falls through to the scalar implementation.
pub fn sha1_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_sha1_verify(password, target_hex)
}

/// Batched SHA-256 verification.
pub fn sha256_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords
        .iter()
        .zip(targets)
        .map(|(pw, t)| sha256_verify(pw, t))
        .collect()
}

/// Batched SHA-1 verification.
pub fn sha1_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords
        .iter()
        .zip(targets)
        .map(|(pw, t)| sha1_verify(pw, t))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::Sha1;
    use sha2::Sha256;
    use sha2::digest::Digest as _;

    #[test]
    fn sha256_verify_agrees_with_the_digest_crate() {
        let mut h = Sha256::new();
        h.update(b"correct horse battery staple");
        let d = hex::encode(h.finalize());
        assert!(sha256_verify(b"correct horse battery staple", &d));
        assert!(!sha256_verify(b"Correct horse battery staple", &d));
    }

    #[test]
    fn sha1_verify_agrees_with_the_digest_crate() {
        let mut h = Sha1::new();
        h.update(b"correct horse battery staple");
        let d = hex::encode(h.finalize());
        assert!(sha1_verify(b"correct horse battery staple", &d));
        assert!(!sha1_verify(b"correct horse battery stapl", &d));
    }

    #[test]
    fn batch_results_match_single_results() {
        let inputs: Vec<Vec<u8>> = (0..16u8).map(|i| format!("candidate{i}").into_bytes()).collect();
        let refs: Vec<&[u8]> = inputs.iter().map(|m| m.as_slice()).collect();
        let mut targets = Vec::new();
        for m in &inputs {
            let mut h = Sha256::new();
            h.update(m);
            targets.push(hex::encode(h.finalize()));
        }
        let target_refs: Vec<&str> = targets.iter().map(|s| s.as_str()).collect();
        assert_eq!(
            sha256_batch_verify(&refs, &target_refs),
            refs.iter().zip(target_refs.iter()).map(|(p, t)| sha256_verify(p, t)).collect::<Vec<_>>()
        );
    }
}