//! ARM SVE, the Scalable Vector Extension.
//!
//! # Status: not implemented
//!
//! SVE is the only ARM vector extension with a runtime selected lane count: a
//! single `svcntw()` gives between 128 and 2048 bits, so one kernel binary covers
//! every implementation. That is a real advantage over NEON, which has a fixed
//! four lanes, and over AVX-512, which has several incompatible subsets.
//!
//! The complication is that SVE is mostly found in server parts, notably
//! A64FX and the Neoverse V2, which matters for a password cracker only if the
//! cracking host is such a machine. There is no local hardware to test against,
//! and an untested SVE kernel would be exactly the kind of unverified hash this
//! crate refuses to ship.
//!
//! Every function here is a pass through to the scalar implementation.

use crate::dispatch::scalar_md5_verify;

/// Whether SVE is available. Requires `+sve`, so it is false in any default
/// build.
pub fn sve_available() -> bool {
    cfg!(target_feature = "sve")
}

/// MD5 verification. Falls through to the scalar implementation.
pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}

/// Batched MD5 verification.
pub fn md5_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords
        .iter()
        .zip(targets)
        .map(|(pw, t)| md5_verify(pw, t))
        .collect()
}