//! OpenCL kernel sources and lookup.
//!
//! The MD5 source is assembled at build time from two parts:
//!
//!   1. `engines/kernel-common/hash_core.cl`, generated from the shared header by
//!      `scripts/gen-opencl-core.py`
//!   2. the kernel entry point in `src/kernels/md5.cl`
//!
//! OpenCL C has no portable preprocessor include, so a shader cannot `#include`
//! anything. Concatenating at build time is what lets the CUDA and OpenCL engines
//! run the same verified compression code instead of two copies that drift.
//!
//! Only `md5` is listed. The other kernel files in this directory are still the
//! original sources, which used a four-entry constant table instead of the full
//! 64 and a fixed rotation of 7 for every step. They are deliberately not
//! reachable from [`get_kernel`], so nothing can dispatch to them.

use crate::error::OpenclError;

/// Assembled MD5 program source.
pub const CL_MD5: &str = include_str!("../../../target-generated/opencl/md5.cl");

/// Kernels this build can dispatch to, verified and reachable.
pub fn available_kernels() -> &'static [&'static str] {
    &["md5"]
}

/// Returns the program source for a kernel.
///
/// A name that is not in [`available_kernels`] is reported as
/// [`OpenclError::NoSuchKernel`] rather than as a generic lookup failure, so the
/// caller can tell "this build has no such kernel" from "the OpenCL runtime is
/// misconfigured".
pub fn get_kernel(name: &str) -> Result<&'static str, OpenclError> {
    let key = name.to_ascii_lowercase();
    if !available_kernels().contains(&key.as_str()) {
        return Err(OpenclError::NoSuchKernel(name.to_string()));
    }
    match key.as_str() {
        "md5" => Ok(CL_MD5),
        other => Err(OpenclError::NoSuchKernel(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md5_source_is_present_and_not_trivially_empty() {
        assert!(
            CL_MD5.len() > 1000,
            "assembled MD5 source is suspiciously short: {} bytes",
            CL_MD5.len()
        );
        assert!(CL_MD5.contains("md5_digest"), "kernel entry point missing");
    }

    #[test]
    fn assembled_source_carries_the_full_constant_table() {
        // The original .cl used four hand-picked round constants. A table that
        // starts with the real MD5 first constant and has 64 entries is the
        // check that the full table survived assembly.
        assert!(
            CL_MD5.contains("0xd76aa478"),
            "first MD5 round constant missing from the assembled source"
        );
        assert!(
            CL_MD5.contains("0xeb86d391"),
            "last MD5 round constant missing, so the 64 entry table is truncated"
        );
    }

    #[test]
    fn known_vectors_are_absent_from_kernel_source() {
        // Digest values belong in tests, not in the kernel. A digest inside the
        // shader source would be a hardcoded answer waiting to be mistaken for a
        // computed one.
        assert!(!CL_MD5.contains("5d41402abc4b2a76b9719d911017c592"));
    }

    #[test]
    fn lookup_reports_unknown_kernels_clearly() {
        assert_eq!(get_kernel("md5"), Ok(CL_MD5));
        assert_eq!(get_kernel("MD5"), Ok(CL_MD5));
        match get_kernel("sha1") {
            Err(OpenclError::NoSuchKernel(n)) => assert_eq!(n, "sha1"),
            other => panic!("expected NoSuchKernel, got {other:?}"),
        }
    }
}
