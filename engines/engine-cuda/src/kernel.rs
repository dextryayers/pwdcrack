//! Kernel loading and compilation.
//!
//! # Why this file does not embed `.cu` sources
//!
//! The previous version had `include_str!("kernels/md5.cu")` and passed the
//! result to `cudarc::ptx::compile_ptx`. That cannot work: `ptx::compile_ptx`
//! expects PTX assembly, which nvcc produces, and what the include gave it was
//! C++ source. Every call would have failed at the driver, and because the whole
//! path returned a single error variant the failure was indistinguishable from
//! "no CUDA device".
//!
//! The build script now runs nvcc once and embeds the resulting PTX through
//! `include_bytes!`, which is both the correct input and smaller than the source.
//!
//! # When there is no toolkit
//!
//! A build made with `PW_CUDA_ALLOW_NO_NVCC=1` has no PTX. Rather than pointing
//! at an empty string and failing deep inside the driver, [`ptx_for`] returns
//! `None` and the caller reports that the binary was built without kernels.

use crate::error::CudaError;

/// PTX for the MD5 kernel, produced by the build script.
///
/// Absent in a build made with `PW_CUDA_ALLOW_NO_NVCC=1`.
#[cfg(not(pw_cuda_no_ptx))]
pub const KERNEL_MD5_PTX: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/generated/md5.ptx"));

/// Compiles PTX for the compute capability of the actual device.
///
/// The build targets `compute_60` and the driver JITs upward, so one PTX serves
/// every architecture from Maxwell onward. Requesting a capability below the PTX
/// ISA version would fail, and cudarc surfaces that as a driver error rather than
/// silently producing wrong results.
pub fn compile_kernel(ptx: &[u8], arch: &str) -> Result<Vec<u8>, CudaError> {
    #[cfg(feature = "cuda")]
    {
        crate::compile_ptx(ptx, arch)
    }
    #[cfg(not(feature = "cuda"))]
    {
        let _ = (ptx, arch);
        Err(CudaError::NoCudaSupport)
    }
}

/// Returns the embedded PTX for a kernel name, or `None` when the binary was
/// built without a CUDA toolkit.
///
/// A missing PTX is a build configuration fact, not a runtime failure, so it is
/// reported as `None` and the caller decides what to do. Returning an error here
/// would conflate "this build has no kernels" with "the device is broken".
pub fn ptx_for(name: &str) -> Option<&'static [u8]> {
    match name {
        #[cfg(not(pw_cuda_no_ptx))]
        "md5" => Some(KERNEL_MD5_PTX),
        _ => None,
    }
}

/// Whether this binary carries any CUDA kernels at all.
///
/// False means the build used `PW_CUDA_ALLOW_NO_NVCC=1`. The distinction matters
/// because "no kernels in the binary" and "no GPU on this machine" look identical
/// to a user otherwise, and only the first is a property of the build.
pub fn kernels_embedded() -> bool {
    ptx_for("md5").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ptx_lookup_reports_build_configuration() {
        // Either outcome is legitimate, but it must be reported, not inferred
        // from a driver error later on.
        let embedded = kernels_embedded();
        if embedded {
            let ptx = ptx_for("md5").expect("reported embedded");
            assert!(!ptx.is_empty(), "embedded PTX is empty");
            // A real PTX module starts with a version directive. Checking that
            // the embedded bytes are PTX and not, say, C++ source is the one
            // check that would have caught the original include_str bug.
            let head = String::from_utf8_lossy(&ptx[..ptx.len().min(16)]);
            assert!(
                head.contains(".version"),
                "embedded bytes do not look like PTX, head was: {head:?}"
            );
        } else {
            assert!(cfg!(pw_cuda_no_ptx), "no PTX but the no-ptx cfg was not set");
            assert!(ptx_for("md5").is_none());
        }
    }

    #[test]
    fn unknown_kernel_name_is_none() {
        assert!(ptx_for("no-such-kernel").is_none());
    }

    #[test]
    fn kernels_that_have_no_verified_implementation_are_not_advertised() {
        // Only md5.cu has been rewritten and verified. The other files are still
        // the original broken sources, so naming them here would claim kernels
        // that do not work.
        for name in ["sha1", "sha256", "sha512", "ntlm", "bcrypt"] {
            assert!(
                ptx_for(name).is_none(),
                "{name} is advertised but has not been rewritten or verified"
            );
        }
    }
}