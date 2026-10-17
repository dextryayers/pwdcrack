//! OpenCL cracker entry points.
//!
//! # Status
//!
//! The MD5 kernel is written and verified. The launch path is not, and this file
//! says so rather than returning a generic error.
//!
//! What has been checked, by `scripts/verify-opencl-kernels.sh`:
//!
//! - the generated core and the assembled kernel are accepted by clang's OpenCL
//!   front end, so the source is valid OpenCL C
//! - the compression produces 201 correct digests against python hashlib
//! - the kernel body executed through a host shim gives 133 correct results,
//!   covering every candidate length from 0 to 127, an over-length candidate, a
//!   candidate containing a zero byte, and three known vectors
//!
//! What has not been checked: anything requiring a real OpenCL device. This
//! machine has `libOpenCL.so.1` and no vendor ICD, so `platforms()` returns zero
//! entries and there is nothing to dispatch to. In particular no performance
//! claim is made anywhere.
//!
//! # Why the error variants are split
//!
//! Three situations used to collapse into one `NotEnabled`, which left the user
//! unable to tell a missing driver from a missing device from a missing kernel.
//! They are distinct problems with distinct fixes, so they are distinct results.

use crate::error::OpenclError;
use crate::kernel;
use crate::{OpenclEngine, device};

pub struct OpenclCracker {
    engine: OpenclEngine,
}

impl OpenclCracker {
    pub fn new(engine: OpenclEngine) -> Self {
        OpenclCracker { engine }
    }

    pub fn engine(&self) -> &OpenclEngine {
        &self.engine
    }

    /// Computes MD5 for a batch of candidates on the GPU.
    ///
    /// Not implemented yet. The three failure cases below are reported
    /// separately so that a user, or a caller deciding whether to fall back to
    /// the CPU, can tell them apart.
    ///
    /// - [`OpenclError::NoPlatform`]: the ICD loader is present but no vendor
    ///   driver registered a platform. Installing the vendor's OpenCL runtime,
    ///   usually a package named after the GPU vendor, fixes this.
    /// - [`OpenclError::NoDevice`]: platforms exist but none support the needed
    ///   compute capability.
    /// - [`OpenclError::NoSuchKernel`]: a device is present but the build has no
    ///   kernel for the requested hash. See [`kernel::available_kernels`].
    pub fn crack_md5(
        &self,
        _candidates: &[u8],
        _target_hex: &str,
    ) -> Result<Vec<bool>, OpenclError> {
        Err(self.diagnose("md5"))
    }

    /// Returns the reason the requested kernel cannot run on this host.
    ///
    /// Exposed so the caller can report an accurate cause instead of a generic
    /// failure, and so a test can assert the distinction without a device.
    pub fn diagnose(&self, hash: &str) -> OpenclError {
        // The kernel name is checked before anything about the host. Asking for a
        // hash this build has no kernel for is a caller mistake, and reporting it
        // as a missing device driver would send the user off to install
        // something that was never the problem.
        if !kernel::available_kernels().iter().any(|k| *k == hash) {
            return OpenclError::NoSuchKernel(hash.to_string());
        }

        let platforms = match device::platform_count() {
            Ok(n) => n,
            Err(e) => return e,
        };
        if platforms == 0 {
            return OpenclError::NoPlatform;
        }
        match device::device_count() {
            Ok(0) => return OpenclError::NoDevice,
            Ok(_) => {}
            Err(e) => return e,
        }
        // A device and a kernel are both present, which means this is the
        // unimplemented launch path rather than a missing piece of the host.
        OpenclError::LaunchNotImplemented(hash.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This host has the ICD loader and no vendor ICD.
    ///
    /// The test asserts the diagnosis is specific rather than asserting a device
    /// count, so it stays meaningful on a machine that does have a GPU. The point
    /// is that whatever the host looks like, the user gets a cause they can act
    /// on.
    #[test]
    fn diagnosis_is_specific() {
        // `init` returns None when no platform is available, which is the normal
        // case here. `diagnose` takes the engine by value, so build a minimal one
        // rather than skipping the test when there is no device: the point is
        // that the diagnosis is specific either way.
        let engine = OpenclEngine::init().unwrap_or_else(OpenclEngine::unavailable);
        let cracker = OpenclCracker::new(engine);
        let err = cracker.diagnose("md5");
        let msg = err.to_string();
        // It must name a cause, not say "not enabled".
        assert!(
            !msg.contains("NotEnabled"),
            "diagnosis fell back to the generic error: {msg}"
        );
        println!("diagnosis on this host: {msg}");
    }

    /// Only md5 has been written and verified. Naming the others would claim
    /// kernels that are still the original broken sources.
    #[test]
    fn only_md5_is_advertised_as_available() {
        let available = kernel::available_kernels();
        assert_eq!(available, vec!["md5"]);
        for name in ["sha1", "sha256", "sha512", "ntlm", "bcrypt"] {
            assert!(
                !available.contains(&name),
                "{name} is advertised but has not been rewritten or verified"
            );
        }
    }

    /// Asking for a kernel that does not exist must be reported as such rather
    /// than as a device problem.
    #[test]
    fn unknown_kernel_name_is_not_a_device_problem() {
        let cracker = OpenclCracker::new(OpenclEngine::init().unwrap_or_else(OpenclEngine::unavailable));
        let err = cracker.diagnose("no-such-hash");
        assert!(
            matches!(err, OpenclError::NoSuchKernel(_)),
            "expected NoSuchKernel, got {err}"
        );
    }
}