use thiserror::Error;

/// Errors from the OpenCL engine.
///
/// The variants are deliberately specific. A user who cannot run a kernel needs
/// to know whether the vendor driver is missing, whether there is no device,
/// whether the build has no such kernel, or whether the launch path is simply
/// not written yet. Those are four different problems and the previous enum
/// reported three of them as `NotEnabled`, which told the user nothing actionable.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum OpenclError {
    /// The ICD loader is present but no vendor driver registered a platform.
    ///
    /// Usually means the GPU vendor's OpenCL runtime package is not installed.
    #[error(
        "No OpenCL platform found. The ICD loader is present but no vendor driver \
         registered. On Linux install the package for your GPU vendor, usually \
         named after it (nvidia-opencl-icd, intel-opencl-icd, mesa-opencl-icd, \
         pocl-opencl-icd)."
    )]
    NoPlatform,

    /// Platforms exist but none exposes a usable compute device.
    #[error("OpenCL platforms are present but none exposes a usable compute device")]
    NoDevice,

    /// The ICD loader itself could not be reached.
    #[error("OpenCL runtime could not be loaded: {0}")]
    RuntimeUnavailable(String),

    /// Program source could not be built for the device.
    #[error("OpenCL kernel compilation failed: {0}")]
    CompileFailed(String),

    /// The kernel exists on this device but its build log contained an error.
    #[error("OpenCL kernel build failed for '{kernel}': {log}")]
    BuildFailed { kernel: String, log: String },

    /// The kernel was dispatched but execution reported an error.
    #[error("OpenCL kernel execution failed: {0}")]
    LaunchFailed(String),

    /// A buffer could not be allocated.
    #[error("OpenCL out of memory")]
    OutOfMemory,

    /// The build contains no kernel for this hash.
    #[error("No OpenCL kernel for '{0}' in this build")]
    NoSuchKernel(String),

    /// A device and a kernel are both available, but the launch path is not
    /// implemented.
    ///
    /// Separate from [`OpenclError::NoSuchKernel`] on purpose: here the kernel is
    /// present and correct, and what is missing is the code that submits it.
    #[error(
        "OpenCL kernel '{0}' is present and the host has a device, but the launch \
         path is not implemented. See docs/PHASE7_STATUS.md."
    )]
    LaunchNotImplemented(String),

    /// The engine was compiled without the `opencl` feature.
    #[error("OpenCL support was not compiled in (enable the 'opencl' feature)")]
    NotEnabled,

    /// A hash type this engine does not handle at all.
    #[error("Unsupported hash type for the OpenCL engine: {0}")]
    UnsupportedHash(String),

    /// Anything the OpenCL API reported that does not map above.
    #[error("OpenCL error: {0}")]
    Other(String),
}