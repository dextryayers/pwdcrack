use thiserror::Error;

/// Errors from the Vulkan engine.
///
/// Specific variants, for the same reason the OpenCL ones are: "the shader is
/// broken", "the build has no compiler" and "no device" are three different
/// problems and reporting them all as one string leaves the user unable to act.
#[derive(Error, Debug, PartialEq, Eq)]
pub enum VulkanError {
    /// No Vulkan loader or no ICD, so no physical device could be enumerated.
    #[error(
        "No Vulkan device found. This machine has no Vulkan driver, or none is \
         visible to the loader. On Linux install a driver package (mesa-vulkan-drivers \
         for Intel and AMD, nvidia-driver for NVIDIA), and confirm with vulkaninfo."
    )]
    NoDevice,

    /// The loader exists but the physical device does not support compute.
    #[error("Vulkan device found but it does not support compute shaders")]
    NoComputeSupport,

    /// The build was made without the `vulkan` feature.
    #[error(
        "Vulkan support was not compiled in (enable the 'vulkan' feature). No \
         shader compiler is present in this build."
    )]
    FeatureDisabled,

    /// WGSL failed to parse, failed validation, or failed to emit SPIR-V.
    #[error("Vulkan shader compilation failed: {0}")]
    ShaderCompile(String),

    /// The emitted words are not a usable SPIR-V module.
    #[error("Invalid SPIR-V module: {0}")]
    InvalidSpirv(String),

    /// No kernel in this build for the requested hash.
    #[error("No Vulkan kernel for '{0}' in this build")]
    UnknownKernel(String),

    /// A pipeline could not be created.
    #[error("Vulkan pipeline creation failed: {0}")]
    PipelineFailed(String),

    /// A buffer could not be allocated.
    #[error("Vulkan buffer allocation failed: {0}")]
    AllocationFailed(String),

    /// The device ran out of memory.
    #[error("Vulkan device is out of memory")]
    OutOfMemory,

    /// The device ran the kernel but produced a wrong digest.
    ///
    /// Its own variant rather than a generic device error, because a digest
    /// mismatch means the GPU executed something and the answer was wrong, which
    /// is a different and more serious problem than a failure to run.
    #[error("Vulkan kernel produced {count} wrong digest(s): {detail}")]
    DigestMismatch { count: usize, detail: String },

    /// The device reported a problem during dispatch or readback.
    #[error("Vulkan device error: {0}")]
    DeviceError(String),
}