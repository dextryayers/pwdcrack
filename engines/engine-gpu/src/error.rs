//! GPU error types — never panic, always fallback gracefully

use thiserror::Error;

#[derive(Error, Debug)]
pub enum GpuError {
    #[error("No GPU adapter found")]
    NoAdapter,

    #[error("Failed to create device: {0}")]
    DeviceCreation(String),

    #[error("Shader compilation failed: {0}")]
    ShaderCompile(String),

    #[error("GPU out of memory")]
    OutOfMemory,

    #[error("Device lost — GPU crashed or reset")]
    DeviceLost,

    #[error("Operation timed out on GPU")]
    Timeout,

    #[error("SHA256 not implemented for this hash type on GPU")]
    UnsupportedHash,

    #[error("GPU error: {0}")]
    Other(String),
}

impl From<wgpu::Error> for GpuError {
    fn from(e: wgpu::Error) -> Self {
        GpuError::Other(e.to_string())
    }
}
