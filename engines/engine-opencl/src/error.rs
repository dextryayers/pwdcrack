use thiserror::Error;

#[derive(Error, Debug)]
pub enum OpenclError {
    #[error("No OpenCL platform found")] NoPlatform,
    #[error("No OpenCL device found")] NoDevice,
    #[error("OpenCL kernel compilation failed: {0}")] CompileFailed(String),
    #[error("OpenCL kernel execution failed: {0}")] LaunchFailed(String),
    #[error("OpenCL out of memory")] OutOfMemory,
    #[error("OpenCL not enabled at compile time (feature flag)")] NotEnabled,
    #[error("Unsupported hash type")] UnsupportedHash,
    #[error("OpenCL error: {0}")] Other(String),
}
