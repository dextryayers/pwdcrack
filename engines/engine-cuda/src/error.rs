use thiserror::Error;

#[derive(Error, Debug)]
pub enum CudaError {
    #[error("No CUDA-capable GPU found")] NoDevice,
    #[error("Failed to initialize CUDA driver: {0}")] InitFailed(String),
    #[error("CUDA kernel compilation failed: {0}")] CompileFailed(String),
    #[error("CUDA kernel launch failed: {0}")] LaunchFailed(String),
    #[error("CUDA out of memory")] OutOfMemory,
    #[error("No CUDA support at compile time (feature not enabled)")] NoCudaSupport,
    #[error("I/O error: {0}")] Io(#[from] std::io::Error),
    #[error("Unsupported hash type for CUDA kernel")] UnsupportedHash,
}

impl From<String> for CudaError {
    fn from(s: String) -> Self { CudaError::InitFailed(s) }
}
