use thiserror::Error;

#[derive(Error, Debug)]
pub enum SyclError {
    #[error("No SYCL platform found")] NoPlatform,
    #[error("No SYCL device found")] NoDevice,
    #[error("Kernel compilation failed: {0}")] CompileFailed(String),
    #[error("Kernel execution failed: {0}")] LaunchFailed(String),
    #[error("SYCL not available")] NotAvailable,
    #[error("Unsupported hash type")] UnsupportedHash,
}
