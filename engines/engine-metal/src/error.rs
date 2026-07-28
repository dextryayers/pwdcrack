use std::fmt;

#[derive(Debug)]
pub enum MetalError {
    DeviceNotFound,
    ShaderCompilationFailed(String),
    ExecutionFailed(String),
    UnsupportedOS,
}

impl fmt::Display for MetalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetalError::DeviceNotFound => write!(f, "Metal device not found"),
            MetalError::ShaderCompilationFailed(msg) => write!(f, "Shader compilation failed: {}", msg),
            MetalError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            MetalError::UnsupportedOS => write!(f, "Metal is only supported on macOS/iOS"),
        }
    }
}

impl std::error::Error for MetalError {}

pub type Result<T> = std::result::Result<T, MetalError>;
