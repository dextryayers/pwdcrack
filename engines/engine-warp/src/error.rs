use std::fmt;

#[derive(Debug)]
pub enum WarpError {
    KernelCompilationFailed(String),
    ExecutionFailed(String),
    InvalidWarpConfig(String),
}

impl fmt::Display for WarpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WarpError::KernelCompilationFailed(msg) => write!(f, "Kernel compilation failed: {}", msg),
            WarpError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            WarpError::InvalidWarpConfig(msg) => write!(f, "Invalid warp config: {}", msg),
        }
    }
}

impl std::error::Error for WarpError {}

pub type Result<T> = std::result::Result<T, WarpError>;
