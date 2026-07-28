use std::fmt;

#[derive(Debug)]
pub enum XpuError {
    DeviceNotAvailable,
    KernelCompilationFailed(String),
    ExecutionFailed(String),
    LevelZeroError(i32),
}

impl fmt::Display for XpuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XpuError::DeviceNotAvailable => write!(f, "XPU device not available"),
            XpuError::KernelCompilationFailed(msg) => write!(f, "Kernel compilation failed: {}", msg),
            XpuError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            XpuError::LevelZeroError(code) => write!(f, "Level Zero error: {}", code),
        }
    }
}

impl std::error::Error for XpuError {}

pub type Result<T> = std::result::Result<T, XpuError>;
