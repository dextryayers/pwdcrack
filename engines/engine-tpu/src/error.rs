use std::fmt;

#[derive(Debug)]
pub enum TpuError {
    DeviceNotAvailable,
    ModelLoadFailed(String),
    InferenceFailed(String),
    UnsupportedOperation(String),
}

impl fmt::Display for TpuError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpuError::DeviceNotAvailable => write!(f, "TPU device not available"),
            TpuError::ModelLoadFailed(msg) => write!(f, "Model load failed: {}", msg),
            TpuError::InferenceFailed(msg) => write!(f, "Inference failed: {}", msg),
            TpuError::UnsupportedOperation(op) => write!(f, "Unsupported operation: {}", op),
        }
    }
}

impl std::error::Error for TpuError {}

pub type Result<T> = std::result::Result<T, TpuError>;
