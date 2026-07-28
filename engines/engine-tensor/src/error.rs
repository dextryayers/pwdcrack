use std::fmt;

#[derive(Debug)]
pub enum TensorError {
    ModelNotLoaded,
    ShapeMismatch(String),
    ExecutionFailed(String),
    UnsupportedOp(String),
}

impl fmt::Display for TensorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TensorError::ModelNotLoaded => write!(f, "Model not loaded"),
            TensorError::ShapeMismatch(msg) => write!(f, "Shape mismatch: {}", msg),
            TensorError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            TensorError::UnsupportedOp(op) => write!(f, "Unsupported operation: {}", op),
        }
    }
}

impl std::error::Error for TensorError {}

pub type Result<T> = std::result::Result<T, TensorError>;
