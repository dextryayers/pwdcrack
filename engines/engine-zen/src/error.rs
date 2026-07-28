use std::fmt;

#[derive(Debug)]
pub enum ZenError {
    NoSupportedIsa,
    UnsupportedOperation(String),
    ExecutionFailed(String),
}

impl fmt::Display for ZenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZenError::NoSupportedIsa => write!(f, "No supported ISA (AVX2/AVX-512) found"),
            ZenError::UnsupportedOperation(op) => write!(f, "Unsupported operation: {}", op),
            ZenError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
        }
    }
}

impl std::error::Error for ZenError {}

pub type Result<T> = std::result::Result<T, ZenError>;
