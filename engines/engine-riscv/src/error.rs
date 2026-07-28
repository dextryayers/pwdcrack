use std::fmt;

#[derive(Debug)]
pub enum RiscvError {
    VectorUnitNotAvailable,
    UnsupportedExtension(String),
    ExecutionFailed(String),
}

impl fmt::Display for RiscvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiscvError::VectorUnitNotAvailable => write!(f, "RISC-V vector unit not available"),
            RiscvError::UnsupportedExtension(ext) => write!(f, "Unsupported extension: {}", ext),
            RiscvError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
        }
    }
}

impl std::error::Error for RiscvError {}

pub type Result<T> = std::result::Result<T, RiscvError>;
