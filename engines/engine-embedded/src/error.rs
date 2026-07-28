use std::fmt;

#[derive(Debug)]
pub enum EmbeddedError {
    NoEngineAvailable,
    UnsupportedArchitecture(String),
    ExecutionFailed(String),
}

impl fmt::Display for EmbeddedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmbeddedError::NoEngineAvailable => write!(f, "No embedded acceleration engine available"),
            EmbeddedError::UnsupportedArchitecture(arch) => write!(f, "Unsupported architecture: {}", arch),
            EmbeddedError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
        }
    }
}

impl std::error::Error for EmbeddedError {}

pub type Result<T> = std::result::Result<T, EmbeddedError>;
