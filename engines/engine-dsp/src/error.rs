use std::fmt;

#[derive(Debug)]
pub enum DspError {
    DeviceNotAvailable,
    ProgramLoadFailed(String),
    ExecutionFailed(String),
    UnsupportedFeature(String),
}

impl fmt::Display for DspError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DspError::DeviceNotAvailable => write!(f, "DSP device not available"),
            DspError::ProgramLoadFailed(msg) => write!(f, "Program load failed: {}", msg),
            DspError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            DspError::UnsupportedFeature(feat) => write!(f, "Unsupported feature: {}", feat),
        }
    }
}

impl std::error::Error for DspError {}

pub type Result<T> = std::result::Result<T, DspError>;
