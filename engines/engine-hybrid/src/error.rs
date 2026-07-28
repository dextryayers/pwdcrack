use std::fmt;

#[derive(Debug)]
pub enum HybridError {
    NoDevicesRegistered,
    ScheduleFailed(String),
    DeviceUnavailable(String),
    BalanceError(String),
}

impl fmt::Display for HybridError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HybridError::NoDevicesRegistered => write!(f, "No devices registered"),
            HybridError::ScheduleFailed(msg) => write!(f, "Schedule failed: {}", msg),
            HybridError::DeviceUnavailable(name) => write!(f, "Device unavailable: {}", name),
            HybridError::BalanceError(msg) => write!(f, "Balance error: {}", msg),
        }
    }
}

impl std::error::Error for HybridError {}

pub type Result<T> = std::result::Result<T, HybridError>;
