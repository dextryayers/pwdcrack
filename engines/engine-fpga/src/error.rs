//! FPGA error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum FpgaError {
    #[error("FPGA device not found: {0}")]
    DeviceNotFound(String),

    #[error("PCIe DMA error: {0}")]
    DmaError(String),

    #[error("FPGA communication timeout")]
    Timeout,

    #[error("FPGA CRC mismatch — data corruption")]
    CrcMismatch,

    #[error("FPGA core not ready")]
    CoreNotReady,

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type FpgaResult<T> = Result<T, FpgaError>;
