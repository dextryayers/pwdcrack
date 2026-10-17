//! Errors from the FPGA engine.
//!
//! Every variant names a distinct cause. The previous enum had a single
//! `CrcMismatch` carrying no detail and no variant for a bad version or a
//! malformed packet, so a caller could not tell corruption from an
//! incompatible device image from a programming error on the host.

use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq, Clone)]
pub enum FpgaError {
    /// No FPGA was found at the expected device node.
    #[error("FPGA device not found: {0}")]
    DeviceNotFound(String),

    /// A DMA transfer failed at the driver level.
    #[error("PCIe DMA error: {0}")]
    DmaError(String),

    /// The device did not respond within the deadline.
    ///
    /// Distinct from a protocol error: a timeout says nothing about whether the
    /// packet was well formed.
    #[error("FPGA communication timeout")]
    Timeout,

    /// The trailing checksum did not match the computed one.
    ///
    /// Carries both values. Which one was stated and which was computed is the
    /// difference between a device computing a different function and a packet
    /// being damaged in transit, and those need different investigations.
    #[error("CRC mismatch: device or packet stated {stated:#010x}, payload computes {computed:#010x}")]
    CrcMismatch { stated: u32, computed: u32 },

    /// The peer speaks a protocol revision this build does not.
    #[error("FPGA protocol version mismatch: peer sent {got}, this build speaks {expected}")]
    VersionMismatch { got: u16, expected: u16 },

    /// The packet is structurally invalid for a reason other than the checksum.
    #[error("invalid FPGA packet: {0}")]
    InvalidPacket(String),

    /// The requested core is not present in the device image.
    #[error("FPGA core '{0}' is not in the device image")]
    UnknownCore(String),

    /// The device replied, but not yet.
    #[error("FPGA core not ready")]
    CoreNotReady,

    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for FpgaError {
    fn from(e: std::io::Error) -> Self {
        FpgaError::Io(e.to_string())
    }
}

pub type FpgaResult<T> = Result<T, FpgaError>;