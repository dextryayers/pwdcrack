//! engine-bridge — FFI bridges to other languages
//!
//! - C FFI exports: libcrack-core.so (always built)
//! - Python bindings: PyO3 (feature "python")
//! - Perl bindings: XS (feature "perl")
//! - Node.js N-API (feature "node")
//! - Ruby FFI (feature "ruby")

pub mod c_api;

#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "node")]
pub mod node;

/// Version string for all bridges
pub const BRIDGE_VERSION: &str = "1.1.0";

/// Returns the ABI version for bridge compatibility checks
pub fn abi_version() -> u32 { 1 }
