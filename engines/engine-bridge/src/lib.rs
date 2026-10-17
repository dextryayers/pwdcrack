//! engine-bridge: FFI bridges to other languages
//!
//! - C FFI exports: libcrack-core.so (always built)
//! - Python bindings: PyO3 (feature "python")
//! - Perl bindings: XS (feature "perl")
//! - Node.js N-API (feature "node")
//!
//! There is no Ruby binding. One used to be promised by a `ruby` feature that
//! had no module behind it, so `--features ruby` built the same library as no
//! features at all.

pub mod c_api;

#[cfg(feature = "python")]
pub mod python;

#[cfg(feature = "node")]
pub mod node;

/// Version of the wrapped library, for every bridge.
///
/// Derived rather than written down. The constant said "1.1.0" while
/// `pwdcrack` was 1.2.0, so a C or Python caller comparing versions got an
/// answer about a release that no longer existed.
pub const BRIDGE_VERSION: &str = pwdcrack::VERSION;

/// Returns the ABI version for bridge compatibility checks
pub fn abi_version() -> u32 { 1 }
