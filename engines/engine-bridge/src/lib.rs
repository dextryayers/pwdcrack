//! engine-bridge — FFI bridges to other languages
//!
//! - C FFI exports: libcrack-core.so (always built)
//! - Python bindings: PyO3 (feature "python")
//! - Perl bindings: XS (feature "perl")

pub mod c_api;

#[cfg(feature = "python")]
pub mod python;
