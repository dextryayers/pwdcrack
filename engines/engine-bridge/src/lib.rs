//! engine-bridge — FFI bridges to other languages
//!
//! - C FFI exports: libcrack-core.so
//! - Python bindings: PyO3 (maturin)
//! - Perl bindings: XS

pub mod c_api;

// The C API module is always compiled
// Python and Perl modules are separate packages
