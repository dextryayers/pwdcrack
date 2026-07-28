//! AMD Zen CPU optimization engine for pwdcrack.
//!
//! Provides AVX2/AVX-512 tuned hash cracking for AMD Zen architectures.

pub mod arch;
pub mod dispatch;
pub mod cracker;
pub mod error;
