//! Intel XPU/oneAPI unified acceleration engine for pwdcrack.
//!
//! Provides XPU device detection, kernel compilation, and hash cracking.

pub mod device;
pub mod kernel;
pub mod cracker;
pub mod error;
