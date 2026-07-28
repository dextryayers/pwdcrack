//! Embedded system optimization engine for pwdcrack.
//!
//! Provides ARM NEON/MVE accelerated hash cracking for embedded systems.

pub mod neon;
pub mod mve;
pub mod cracker;
pub mod error;
