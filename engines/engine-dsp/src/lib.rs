//! Digital Signal Processor acceleration engine for pwdcrack.
//!
//! Provides DSP instruction execution and hash cracking for Hexagon and CEVA.

pub mod dsp;
pub mod instr;
pub mod cracker;
pub mod error;
