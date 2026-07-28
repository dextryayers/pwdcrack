//! ARM SIMD implementations
//!
//! Optimized hash verification using ARM NEON / SVE:
//! - NEON32: ARMv7 (32-bit ARM with NEON)
//! - NEON64: AArch64 (all 64-bit ARM CPUs)
//! - SVE: Scalable Vector Extension (ARMv8.2+)

pub mod neon32;
pub mod neon64;
pub mod sve;

#[allow(dead_code)]
use crate::SimdLevel;
#[allow(dead_code)]
use crate::dispatch::{scalar_md5_verify, scalar_sha256_verify};

#[allow(dead_code)]
pub fn dispatch_md5(level: SimdLevel) -> fn(&[u8], &str) -> bool {
    match level {
        SimdLevel::Sve | SimdLevel::Neon64 => neon64::md5_verify,
        SimdLevel::Neon32 => neon32::md5_verify,
        _ => scalar_md5_verify,
    }
}

#[allow(dead_code)]
pub fn dispatch_sha256(level: SimdLevel) -> fn(&[u8], &str) -> bool {
    match level {
        SimdLevel::Sve | SimdLevel::Neon64 => neon64::sha256_verify,
        _ => scalar_sha256_verify,
    }
}

