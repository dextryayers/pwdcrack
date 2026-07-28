//! x86/x86_64 SIMD implementations
//!
//! Optimized hash verification using x86 SIMD extensions:
//! - SSE2: baseline (all x86_64 CPUs)
//! - SSE4.2: Nehalem+ (2008+)
//! - SHA-NI: SHA extensions (Goldmont+, Zen+)
//! - AVX2: Haswell+ (2013+)
//! - AVX-512: Skylake-X+ / Zen 4+

pub mod sse2;
pub mod sse42;
pub mod shani;
pub mod avx2;
pub mod avx512;

#[allow(dead_code)]
use crate::SimdLevel;
#[allow(dead_code)]
use crate::dispatch::{scalar_md5_verify, scalar_sha256_verify};

#[allow(dead_code)]
pub fn dispatch_md5(level: SimdLevel) -> fn(&[u8], &str) -> bool {
    match level {
        SimdLevel::Avx512 => avx512::md5_verify,
        SimdLevel::Avx2 => avx2::md5_verify,
        _ => scalar_md5_verify,
    }
}

#[allow(dead_code)]
pub fn dispatch_sha256(level: SimdLevel) -> fn(&[u8], &str) -> bool {
    match level {
        SimdLevel::ShaNi | SimdLevel::Avx2 | SimdLevel::Avx512 => shani::sha256_verify,
        _ => scalar_sha256_verify,
    }
}

