//! engine-simd — SIMD-accelerated hash verification
//!
//! Auto-detects CPU features and dispatches to optimal SIMD path:
//! - x86: SSE2 → SSE4.2 → AVX2 → AVX-512 (with VAES)
//! - ARM: NEON32 → NEON64 → SVE
//! - Fallback: scalar (pure Rust, works everywhere)

pub mod detect;
pub mod dispatch;
pub mod md5;
pub mod sha1;
pub mod sha256;
pub mod ntlm;

use std::sync::atomic::{AtomicU8, Ordering};
pub use dispatch::SimdLevel;

static CURRENT_SIMD: AtomicU8 = AtomicU8::new(0);

/// Initialize SIMD detection — call once at startup
pub fn init() {
    let level = detect::detect_simd_level();
    CURRENT_SIMD.store(level as u8, Ordering::Relaxed);
    log::info!("SIMD: {:?} detected", level);
}

/// Get current SIMD level
pub fn current_level() -> SimdLevel {
    match CURRENT_SIMD.load(Ordering::Relaxed) {
        0 => SimdLevel::Scalar,
        1 => SimdLevel::Sse2,
        2 => SimdLevel::Sse42,
        3 => SimdLevel::Avx2,
        4 => SimdLevel::Avx512,
        5 => SimdLevel::Vaes,
        6 => SimdLevel::Neon32,
        7 => SimdLevel::Neon64,
        8 => SimdLevel::Sve,
        _ => SimdLevel::Scalar,
    }
}
