pub mod detect;
pub mod dispatch;
pub mod md5;
pub mod sha1;
pub mod sha256;
pub mod ntlm;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub mod x86;

#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
pub mod arm;

use std::sync::atomic::{AtomicU8, Ordering};
pub use dispatch::SimdLevel;

static CURRENT_SIMD: AtomicU8 = AtomicU8::new(0);

pub fn init() {
    let level = detect::detect_simd_level();
    CURRENT_SIMD.store(level as u8, Ordering::Relaxed);
    log::info!("SIMD: {:?} detected", level);

    let summary = detect::simd_summary();
    for (name, present) in &summary {
        if *present {
            log::debug!("  ✓ {}", name);
        }
    }
}

pub fn current_level() -> SimdLevel {
    match CURRENT_SIMD.load(Ordering::Relaxed) {
        0 => SimdLevel::Scalar,
        1 => SimdLevel::Sse2,
        2 => SimdLevel::Sse42,
        3 => SimdLevel::ShaNi,
        4 => SimdLevel::Avx2,
        5 => SimdLevel::Avx512,
        6 => SimdLevel::Vaes,
        7 => SimdLevel::Neon32,
        8 => SimdLevel::Neon64,
        9 => SimdLevel::Sve,
        _ => SimdLevel::Scalar,
    }
}
