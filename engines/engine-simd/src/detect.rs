//! CPU feature detection for SIMD dispatch

use super::SimdLevel;

/// Detect best available SIMD level on current CPU
pub fn detect_simd_level() -> SimdLevel {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        return detect_x86();
    }

    #[cfg(target_arch = "aarch64")]
    {
        // All AArch64 CPUs have NEON
        if cfg!(target_feature = "sve") {
            return SimdLevel::Sve;
        }
        return SimdLevel::Neon64;
    }

    #[cfg(target_arch = "arm")]
    {
        if cfg!(target_feature = "neon") {
            return SimdLevel::Neon32;
        }
        return SimdLevel::Scalar;
    }

    #[cfg(not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm",
    )))]
    {
        SimdLevel::Scalar
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
fn detect_x86() -> SimdLevel {
    #[cfg(feature = "simd-detect")]
    {
        let cpuid = raw_cpuid::CpuId::new();

        // Extended features: AVX2, AVX-512, VAES
        if let Some(ext) = cpuid.get_extended_feature_info() {
            if ext.has_avx512f() && ext.has_vaes() {
                return SimdLevel::Vaes;
            }
            if ext.has_avx512f() {
                return SimdLevel::Avx512;
            }
            if ext.has_avx2() {
                return SimdLevel::Avx2;
            }
        }

        // Basic features: SSE4.2, SSE2
        if let Some(feats) = cpuid.get_feature_info() {
            if feats.has_sse42() {
                return SimdLevel::Sse42;
            }
            if feats.has_sse2() {
                return SimdLevel::Sse2;
            }
        }
    }

    // When simd-detect is disabled or detection fails:
    #[cfg(feature = "simd-avx512")]
    { return SimdLevel::Avx512; }

    #[cfg(feature = "simd-avx2")]
    { return SimdLevel::Avx2; }

    #[cfg(feature = "simd-sse2")]
    { return SimdLevel::Sse2; }

    #[cfg(feature = "simd-scalar")]
    { return SimdLevel::Scalar; }

    SimdLevel::Scalar
}

/// Human-readable SIMD feature summary
pub fn simd_summary() -> Vec<(&'static str, bool)> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        let cpuid = raw_cpuid::CpuId::new();
        let info = cpuid.get_feature_info();
        let ext = cpuid.get_extended_feature_info();

        vec![
            ("SSE2",      info.as_ref().map_or(false, |f| f.has_sse2())),
            ("SSE4.2",    info.as_ref().map_or(false, |f| f.has_sse42())),
            ("AVX2",      ext.as_ref().map_or(false, |f| f.has_avx2())),
            ("AVX-512F",  ext.as_ref().map_or(false, |f| f.has_avx512f())),
            ("VAES",      ext.as_ref().map_or(false, |f| f.has_vaes())),
            ("POPCNT",    info.as_ref().map_or(false, |f| f.has_popcnt())),
            ("AES-NI",    info.as_ref().map_or(false, |f| f.has_aesni())),
        ]
    }

    #[cfg(target_arch = "aarch64")]
    {
        vec![
            ("NEON", true),
            ("SVE", cfg!(target_feature = "sve")),
        ]
    }

    #[cfg(target_arch = "arm")]
    {
        vec![
            ("NEON", cfg!(target_feature = "neon")),
        ]
    }

    #[cfg(not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm",
    )))]
    {
        Vec::new()
    }
}
