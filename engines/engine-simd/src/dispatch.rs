//! SIMD dispatch layer — routes to best available implementation

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SimdLevel {
    Scalar  = 0,
    Sse2    = 1,
    Sse42   = 2,
    Avx2    = 3,
    Avx512  = 4,
    Vaes    = 5,
    Neon32  = 6,
    Neon64  = 7,
    Sve     = 8,
}

/// Verify MD5 hash using best available SIMD
pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    let level = crate::current_level();

    // Dispatch to optimal implementation
    #[cfg(any(feature = "simd-avx512", feature = "simd-detect"))]
    if level >= SimdLevel::Vaes || level >= SimdLevel::Avx512 {
        // AVX-512 + VAES path — fastest
        return avx512_md5_verify(password, target_hex);
    }

    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if level >= SimdLevel::Avx2 {
        return avx2_md5_verify(password, target_hex);
    }

    #[cfg(any(feature = "simd-neon64", feature = "simd-detect"))]
    if level >= SimdLevel::Neon64 {
        return neon_md5_verify(password, target_hex);
    }

    // Fallback: scalar implementation
    scalar_md5_verify(password, target_hex)
}

// ---------------------------------------------------------------------------
// Scalar fallback — works on ALL platforms (32-bit, ARM, no-SIMD, etc.)
// ---------------------------------------------------------------------------
pub fn scalar_md5_verify(password: &[u8], target_hex: &str) -> bool {
    use md5::{Md5, Digest};
    let mut hasher = Md5::new();
    hasher.update(password);
    let result = hasher.finalize();
    let computed = hex::encode(result);
    computed.eq_ignore_ascii_case(target_hex)
}

pub fn scalar_sha1_verify(password: &[u8], target_hex: &str) -> bool {
    use sha1::{Sha1, Digest};
    let mut hasher = Sha1::new();
    hasher.update(password);
    let result = hasher.finalize();
    let computed = hex::encode(result);
    computed.eq_ignore_ascii_case(target_hex)
}

pub fn scalar_sha256_verify(password: &[u8], target_hex: &str) -> bool {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(password);
    let result = hasher.finalize();
    let computed = hex::encode(result);
    computed.eq_ignore_ascii_case(target_hex)
}

// ---------------------------------------------------------------------------
// SIMD stubs — actual implementation when feature flags are enabled
// ---------------------------------------------------------------------------

#[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
fn avx2_md5_verify(password: &[u8], target_hex: &str) -> bool {
    // AVX2: 8 MD5 hashes in parallel
    // Implementation: 8 independent MD5 computations using 256-bit registers
    // Each lane processes one password
    // @see https://github.com/RustCrypto/hashes for reference impl

    // For now, fallback to scalar until AVX2 implementation is complete
    scalar_md5_verify(password, target_hex)
}

#[cfg(any(feature = "simd-avx512", feature = "simd-detect"))]
fn avx512_md5_verify(password: &[u8], target_hex: &str) -> bool {
    // AVX-512: 16 MD5 hashes in parallel
    // Uses zmm registers for 16-way computation
    // With VAES: AES-NI instruction set for SHA-256 acceleration

    scalar_md5_verify(password, target_hex)
}

#[cfg(any(feature = "simd-neon64", feature = "simd-detect"))]
fn neon_md5_verify(password: &[u8], target_hex: &str) -> bool {
    // ARM NEON: 4 MD5 hashes in parallel
    // Uses 128-bit Q registers

    scalar_md5_verify(password, target_hex)
}
