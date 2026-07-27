#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum SimdLevel {
    Scalar  = 0,
    Sse2    = 1,
    Sse42   = 2,
    ShaNi   = 3,
    Avx2    = 4,
    Avx512  = 5,
    Vaes    = 6,
    Neon32  = 7,
    Neon64  = 8,
    Sve     = 9,
}

pub fn md5_verify(password: &[u8], target_hex: &str) -> bool {
    let level = crate::current_level();

    #[cfg(any(feature = "simd-avx512", feature = "simd-detect"))]
    if level >= SimdLevel::Avx512 {
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

    scalar_md5_verify(password, target_hex)
}

pub fn sha256_verify(password: &[u8], target_hex: &str) -> bool {
    let level = crate::current_level();

    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if level >= SimdLevel::ShaNi {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return crate::x86::shani::sha256_verify(password, target_hex);
    }

    scalar_sha256_verify(password, target_hex)
}

pub fn sha1_verify(password: &[u8], target_hex: &str) -> bool {
    let level = crate::current_level();

    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if level >= SimdLevel::ShaNi {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return crate::x86::shani::sha1_verify(password, target_hex);
    }

    scalar_sha1_verify(password, target_hex)
}

pub fn sha256_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if crate::current_level() >= SimdLevel::ShaNi {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return crate::x86::shani::sha256_batch_verify(passwords, targets);
    }
    passwords.iter().zip(targets).map(|(pw, t)| scalar_sha256_verify(pw, t)).collect()
}

pub fn sha1_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if crate::current_level() >= SimdLevel::ShaNi {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return crate::x86::shani::sha1_batch_verify(passwords, targets);
    }
    passwords.iter().zip(targets).map(|(pw, t)| scalar_sha1_verify(pw, t)).collect()
}

// Scalar fallbacks
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

// SIMD multi-hash stubs
#[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
fn avx2_md5_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}

#[cfg(any(feature = "simd-avx512", feature = "simd-detect"))]
fn avx512_md5_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}

#[cfg(any(feature = "simd-neon64", feature = "simd-detect"))]
fn neon_md5_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_md5_verify(password, target_hex)
}
