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
    scalar_md5_verify(password, target_hex)
}

pub fn sha256_verify(password: &[u8], target_hex: &str) -> bool {
    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if crate::current_level() >= SimdLevel::ShaNi {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return crate::x86::shani::sha256_verify(password, target_hex);
    }
    #[cfg(any(target_arch = "aarch64", feature = "simd-neon64"))]
    if crate::current_level() >= SimdLevel::Neon64 {
        #[cfg(target_arch = "aarch64")]
        return crate::arm::neon64::sha256_verify(password, target_hex);
    }
    scalar_sha256_verify(password, target_hex)
}

pub fn sha1_verify(password: &[u8], target_hex: &str) -> bool {
    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if crate::current_level() >= SimdLevel::ShaNi {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return crate::x86::shani::sha1_verify(password, target_hex);
    }
    #[cfg(any(target_arch = "aarch64", feature = "simd-neon64"))]
    if crate::current_level() >= SimdLevel::Neon64 {
        #[cfg(target_arch = "aarch64")]
        return crate::arm::neon64::sha1_verify(password, target_hex);
    }
    scalar_sha1_verify(password, target_hex)
}

pub fn ntlm_verify(password: &[u8], target_hex: &str) -> bool {
    scalar_ntlm_verify(password, target_hex)
}

pub fn md5_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords.iter().zip(targets).map(|(pw, t)| md5_verify(pw, t)).collect()
}

pub fn sha256_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if crate::current_level() >= SimdLevel::ShaNi {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return crate::x86::shani::sha256_batch_verify(passwords, targets);
    }
    #[cfg(any(target_arch = "aarch64", feature = "simd-neon64"))]
    if crate::current_level() >= SimdLevel::Neon64 {
        #[cfg(target_arch = "aarch64")]
        return crate::arm::neon64::sha256_batch_verify(passwords, targets);
    }
    passwords.iter().zip(targets).map(|(pw, t)| scalar_sha256_verify(pw, t)).collect()
}

pub fn sha1_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    #[cfg(any(feature = "simd-avx2", feature = "simd-detect"))]
    if crate::current_level() >= SimdLevel::ShaNi {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        return crate::x86::shani::sha1_batch_verify(passwords, targets);
    }
    #[cfg(any(target_arch = "aarch64", feature = "simd-neon64"))]
    if crate::current_level() >= SimdLevel::Neon64 {
        #[cfg(target_arch = "aarch64")]
        return crate::arm::neon64::sha1_batch_verify(passwords, targets);
    }
    passwords.iter().zip(targets).map(|(pw, t)| scalar_sha1_verify(pw, t)).collect()
}

pub fn ntlm_batch_verify(passwords: &[&[u8]], targets: &[&str]) -> Vec<bool> {
    passwords.iter().zip(targets).map(|(pw, t)| ntlm_verify(pw, t)).collect()
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

pub fn scalar_ntlm_verify(password: &[u8], target_hex: &str) -> bool {
    use md4::{Md4, Digest};
    let utf16: Vec<u16> = password.iter().map(|&b| b as u16).collect();
    let mut bytes = Vec::with_capacity(utf16.len() * 2);
    for c in utf16 { bytes.extend_from_slice(&c.to_le_bytes()); }
    let mut hasher = Md4::new();
    hasher.update(&bytes);
    let result = hasher.finalize();
    let computed = hex::encode(result);
    computed.eq_ignore_ascii_case(target_hex)
}
