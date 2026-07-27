//! SIMD-accelerated NTLM verification

use md4::{Md4, Digest};

/// NTLM = MD4(UTF16-LE(password))
pub fn verify(password: &[u8], target_hex: &str) -> bool {
    let utf16: Vec<u16> = password.iter()
        .map(|&b| b as u16)
        .collect();
    let mut bytes = Vec::with_capacity(utf16.len() * 2);
    for c in utf16 {
        bytes.extend_from_slice(&c.to_le_bytes());
    }

    let mut hasher = Md4::new();
    hasher.update(&bytes);
    let result = hasher.finalize();
    let computed = hex::encode(result);
    computed.eq_ignore_ascii_case(target_hex)
}
