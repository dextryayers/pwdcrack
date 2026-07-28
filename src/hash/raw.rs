use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256, Digest as Sha2Digest};
use sha1::Sha1;
use md5::Md5;
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use blake2::{Blake2b, Blake2b512, Blake2s256, Blake2s};
use ripemd::{Ripemd128, Ripemd160, Ripemd256, Ripemd320};
use whirlpool::Whirlpool;
use streebog::{Streebog256, Streebog512};
use jh::{Jh224, Jh256, Jh384, Jh512};
use skein::{Skein256, Skein512};
use shabal::{Shabal192, Shabal224, Shabal256, Shabal384, Shabal512};
use gost94::Gost94CryptoPro;
use des::Des;
use cipher::{KeyInit, BlockCipherEncrypt, Array};

use super::{HashCracker, HashEntry, HashType, HashParser};

macro_rules! impl_raw_hash {
    ($name:ident, $hash_type:expr, $digest:ty, $bit_len:expr) => {
        /// Hash cracker and parser for a raw hex-encoded hash type.
        pub struct $name;

        impl HashCracker for $name {
            fn hash_type(&self) -> HashType { $hash_type }
            fn name(&self) -> &'static str { stringify!($name) }

            fn verify(&self, password: &str, entry: &HashEntry) -> bool {
                let mut hasher = <$digest>::new();
                hasher.update(password.as_bytes());
                let result = hasher.finalize();
                let computed = hex::encode(result);
                computed.eq_ignore_ascii_case(&entry.raw)
            }

            fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
        }

        impl HashParser for $name {
            fn parse(&self, line: &str) -> Option<HashEntry> {
                let trimmed = line.trim();
                if trimmed.len() != $bit_len / 4 { return None; }
                if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
                let bytes = hex::decode(trimmed).ok()?;
                Some(HashEntry {
                    raw: trimmed.to_lowercase(),
                    hash_type: $hash_type,
                    hash_bytes: bytes,
                    salt: None,
                    username: None,
                    cracked: false,
                    password: None,
                })
            }

            fn can_parse(&self, line: &str) -> bool {
                let trimmed = line.trim();
                trimmed.len() == $bit_len / 4
                    && trimmed.chars().all(|c| c.is_ascii_hexdigit())
            }
        }
    };
}

impl_raw_hash!(Md5Hash, HashType::MD5, Md5, 128);
impl_raw_hash!(Sha1Hash, HashType::SHA1, Sha1, 160);
impl_raw_hash!(Sha224Hash, HashType::SHA224, Sha224, 224);
impl_raw_hash!(Sha256Hash, HashType::SHA256, Sha256, 256);
impl_raw_hash!(Sha384Hash, HashType::SHA384, Sha384, 384);
impl_raw_hash!(Sha512Hash, HashType::SHA512, Sha512, 512);
impl_raw_hash!(Sha3_512Hash, HashType::SHA3512, Sha3_512, 512);
impl_raw_hash!(Blake2b256Hash, HashType::BLAKE2B256, Blake2b<digest::consts::U32>, 256);
impl_raw_hash!(Blake2s256Hash, HashType::BLAKE2S256, Blake2s256, 256);
impl_raw_hash!(Blake2b512Hash, HashType::BLAKE2B512, Blake2b512, 512);
impl_raw_hash!(Ripemd128Hash, HashType::RIPEMD128, Ripemd128, 128);
impl_raw_hash!(Ripemd160Hash, HashType::RIPEMD160, Ripemd160, 160);
impl_raw_hash!(Ripemd256Hash, HashType::RIPEMD256, Ripemd256, 256);
impl_raw_hash!(Ripemd320Hash, HashType::RIPEMD320, Ripemd320, 320);
impl_raw_hash!(Sha3_224Hash, HashType::SHA3224, Sha3_224, 224);
impl_raw_hash!(Sha3_256Hash, HashType::SHA3256, Sha3_256, 256);
impl_raw_hash!(Sha3_384Hash, HashType::SHA3384, Sha3_384, 384);
impl_raw_hash!(Sha512_224Hash, HashType::SHA512_224, Sha512_224, 224);
impl_raw_hash!(Sha512_256Hash, HashType::SHA512_256, Sha512_256, 256);
impl_raw_hash!(WhirlpoolHash, HashType::WHIRLPOOL, Whirlpool, 512);
impl_raw_hash!(Streebog256Hash, HashType::STREEBOG256, Streebog256, 256);
impl_raw_hash!(Streebog512Hash, HashType::STREEBOG512, Streebog512, 512);
pub struct Tiger192Hash;

impl HashCracker for Tiger192Hash {
    fn hash_type(&self) -> HashType { HashType::TIGER192 }
    fn name(&self) -> &'static str { "Tiger-192" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        use tiger::digest::Digest;
        let mut hasher = tiger::Tiger::new();
        hasher.update(password.as_bytes());
        let result = hasher.finalize();
        let computed = hex::encode(result);
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Tiger192Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let trimmed = line.trim();
        if trimmed.len() != 48 { return None; }
        if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        let bytes = hex::decode(trimmed).ok()?;
        Some(HashEntry {
            raw: trimmed.to_lowercase(),
            hash_type: HashType::TIGER192,
            hash_bytes: bytes,
            salt: None,
            username: None,
            cracked: false,
            password: None,
        })
    }
    fn can_parse(&self, line: &str) -> bool {
        let trimmed = line.trim();
        trimmed.len() == 48 && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    }
}
impl_raw_hash!(Jh224Hash, HashType::JH224, Jh224, 224);
impl_raw_hash!(Jh256Hash, HashType::JH256, Jh256, 256);
impl_raw_hash!(Jh384Hash, HashType::JH384, Jh384, 384);
impl_raw_hash!(Jh512Hash, HashType::JH512, Jh512, 512);
impl_raw_hash!(Skein256Hash, HashType::SKEIN256, Skein256, 256);
impl_raw_hash!(Skein512Hash, HashType::SKEIN512, Skein512, 512);
impl_raw_hash!(Shabal192Hash, HashType::SHABAL192, Shabal192, 192);
impl_raw_hash!(Shabal224Hash, HashType::SHABAL224, Shabal224, 224);
impl_raw_hash!(Shabal256Hash, HashType::SHABAL256, Shabal256, 256);
impl_raw_hash!(Shabal384Hash, HashType::SHABAL384, Shabal384, 384);
impl_raw_hash!(Shabal512Hash, HashType::SHABAL512, Shabal512, 512);
impl_raw_hash!(Gost94CryptoProHash, HashType::GOST94256, Gost94CryptoPro, 256);

// GOST94-512 (GOST R 34.11-94 512-bit variant — detection only, no Rust digest)
pub struct Gost94_512Hash;
impl HashCracker for Gost94_512Hash {
    fn hash_type(&self) -> HashType { HashType::GOST94512 }
    fn name(&self) -> &'static str { "GOST94-512" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}
impl HashParser for Gost94_512Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() != 128 || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::GOST94512,
            hash_bytes: hex::decode(t).ok()?, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim(); t.len() == 128 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

impl_raw_hash!(Blake2b384Hash, HashType::BLAKE2B384, Blake2b<digest::consts::U48>, 384);
impl_raw_hash!(Blake2b224Hash, HashType::BLAKE2B224, Blake2b<digest::consts::U28>, 224);
impl_raw_hash!(Blake2b160Hash, HashType::BLAKE2B160, Blake2b<digest::consts::U20>, 160);
impl_raw_hash!(Blake2s128Hash, HashType::BLAKE2S128, Blake2s<digest::consts::U16>, 128);
impl_raw_hash!(Blake2s160Hash, HashType::BLAKE2S160, Blake2s<digest::consts::U20>, 160);

/// Cracker and parser for NTLM hashes (MD4, 32 hex chars).
pub struct NtlmHash;

impl HashCracker for NtlmHash {
    fn hash_type(&self) -> HashType { HashType::NTLM }
    fn name(&self) -> &'static str { "NTLM" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        use md4::Md4;
        use md4::Digest;
        let mut hasher = Md4::new();
        let utf16: Vec<u16> = password.encode_utf16().collect();
        let bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let computed = hex::encode(result);
        computed.eq_ignore_ascii_case(&entry.raw)
    }

    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for NtlmHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let trimmed = line.trim();

        if let Some(rest) = trimmed.strip_prefix("$NT$") {
            if rest.len() == 32 && rest.chars().all(|c| c.is_ascii_hexdigit()) {
                let bytes = hex::decode(rest).ok()?;
                return Some(HashEntry {
                    raw: rest.to_lowercase(),
                    hash_type: HashType::NTLM,
                    hash_bytes: bytes,
                    salt: None,
                    username: None,
                    cracked: false,
                    password: None,
                });
            }
        }

        if let Some(idx) = trimmed.find(':') {
            let after = &trimmed[idx + 1..];
            if after.len() == 32 && after.chars().all(|c| c.is_ascii_hexdigit()) {
                let bytes = hex::decode(after).ok()?;
                let username = trimmed[..idx].to_string();
                return Some(HashEntry {
                    raw: after.to_lowercase(),
                    hash_type: HashType::NTLM,
                    hash_bytes: bytes,
                    salt: None,
                    username: Some(username),
                    cracked: false,
                    password: None,
                });
            }
        }

        if trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let bytes = hex::decode(trimmed).ok()?;
            return Some(HashEntry {
                raw: trimmed.to_lowercase(),
                hash_type: HashType::NTLM,
                hash_bytes: bytes,
                salt: None,
                username: None,
                cracked: false,
                password: None,
            });
        }

        None
    }

    fn can_parse(&self, line: &str) -> bool {
        let trimmed = line.trim();
        if trimmed.starts_with("$NT$") {
            let rest = &trimmed[4..];
            return rest.len() == 32 && rest.chars().all(|c| c.is_ascii_hexdigit());
        }
        if let Some(idx) = trimmed.find(':') {
            let after = &trimmed[idx + 1..];
            if after.len() == 32 && after.chars().all(|c| c.is_ascii_hexdigit()) {
                return true;
            }
        }
        trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    }
}

fn str_to_key(key: &[u8]) -> [u8; 8] {
    let mut result = [0u8; 8];
    result[0] = key[0] >> 1;
    result[1] = ((key[0] & 0x01) << 6) | (key[1] >> 2);
    result[2] = ((key[1] & 0x03) << 5) | (key[2] >> 3);
    result[3] = ((key[2] & 0x07) << 4) | (key[3] >> 4);
    result[4] = ((key[3] & 0x0F) << 3) | (key[4] >> 5);
    result[5] = ((key[4] & 0x1F) << 2) | (key[5] >> 6);
    result[6] = ((key[5] & 0x3F) << 1) | (key[6] >> 7);
    result[7] = key[6] & 0x7F;
    for i in 0..8 {
        let bit_count = result[i].count_ones();
        result[i] = (result[i] << 1) | if bit_count % 2 == 0 { 1 } else { 0 };
    }
    result
}

fn lm_hash_raw(password: &str) -> Option<Vec<u8>> {
    let upper = password.to_uppercase();
    let mut key = upper.as_bytes().to_vec();
    key.resize(14, 0);
    let key1 = str_to_key(&key[..7]);
    let key2 = str_to_key(&key[7..14]);

    let des1 = Des::new(&Array::from(key1));
    let des2 = Des::new(&Array::from(key2));

    let magic = *b"KGS!@#$%";
    let mut block1 = Array::from(magic);
    des1.encrypt_block(&mut block1);
    let mut block2 = Array::from(magic);
    des2.encrypt_block(&mut block2);

    Some([block1.to_vec(), block2.to_vec()].concat())
}

/// Cracker and parser for LM (LAN Manager) hashes (DES, 32 hex chars).
pub struct LmHash;

impl HashCracker for LmHash {
    fn hash_type(&self) -> HashType { HashType::LM }
    fn name(&self) -> &'static str { "LM" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        if password.len() > 14 { return false; }
        match lm_hash_raw(password) {
            Some(computed) => hex::encode(computed).eq_ignore_ascii_case(&entry.raw),
            None => false,
        }
    }

    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for LmHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let trimmed = line.trim();
        if trimmed.len() != 32 { return None; }
        if !trimmed.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        let bytes = hex::decode(trimmed).ok()?;
        Some(HashEntry {
            raw: trimmed.to_lowercase(),
            hash_type: HashType::LM,
            hash_bytes: bytes,
            salt: None,
            username: None,
            cracked: false,
            password: None,
        })
    }

    fn can_parse(&self, line: &str) -> bool {
        let trimmed = line.trim();
        trimmed.len() == 32 && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    }
}
