use sha2::{Sha256, Sha384, Sha512, Digest as Sha2Digest};
use sha1::Sha1;
use md5::Md5;
use sha3::Sha3_512;
use blake2::{Blake2b512, Blake2s256};
use ripemd::Ripemd160;
use des::Des;
use cipher::{KeyInit, BlockCipherEncrypt, Array};

use super::{HashCracker, HashEntry, HashType, HashParser};

macro_rules! impl_raw_hash {
    ($name:ident, $hash_type:expr, $digest:ty, $bit_len:expr) => {
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
impl_raw_hash!(Sha224Hash, HashType::SHA224, Sha256, 224);
impl_raw_hash!(Sha256Hash, HashType::SHA256, Sha256, 256);
impl_raw_hash!(Sha384Hash, HashType::SHA384, Sha384, 384);
impl_raw_hash!(Sha512Hash, HashType::SHA512, Sha512, 512);
impl_raw_hash!(Sha3_512Hash, HashType::SHA3512, Sha3_512, 512);
impl_raw_hash!(Blake2b512Hash, HashType::BLAKE2B512, Blake2b512, 512);
impl_raw_hash!(Blake2s256Hash, HashType::BLAKE2B256, Blake2s256, 256);
impl_raw_hash!(Ripemd160Hash, HashType::RIPEMD160, Ripemd160, 160);

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
