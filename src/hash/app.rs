use super::{HashCracker, HashEntry, HashType, HashParser};

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() { return false; }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── Apache MD5 ($apr1$) ──

pub struct Apr1Hash;

impl HashCracker for Apr1Hash {
    fn hash_type(&self) -> HashType { HashType::APR1MD5 }
    fn name(&self) -> &'static str { "Apache MD5" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        let computed = apr1_md5(password, salt);
        computed == entry.raw
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Apr1Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if !t.starts_with("$apr1$") { return None; }
        let rest = &t[6..];
        let dollar = rest.find('$')?;
        let salt = &rest[..dollar];
        if salt.is_empty() || salt.len() > 8 { return None; }
        let hash = &rest[dollar+1..];
        if hash.len() != 22 { return None; }
        Some(HashEntry {
            raw: t.to_string(), hash_type: HashType::APR1MD5,
            hash_bytes: hash.as_bytes().to_vec(),
            salt: Some(salt.to_string()), username: None,
            cracked: false, password: None,
        })
    }
    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("$apr1$")
    }
}

fn apr1_md5(pw: &str, salt: &str) -> String {
    use md5::Md5;
    use digest::Digest;
    let mut ctx = Md5::new();
    let pw_bytes = pw.as_bytes();
    ctx.update(pw_bytes);
    ctx.update(b"$apr1$");
    ctx.update(salt.as_bytes());
    let mut ctx2 = Md5::new();
    ctx2.update(pw_bytes);
    ctx2.update(salt.as_bytes());
    ctx2.update(pw_bytes);
    let final2 = ctx2.finalize();
    let flen = pw_bytes.len();
    for j in 0..flen {
        ctx.update(&[final2[j]]);
    }
    let mut n = flen;
    while n > 0 {
        if n & 1 != 0 {
            ctx.update(b"\x00");
        } else {
            ctx.update(&pw_bytes[..1]);
        }
        n >>= 1;
    }
    let mut final_ = ctx.finalize();
    for round in 0..1000 {
        let mut ctx3 = Md5::new();
        if (round & 1) != 0 {
            ctx3.update(pw_bytes);
        } else {
            ctx3.update(final_);
        }
        if (round % 3) != 0 {
            ctx3.update(salt.as_bytes());
        }
        if (round % 7) != 0 {
            ctx3.update(pw_bytes);
        }
        if (round & 1) != 0 {
            ctx3.update(final_);
        } else {
            ctx3.update(pw_bytes);
        }
        final_ = ctx3.finalize();
    }
    let bytes = final_.as_slice();
    const ITA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let b64 = |i: usize| -> char { ITA64[i.min(63)] as char };
    let mut out = String::from("$apr1$");
    out.push_str(salt);
    out.push('$');
    out.push(b64(((bytes[0] as u16) | ((bytes[6] as u16 & 0x0f) << 8)) as usize));
    out.push(b64((((bytes[6] as u16 & 0xf0) >> 4) | ((bytes[12] as u16 & 0x0f) << 4)) as usize));
    out.push(b64((((bytes[12] as u16 & 0xf0) >> 8) | ((bytes[1] as u16 & 0x03) << 2)) as usize));
    out.push(b64((((bytes[1] as u16) >> 2) & 0x3f) as usize));
    out.push(b64((((bytes[1] as u16) >> 4) | ((bytes[7] as u16 & 0x0f) << 4)) as usize));
    out.push(b64((((bytes[7] as u16) >> 4) | ((bytes[13] as u16 & 0x0f) << 4)) as usize));
    out.push(b64((((bytes[13] as u16) >> 4) | ((bytes[2] as u16 & 0x0f) << 4)) as usize));
    out.push(b64((((bytes[2] as u16) >> 4) | ((bytes[8] as u16 & 0x0f) << 4)) as usize));
    out.push(b64((((bytes[8] as u16) >> 4) | ((bytes[14] as u16 & 0x0f) << 4)) as usize));
    out.push(b64((((bytes[14] as u16) >> 4) | ((bytes[3] as u16 & 0x0f) << 4)) as usize));
    out.push(b64((((bytes[3] as u16) >> 4) | ((bytes[9] as u16 & 0x0f) << 4)) as usize));
    out.push(b64((((bytes[9] as u16) >> 4) | ((bytes[15] as u16 & 0x0f) << 4)) as usize));
    out.push(b64((((bytes[15] as u16) >> 4) | ((bytes[4] as u16 & 0x0f) << 4)) as usize));
    out.push(b64((((bytes[4] as u16) >> 4) | ((bytes[10] as u16 & 0x0f) << 4)) as usize));
    out.push(b64((((bytes[10] as u16) >> 4) | ((bytes[5] as u16 & 0x0f) << 4)) as usize));
    out.push(b64((((bytes[5] as u16) >> 4)) as usize));
    out.push(b64((bytes[11] as u16) as usize));
    out
}

// ── MySQL 4.1/5.x ──

pub struct Mysql41Hash;

impl HashCracker for Mysql41Hash {
    fn hash_type(&self) -> HashType { HashType::MYSQL41 }
    fn name(&self) -> &'static str { "MySQL 4.1" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        use sha1::Sha1;
        use digest::Digest;
        let mut h = Sha1::new();
        h.update(password.as_bytes());
        let r1 = h.finalize_reset();
        h.update(hex::encode(r1).as_bytes());
        let r2 = h.finalize();
        let computed = "*".to_string() + &hex::encode(r2).to_uppercase();
        computed == entry.raw
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Mysql41Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if !t.starts_with('*') || t.len() != 41 { return None; }
        if !t[1..].chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: t.to_string(), hash_type: HashType::MYSQL41,
            hash_bytes: hex::decode(&t[1..]).ok()?, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim(); t.starts_with('*') && t.len() == 41 && t[1..].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── PostgreSQL MD5 ──

pub struct PostgresqlHash;

impl HashCracker for PostgresqlHash {
    fn hash_type(&self) -> HashType { HashType::POSTGRESQL }
    fn name(&self) -> &'static str { "PostgreSQL MD5" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let user = entry.username.as_deref().unwrap_or("");
        use md5::Md5; use digest::Digest;
        let mut h = Md5::new();
        h.update(password.as_bytes());
        h.update(user.as_bytes());
        let computed = "md5".to_string() + &hex::encode(h.finalize());
        computed == entry.raw
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for PostgresqlHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if !t.starts_with("md5") || t.len() != 35 { return None; }
        if !t[3..].chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: t.to_string(), hash_type: HashType::POSTGRESQL,
            hash_bytes: hex::decode(&t[3..]).ok()?, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim(); t.starts_with("md5") && t.len() == 35 && t[3..].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── MD4 raw hash ──

pub struct Md4Hash;

impl HashCracker for Md4Hash {
    fn hash_type(&self) -> HashType { HashType::MD4 }
    fn name(&self) -> &'static str { "MD4" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        use md4::{Md4, Digest};
        let mut h = Md4::new();
        h.update(password.as_bytes());
        let computed = hex::encode(h.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Md4Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() != 32 || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        let bytes = hex::decode(t).ok()?;
        Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::MD4,
            hash_bytes: bytes, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim(); t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── BLAKE3-256 raw hash ──

pub struct Blake3Hash;

impl HashCracker for Blake3Hash {
    fn hash_type(&self) -> HashType { HashType::BLAKE3256 }
    fn name(&self) -> &'static str { "BLAKE3-256" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let hash = blake3::hash(password.as_bytes());
        let computed = hex::encode(hash.as_bytes());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Blake3Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        let bytes = hex::decode(t).ok()?;
        Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::BLAKE3256,
            hash_bytes: bytes, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim(); t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── CRC32 ──

pub struct Crc32Hash;

impl HashCracker for Crc32Hash {
    fn hash_type(&self) -> HashType { HashType::CRC32 }
    fn name(&self) -> &'static str { "CRC32" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let crc = crc32fast::hash(password.as_bytes());
        let computed = format!("{:08x}", crc);
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Crc32Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() != 8 || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        let bytes = hex::decode(t).ok()?;
        Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::CRC32,
            hash_bytes: bytes, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim(); t.len() == 8 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── CRC64 ──

pub struct Crc64Hash;

impl HashCracker for Crc64Hash {
    fn hash_type(&self) -> HashType { HashType::CRC64 }
    fn name(&self) -> &'static str { "CRC64" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let crc = crc64::crc64(0, password.as_bytes());
        let computed = format!("{:016x}", crc);
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Crc64Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() != 16 || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        let bytes = hex::decode(t).ok()?;
        Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::CRC64,
            hash_bytes: bytes, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim(); t.len() == 16 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── HMAC-SHA1 ──

pub struct HmacSha1Hash;

impl HashCracker for HmacSha1Hash {
    fn hash_type(&self) -> HashType { HashType::HMACSHA1 }
    fn name(&self) -> &'static str { "HMAC-SHA1" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use hmac::{Hmac, Mac};
        use sha1::Sha1;
        let key = password.as_bytes();
        if key.is_empty() { return false; }
        if let Ok(mut mac) = Hmac::<Sha1>::new_from_slice(key) {
            mac.update(salt.as_bytes());
            let computed = hex::encode(mac.finalize().into_bytes());
            return computed.eq_ignore_ascii_case(&entry.raw);
        }
        false
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for HmacSha1Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let (hash, salt) = split_salt(line)?;
        if hash.len() != 40 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::HMACSHA1,
            hash_bytes: hex::decode(hash).ok()?, salt, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, _: &str) -> bool { true }
}

// ── HMAC-SHA256 ──

pub struct HmacSha256Hash;

impl HashCracker for HmacSha256Hash {
    fn hash_type(&self) -> HashType { HashType::HMACSHA256 }
    fn name(&self) -> &'static str { "HMAC-SHA256" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let key = password.as_bytes();
        if key.is_empty() { return false; }
        if let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) {
            mac.update(salt.as_bytes());
            let computed = hex::encode(mac.finalize().into_bytes());
            return computed.eq_ignore_ascii_case(&entry.raw);
        }
        false
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for HmacSha256Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let (hash, salt) = split_salt(line)?;
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::HMACSHA256,
            hash_bytes: hex::decode(hash).ok()?, salt, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, _: &str) -> bool { true }
}

// ── HMAC-MD5 ──

pub struct HmacMd5Hash;

impl HashCracker for HmacMd5Hash {
    fn hash_type(&self) -> HashType { HashType::HMACMD5 }
    fn name(&self) -> &'static str { "HMAC-MD5" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use hmac::{Hmac, Mac};
        use md5::Md5;
        let key = password.as_bytes();
        if key.is_empty() { return false; }
        if let Ok(mut mac) = Hmac::<Md5>::new_from_slice(key) {
            mac.update(salt.as_bytes());
            let computed = hex::encode(mac.finalize().into_bytes());
            return computed.eq_ignore_ascii_case(&entry.raw);
        }
        false
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for HmacMd5Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let (hash, salt) = split_salt(line)?;
        if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::HMACMD5,
            hash_bytes: hex::decode(hash).ok()?, salt, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, _: &str) -> bool { true }
}

// ── HMAC-SHA512 ──

pub struct HmacSha512Hash;

impl HashCracker for HmacSha512Hash {
    fn hash_type(&self) -> HashType { HashType::HMACSHA512 }
    fn name(&self) -> &'static str { "HMAC-SHA512" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use hmac::{Hmac, Mac};
        use sha2::Sha512;
        let key = password.as_bytes();
        if key.is_empty() { return false; }
        if let Ok(mut mac) = Hmac::<Sha512>::new_from_slice(key) {
            mac.update(salt.as_bytes());
            let computed = hex::encode(mac.finalize().into_bytes());
            return computed.eq_ignore_ascii_case(&entry.raw);
        }
        false
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for HmacSha512Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let (hash, salt) = split_salt(line)?;
        if hash.len() != 128 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::HMACSHA512,
            hash_bytes: hex::decode(hash).ok()?, salt, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, _: &str) -> bool { true }
}

// ── HMAC-SHA224 ──

pub struct HmacSha224Hash;

impl HashCracker for HmacSha224Hash {
    fn hash_type(&self) -> HashType { HashType::HMACSHA224 }
    fn name(&self) -> &'static str { "HMAC-SHA224" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use hmac::{Hmac, Mac};
        use sha2::Sha224;
        let key = password.as_bytes();
        if key.is_empty() { return false; }
        if let Ok(mut mac) = Hmac::<Sha224>::new_from_slice(key) {
            mac.update(salt.as_bytes());
            let computed = hex::encode(mac.finalize().into_bytes());
            return computed.eq_ignore_ascii_case(&entry.raw);
        }
        false
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for HmacSha224Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let (hash, salt) = split_salt(line)?;
        if hash.len() != 56 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::HMACSHA224,
            hash_bytes: hex::decode(hash).ok()?, salt, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, _: &str) -> bool { true }
}

// ── HMAC-SHA384 ──

pub struct HmacSha384Hash;

impl HashCracker for HmacSha384Hash {
    fn hash_type(&self) -> HashType { HashType::HMACSHA384 }
    fn name(&self) -> &'static str { "HMAC-SHA384" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use hmac::{Hmac, Mac};
        use sha2::Sha384;
        let key = password.as_bytes();
        if key.is_empty() { return false; }
        if let Ok(mut mac) = Hmac::<Sha384>::new_from_slice(key) {
            mac.update(salt.as_bytes());
            let computed = hex::encode(mac.finalize().into_bytes());
            return computed.eq_ignore_ascii_case(&entry.raw);
        }
        false
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for HmacSha384Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let (hash, salt) = split_salt(line)?;
        if hash.len() != 96 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::HMACSHA384,
            hash_bytes: hex::decode(hash).ok()?, salt, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, _: &str) -> bool { true }
}

// ── HMAC-RIPEMD160 ──

pub struct HmacRipemd160Hash;

impl HashCracker for HmacRipemd160Hash {
    fn hash_type(&self) -> HashType { HashType::HMACRIPEMD160 }
    fn name(&self) -> &'static str { "HMAC-RIPEMD160" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use hmac::{Hmac, Mac};
        use ripemd::Ripemd160;
        let key = password.as_bytes();
        if key.is_empty() { return false; }
        if let Ok(mut mac) = Hmac::<Ripemd160>::new_from_slice(key) {
            mac.update(salt.as_bytes());
            let computed = hex::encode(mac.finalize().into_bytes());
            return computed.eq_ignore_ascii_case(&entry.raw);
        }
        false
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for HmacRipemd160Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let (hash, salt) = split_salt(line)?;
        if hash.len() != 40 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::HMACRIPEMD160,
            hash_bytes: hex::decode(hash).ok()?, salt, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, _: &str) -> bool { true }
}

// ── Helper: split salt:hash format ──

fn split_salt(line: &str) -> Option<(String, Option<String>)> {
    let t = line.trim();
    if let Some(idx) = t.find(':') {
        let hash = t[..idx].to_string();
        let salt = Some(t[idx+1..].to_string());
        Some((hash, salt))
    } else {
        Some((t.to_string(), None))
    }
}

// ── PBKDF2-HMAC-SHA256 ──

pub struct Pbkdf2Sha256Hash;

impl HashCracker for Pbkdf2Sha256Hash {
    fn hash_type(&self) -> HashType { HashType::PBKDF2SHA256 }
    fn name(&self) -> &'static str { "PBKDF2-SHA256" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha256;
        let mut out = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), 10000, &mut out);
        let computed = hex::encode(&out);
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Pbkdf2Sha256Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() < 2 { return None; }
        let hash = parts[0];
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::PBKDF2SHA256,
            hash_bytes: hex::decode(hash).ok()?, salt: Some(parts[1..].join(":")),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, _: &str) -> bool { true }
}

// ── PBKDF2-HMAC-SHA512 ──

pub struct Pbkdf2Sha512Hash;

impl HashCracker for Pbkdf2Sha512Hash {
    fn hash_type(&self) -> HashType { HashType::PBKDF2SHA512 }
    fn name(&self) -> &'static str { "PBKDF2-SHA512" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use pbkdf2::pbkdf2_hmac;
        use sha2::Sha512;
        let mut out = vec![0u8; 64];
        pbkdf2_hmac::<Sha512>(password.as_bytes(), salt.as_bytes(), 10000, &mut out);
        let computed = hex::encode(&out);
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Pbkdf2Sha512Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() < 2 { return None; }
        let hash = parts[0];
        if hash.len() != 128 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::PBKDF2SHA512,
            hash_bytes: hex::decode(hash).ok()?, salt: Some(parts[1..].join(":")),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, _: &str) -> bool { true }
}

// ── PBKDF2-HMAC-SHA1 ──

pub struct Pbkdf2Sha1Hash;

impl HashCracker for Pbkdf2Sha1Hash {
    fn hash_type(&self) -> HashType { HashType::PBKDF2SHA1 }
    fn name(&self) -> &'static str { "PBKDF2-SHA1" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use pbkdf2::pbkdf2_hmac;
        use sha1::Sha1;
        let mut out = vec![0u8; 20];
        pbkdf2_hmac::<Sha1>(password.as_bytes(), salt.as_bytes(), 10000, &mut out);
        let computed = hex::encode(&out);
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Pbkdf2Sha1Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() < 2 { return None; }
        let hash = parts[0];
        if hash.len() != 40 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::PBKDF2SHA1,
            hash_bytes: hex::decode(hash).ok()?, salt: Some(parts[1..].join(":")),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, _: &str) -> bool { true }
}

// ── DCC1 (Domain Cached Credentials) ──

pub struct Dcc1Hash;

impl HashCracker for Dcc1Hash {
    fn hash_type(&self) -> HashType { HashType::DCC1 }
    fn name(&self) -> &'static str { "DCC1" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let user = entry.username.as_deref().unwrap_or("").to_uppercase();
        use md4::{Md4, Digest};
        let mut h = Md4::new();
        h.update(password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>());
        h.update(user.as_bytes());
        let computed = hex::encode(h.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Dcc1Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 || parts[0].len() != 32 || !parts[0].chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::DCC1,
            hash_bytes: hex::decode(parts[0]).ok()?, salt: None,
            username: Some(parts[1].to_string()), cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── NTLMv2 ──

pub struct Ntlmv2Hash;

impl HashCracker for Ntlmv2Hash {
    fn hash_type(&self) -> HashType { HashType::NTLMV2 }
    fn name(&self) -> &'static str { "NTLMv2" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool {
        false
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Ntlmv2Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() < 3 { return None; }
        let hash_part = parts[2];
        if hash_part.len() != 32 || !hash_part.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash_part.to_lowercase(), hash_type: HashType::NTLMV2,
            hash_bytes: hex::decode(hash_part).ok()?, salt: None,
            username: Some(parts[0].to_string()), cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() >= 3 && parts[2].len() == 32 && parts[2].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── PHPass / WordPress ($P$, $H$) ──

const ITOA64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn phpass_decode(encoded: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(encoded.len() * 6 / 8);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for &c in encoded {
        if let Some(pos) = ITOA64.iter().position(|&x| x == c) {
            buf = (buf << 6) | pos as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
                buf &= (1 << bits) - 1;
            }
        }
    }
    out
}

pub struct PhpassHash;

impl HashCracker for PhpassHash {
    fn hash_type(&self) -> HashType { HashType::PHPASS }
    fn name(&self) -> &'static str { "PHPass" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        let iter_idx = entry.hash_bytes.first().copied().unwrap_or(8) as usize;
        let iter = if iter_idx < ITOA64.len() { 1 << iter_idx } else { 4096 };
        if entry.hash_bytes.len() < 2 { return false; }
        let target = &entry.hash_bytes[1..];
        use md5::{Md5, Digest};
        let mut ctx = Md5::new();
        ctx.update(password.as_bytes());
        ctx.update(salt.as_bytes());
        let mut digest = ctx.finalize_reset();
        for _ in 1..iter {
            ctx.update(password.as_bytes());
            ctx.update(&digest);
            digest = ctx.finalize_reset();
        }
        constant_time_eq(target, &digest)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for PhpassHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if !s.starts_with("$P$") && !s.starts_with("$H$") { return None; }
        if s.len() != 34 { return None; }
        let iter_char = s.as_bytes().get(3).copied()?;
        let _iter_pos = ITOA64.iter().position(|&x| x == iter_char)?;
        let iter_pos = ITOA64.iter().position(|&x| x == iter_char)?;
        let salt = &s[4..12];
        let hash_b64 = &s[12..34];
        let raw_hash = phpass_decode(hash_b64.as_bytes());
        let mut hash_bytes = Vec::with_capacity(1 + raw_hash.len());
        hash_bytes.push(iter_pos as u8);
        hash_bytes.extend_from_slice(&raw_hash);
        Some(HashEntry { raw: hex::encode(&raw_hash), hash_type: HashType::PHPASS,
            hash_bytes, salt: Some(salt.to_string()),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        (s.starts_with("$P$") || s.starts_with("$H$")) && s.len() == 34
    }
}

// ── Drupal 7 ($S$) ──

pub struct Drupal7Hash;

impl HashCracker for Drupal7Hash {
    fn hash_type(&self) -> HashType { HashType::DRUPAL7 }
    fn name(&self) -> &'static str { "Drupal 7" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        let iter_idx = entry.hash_bytes.first().copied().unwrap_or(8) as usize;
        let iter = if iter_idx < ITOA64.len() { 1 << iter_idx } else { 4096 };
        if entry.hash_bytes.len() < 2 { return false; }
        let target = &entry.hash_bytes[1..];
        use sha2::{Sha512, Digest};
        let mut ctx = Sha512::new();
        ctx.update(password.as_bytes());
        ctx.update(salt.as_bytes());
        let mut digest = ctx.finalize_reset();
        for _ in 1..iter {
            ctx.update(password.as_bytes());
            ctx.update(&digest);
            digest = ctx.finalize_reset();
        }
        constant_time_eq(target, &digest)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Drupal7Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if !s.starts_with("$S$") { return None; }
        if s.len() != 55 { return None; }
        let iter_char = s.as_bytes().get(3).copied()?;
        let iter_pos = ITOA64.iter().position(|&x| x == iter_char)?;
        let salt = &s[4..12];
        let hash_b64 = &s[12..55];
        let raw_hash = phpass_decode(hash_b64.as_bytes());
        let mut hash_bytes = Vec::with_capacity(1 + raw_hash.len());
        hash_bytes.push(iter_pos as u8);
        hash_bytes.extend_from_slice(&raw_hash);
        Some(HashEntry { raw: hex::encode(&raw_hash), hash_type: HashType::DRUPAL7,
            hash_bytes, salt: Some(salt.to_string()),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("$S$") && line.trim().len() == 55
    }
}

// ── osCommerce / xt:Commerce (MD5(pass.salt)) ──

pub struct OscommerceHash;

impl HashCracker for OscommerceHash {
    fn hash_type(&self) -> HashType { HashType::OSCOMMERCE }
    fn name(&self) -> &'static str { "osCommerce" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use md5::{Md5, Digest};
        let mut ctx = Md5::new();
        ctx.update(password.as_bytes());
        ctx.update(salt.as_bytes());
        let computed = hex::encode(ctx.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for OscommerceHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 { return None; }
        let hash = parts[0];
        if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::OSCOMMERCE,
            hash_bytes: hex::decode(hash).ok()?, salt: Some(parts[1].to_string()),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Oracle 10g (SHA1(username || password), hash:user format) ──

pub struct Oracle10gHash;

impl HashCracker for Oracle10gHash {
    fn hash_type(&self) -> HashType { HashType::ORACLE10G }
    fn name(&self) -> &'static str { "Oracle 10g" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let user = entry.username.as_deref().unwrap_or("");
        use sha1::{Sha1, Digest};
        let mut ctx = Sha1::new();
        ctx.update(user.as_bytes());
        ctx.update(password.as_bytes());
        let computed = hex::encode(ctx.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Oracle10gHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() < 2 { return None; }
        let hash = parts[0];
        if hash.len() != 40 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::ORACLE10G,
            hash_bytes: hex::decode(hash).ok()?, salt: None,
            username: Some(parts[1].to_string()), cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() >= 2 && parts[0].len() == 40 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Oracle 11g/12c (SHA512(username || SHA512(password || salt)) ──

pub struct Oracle11gHash;

impl HashCracker for Oracle11gHash {
    fn hash_type(&self) -> HashType { HashType::ORACLE11G }
    fn name(&self) -> &'static str { "Oracle 11g/12c" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let user = entry.username.as_deref().unwrap_or("");
        let salt = entry.salt.as_deref().unwrap_or("");
        use sha2::{Sha512, Digest};
        let inner = {
            let mut ctx = Sha512::new();
            ctx.update(password.as_bytes());
            ctx.update(salt.as_bytes());
            ctx.finalize()
        };
        let mut ctx = Sha512::new();
        ctx.update(user.as_bytes());
        ctx.update(&inner);
        let computed = hex::encode(ctx.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Oracle11gHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        let parts: Vec<&str> = if s.starts_with("S:") {
            let body = &s[2..];
            let sub: Vec<&str> = body.split(':').collect();
            sub
        } else {
            s.split(':').collect()
        };
        if parts.len() < 2 { return None; }
        let hash = if parts[0].len() >= 40 { parts[0] } else { return None; };
        let hash_lower = hash.to_lowercase();
        if hash_lower.len() != 128 || !hash_lower.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash_lower.clone(), hash_type: HashType::ORACLE11G,
            hash_bytes: hex::decode(&hash_lower).ok()?, salt: Some(parts[1..].join(":")),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        let body = if s.starts_with("S:") { &s[2..] } else { s };
        let parts: Vec<&str> = body.split(':').collect();
        parts.len() >= 2 && parts[0].len() == 128 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── MSSQL 2005 (SHA256(salt || password), salt:hash format) ──

pub struct Mssql2005Hash;

impl HashCracker for Mssql2005Hash {
    fn hash_type(&self) -> HashType { HashType::MSSQL2005 }
    fn name(&self) -> &'static str { "MSSQL 2005" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use sha2::{Sha256, Digest};
        let mut ctx = Sha256::new();
        ctx.update(salt.as_bytes());
        ctx.update(password.as_bytes());
        let computed = hex::encode(ctx.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Mssql2005Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() < 2 { return None; }
        let hash = parts[0];
        if !hash.chars().all(|c| c.is_ascii_hexdigit()) || hash.len() != 64 { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::MSSQL2005,
            hash_bytes: hex::decode(hash).ok()?, salt: Some(parts[1..].join(":")),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() >= 2 && parts[0].len() == 64 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── MSSQL 2012 (SHA512(salt || password), salt:hash format) ──

pub struct Mssql2012Hash;

impl HashCracker for Mssql2012Hash {
    fn hash_type(&self) -> HashType { HashType::MSSQL2012 }
    fn name(&self) -> &'static str { "MSSQL 2012" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use sha2::{Sha512, Digest};
        let mut ctx = Sha512::new();
        ctx.update(salt.as_bytes());
        ctx.update(password.as_bytes());
        let computed = hex::encode(ctx.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Mssql2012Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() < 2 { return None; }
        let hash = parts[0];
        if !hash.chars().all(|c| c.is_ascii_hexdigit()) || hash.len() != 128 { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::MSSQL2012,
            hash_bytes: hex::decode(hash).ok()?, salt: Some(parts[1..].join(":")),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() >= 2 && parts[0].len() == 128 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── vBulletin 3.x/4.x (MD5(MD5(password) || salt)) ──

pub struct Vbulletin3Hash;

impl HashCracker for Vbulletin3Hash {
    fn hash_type(&self) -> HashType { HashType::VBULLETIN3 }
    fn name(&self) -> &'static str { "vBulletin 3/4" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use md5::{Md5, Digest};
        let md5_pass = {
            let mut ctx = Md5::new();
            ctx.update(password.as_bytes());
            hex::encode(ctx.finalize())
        };
        let mut ctx = Md5::new();
        ctx.update(md5_pass.as_bytes());
        ctx.update(salt.as_bytes());
        let computed = hex::encode(ctx.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Vbulletin3Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 { return None; }
        let hash = parts[0];
        if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::VBULLETIN3,
            hash_bytes: hex::decode(hash).ok()?, salt: Some(parts[1].to_string()),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── vBulletin 5.x ──

pub struct Vbulletin5Hash;

impl HashCracker for Vbulletin5Hash {
    fn hash_type(&self) -> HashType { HashType::VBULLETIN5 }
    fn name(&self) -> &'static str { "vBulletin 5" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use sha2::{Sha256, Digest};
        let mut ctx = Sha256::new();
        ctx.update(password.as_bytes());
        ctx.update(salt.as_bytes());
        let computed = hex::encode(ctx.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Vbulletin5Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 { return None; }
        let hash = parts[0];
        if !hash.chars().all(|c| c.is_ascii_hexdigit()) || hash.len() != 64 { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::VBULLETIN5,
            hash_bytes: hex::decode(hash).ok()?, salt: Some(parts[1].to_string()),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 64 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── SMF 1.x/2.x (SHA1(username || password)) ──

pub struct SmfHash;

impl HashCracker for SmfHash {
    fn hash_type(&self) -> HashType { HashType::SMF }
    fn name(&self) -> &'static str { "SMF 1/2" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let user = entry.username.as_deref().unwrap_or("");
        use sha1::{Sha1, Digest};
        let mut ctx = Sha1::new();
        ctx.update(user.as_bytes());
        ctx.update(password.as_bytes());
        let computed = hex::encode(ctx.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for SmfHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() < 2 { return None; }
        let hash = parts[0];
        if hash.len() != 40 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::SMF,
            hash_bytes: hex::decode(hash).ok()?, salt: None,
            username: Some(parts[1..].join(":")), cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() >= 2 && parts[0].len() == 40 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── IPB 2.x / MyBB 1.x (MD5(MD5(salt) + MD5(password))) ──

pub struct Ipb2Hash;

impl HashCracker for Ipb2Hash {
    fn hash_type(&self) -> HashType { HashType::IPB2 }
    fn name(&self) -> &'static str { "IPB 2 / MyBB" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use md5::{Md5, Digest};
        let md5_salt = {
            let mut ctx = Md5::new();
            ctx.update(salt.as_bytes());
            hex::encode(ctx.finalize())
        };
        let md5_pass = {
            let mut ctx = Md5::new();
            ctx.update(password.as_bytes());
            hex::encode(ctx.finalize())
        };
        let mut ctx = Md5::new();
        ctx.update(md5_salt.as_bytes());
        ctx.update(md5_pass.as_bytes());
        let computed = hex::encode(ctx.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Ipb2Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 { return None; }
        let hash = parts[0];
        if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::IPB2,
            hash_bytes: hex::decode(hash).ok()?, salt: Some(parts[1].to_string()),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── IPB 3.x+ (SHA256(MD5(password) || salt)) ──

pub struct Ipb3Hash;

impl HashCracker for Ipb3Hash {
    fn hash_type(&self) -> HashType { HashType::IPB3 }
    fn name(&self) -> &'static str { "IPB 3+" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use sha2::{Sha256, Digest};
        use md5::Md5;
        let md5_pass = {
            let mut ctx = Md5::new();
            ctx.update(password.as_bytes());
            hex::encode(ctx.finalize())
        };
        let mut ctx = Sha256::new();
        ctx.update(md5_pass.as_bytes());
        ctx.update(salt.as_bytes());
        let computed = hex::encode(ctx.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Ipb3Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 { return None; }
        let hash = parts[0];
        if !hash.chars().all(|c| c.is_ascii_hexdigit()) || hash.len() != 64 { return None; }
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::IPB3,
            hash_bytes: hex::decode(hash).ok()?, salt: Some(parts[1].to_string()),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 64 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── MediaWiki (:$salt:$hash or :B:salt:hash) ──

pub struct MediawikiHash;

impl HashCracker for MediawikiHash {
    fn hash_type(&self) -> HashType { HashType::MEDIAWIKI }
    fn name(&self) -> &'static str { "MediaWiki" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use md5::{Md5, Digest};
        let mut ctx = Md5::new();
        ctx.update(salt.as_bytes());
        ctx.update(b"-");
        ctx.update(password.as_bytes());
        let computed = hex::encode(ctx.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for MediawikiHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if !s.starts_with(':') { return None; }
        let parts: Vec<&str> = s.split(':').collect();
        if parts.len() < 3 { return None; }
        let hash = parts.last()?;
        if hash.len() != 32 || !hash.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        let salt = parts[1..parts.len()-1].join(":");
        Some(HashEntry { raw: hash.to_lowercase(), hash_type: HashType::MEDIAWIKI,
            hash_bytes: hex::decode(hash).ok()?, salt: Some(salt),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        if !s.starts_with(':') { return false; }
        let parts: Vec<&str> = s.split(':').collect();
        parts.len() >= 3
    }
}

// ── Cisco PIX (DES-based, detection only) ──

pub struct CiscoPixHash;

impl HashCracker for CiscoPixHash {
    fn hash_type(&self) -> HashType { HashType::CISCOPIX }
    fn name(&self) -> &'static str { "Cisco PIX" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for CiscoPixHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if s.len() != 16 || !s.chars().all(|c| c.is_ascii_hexdigit()) || !s.starts_with("02") {
            return None;
        }
        Some(HashEntry { raw: s.to_lowercase(), hash_type: HashType::CISCOPIX,
            hash_bytes: hex::decode(s).ok()?, salt: None,
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.len() == 16 && s.chars().all(|c| c.is_ascii_hexdigit()) && s.starts_with("02")
    }
}

// ── Cisco Type 5 (SHA256-based enable secret) ──

pub struct Cisco5Hash;

impl HashCracker for Cisco5Hash {
    fn hash_type(&self) -> HashType { HashType::CISCO5 }
    fn name(&self) -> &'static str { "Cisco Type 5" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Cisco5Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if !s.starts_with("$5$") || s.len() < 10 { return None; }
        Some(HashEntry { raw: s.to_string(), hash_type: HashType::CISCO5,
            hash_bytes: Vec::new(), salt: None,
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("$5$")
    }
}

// ── DCC2 (Domain Cached Credentials 2: MD4(MD4(password) || MD4(username))) ──

pub struct Dcc2Hash;

impl HashCracker for Dcc2Hash {
    fn hash_type(&self) -> HashType { HashType::DCC2 }
    fn name(&self) -> &'static str { "DCC2" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let user = entry.username.as_deref().unwrap_or("").to_uppercase();
        use md4::{Md4, Digest};
        let md4_pass = {
            let mut ctx = Md4::new();
            ctx.update(password.encode_utf16().flat_map(|c| c.to_le_bytes()).collect::<Vec<_>>());
            ctx.finalize()
        };
        let md4_user = {
            let mut ctx = Md4::new();
            ctx.update(user.as_bytes());
            ctx.finalize()
        };
        let mut ctx = Md4::new();
        ctx.update(&md4_pass);
        ctx.update(&md4_user);
        let computed = hex::encode(ctx.finalize());
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Dcc2Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 || parts[0].len() != 32 || !parts[0].chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::DCC2,
            hash_bytes: hex::decode(parts[0]).ok()?, salt: None,
            username: Some(parts[1].to_string()), cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Sun MD5 (`$md5$`) ──

pub struct SunMd5Hash;

impl HashCracker for SunMd5Hash {
    fn hash_type(&self) -> HashType { HashType::SUNMD5 }
    fn name(&self) -> &'static str { "Sun MD5" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for SunMd5Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if !s.starts_with("$md5$") { return None; }
        Some(HashEntry { raw: s.to_string(), hash_type: HashType::SUNMD5,
            hash_bytes: Vec::new(), salt: None,
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("$md5$")
    }
}

// ── BSDi Crypt (`_`) ──

pub struct BsdiCryptHash;

impl HashCracker for BsdiCryptHash {
    fn hash_type(&self) -> HashType { HashType::BSDICRYPT }
    fn name(&self) -> &'static str { "BSDi Crypt" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for BsdiCryptHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if !s.starts_with('_') || s.len() < 20 { return None; }
        Some(HashEntry { raw: s.to_string(), hash_type: HashType::BSDICRYPT,
            hash_bytes: Vec::new(), salt: None,
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        s.starts_with('_') && s.len() >= 20
    }
}

// ── macOS 10.8+ PBKDF2 ──

pub struct MacosPbkdf2Hash;

impl HashCracker for MacosPbkdf2Hash {
    fn hash_type(&self) -> HashType { HashType::MACOSPBKDF2 }
    fn name(&self) -> &'static str { "macOS PBKDF2" }
    fn verify(&self, _: &str, _: &HashEntry) -> bool { false }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for MacosPbkdf2Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        if !s.starts_with("$ml$") { return None; }
        Some(HashEntry { raw: s.to_string(), hash_type: HashType::MACOSPBKDF2,
            hash_bytes: Vec::new(), salt: None,
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("$ml$")
    }
}

// ── Salted MD5 (MD5(password + salt), hash:salt) ──

pub struct SaltedMd5Hash;

impl HashCracker for SaltedMd5Hash {
    fn hash_type(&self) -> HashType { HashType::SALTEDMD5 }
    fn name(&self) -> &'static str { "Salted MD5" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use md5::{Md5, Digest};
        let mut ctx = Md5::new();
        ctx.update(password.as_bytes());
        ctx.update(salt.as_bytes());
        hex::encode(ctx.finalize()).eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for SaltedMd5Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 || parts[0].len() != 32 || !parts[0].chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::SALTEDMD5,
            hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 32 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Salted SHA-1 (SHA1(password + salt), hash:salt) ──

pub struct SaltedSha1Hash;

impl HashCracker for SaltedSha1Hash {
    fn hash_type(&self) -> HashType { HashType::SALTEDSHA1 }
    fn name(&self) -> &'static str { "Salted SHA-1" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use sha1::{Sha1, Digest};
        let mut ctx = Sha1::new();
        ctx.update(password.as_bytes());
        ctx.update(salt.as_bytes());
        hex::encode(ctx.finalize()).eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for SaltedSha1Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 || parts[0].len() != 40 || !parts[0].chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::SALTEDSHA1,
            hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 40 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Salted SHA-256 (SHA256(password + salt), hash:salt) ──

pub struct SaltedSha256Hash;

impl HashCracker for SaltedSha256Hash {
    fn hash_type(&self) -> HashType { HashType::SALTEDSHA256 }
    fn name(&self) -> &'static str { "Salted SHA-256" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use sha2::{Sha256, Digest};
        let mut ctx = Sha256::new();
        ctx.update(password.as_bytes());
        ctx.update(salt.as_bytes());
        hex::encode(ctx.finalize()).eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for SaltedSha256Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 || parts[0].len() != 64 || !parts[0].chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::SALTEDSHA256,
            hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 64 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Salted SHA-512 (SHA512(password + salt), hash:salt) ──

pub struct SaltedSha512Hash;

impl HashCracker for SaltedSha512Hash {
    fn hash_type(&self) -> HashType { HashType::SALTEDSHA512 }
    fn name(&self) -> &'static str { "Salted SHA-512" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use sha2::{Sha512, Digest};
        let mut ctx = Sha512::new();
        ctx.update(password.as_bytes());
        ctx.update(salt.as_bytes());
        hex::encode(ctx.finalize()).eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for SaltedSha512Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 || parts[0].len() != 128 || !parts[0].chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::SALTEDSHA512,
            hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 128 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Double MD5 (MD5(MD5(password))) ──

pub struct DoubleMd5Hash;

impl HashCracker for DoubleMd5Hash {
    fn hash_type(&self) -> HashType { HashType::DOUBLEMD5 }
    fn name(&self) -> &'static str { "Double MD5" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        use md5::{Md5, Digest};
        let inner = {
            let mut ctx = Md5::new();
            ctx.update(password.as_bytes());
            hex::encode(ctx.finalize())
        };
        let mut ctx = Md5::new();
        ctx.update(inner.as_bytes());
        hex::encode(ctx.finalize()).eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for DoubleMd5Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() != 32 || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::DOUBLEMD5,
            hash_bytes: hex::decode(t).ok()?, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim();
        t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Double SHA-1 (SHA1(SHA1(password))) ──

pub struct DoubleSha1Hash;

impl HashCracker for DoubleSha1Hash {
    fn hash_type(&self) -> HashType { HashType::DOUBLESHA1 }
    fn name(&self) -> &'static str { "Double SHA-1" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        use sha1::{Sha1, Digest};
        let inner = {
            let mut ctx = Sha1::new();
            ctx.update(password.as_bytes());
            hex::encode(ctx.finalize())
        };
        let mut ctx = Sha1::new();
        ctx.update(inner.as_bytes());
        hex::encode(ctx.finalize()).eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for DoubleSha1Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() != 40 || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::DOUBLESHA1,
            hash_bytes: hex::decode(t).ok()?, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim();
        t.len() == 40 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Double SHA-256 (SHA256(SHA256(password))) ──

pub struct DoubleSha256Hash;

impl HashCracker for DoubleSha256Hash {
    fn hash_type(&self) -> HashType { HashType::DOUBLESHA256 }
    fn name(&self) -> &'static str { "Double SHA-256" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        use sha2::{Sha256, Digest};
        let inner = {
            let mut ctx = Sha256::new();
            ctx.update(password.as_bytes());
            hex::encode(ctx.finalize())
        };
        let mut ctx = Sha256::new();
        ctx.update(inner.as_bytes());
        hex::encode(ctx.finalize()).eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for DoubleSha256Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() != 64 || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::DOUBLESHA256,
            hash_bytes: hex::decode(t).ok()?, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim();
        t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── {SHA} (base64 SHA-1) ──

pub struct Sha1DashHash;

impl HashCracker for Sha1DashHash {
    fn hash_type(&self) -> HashType { HashType::SHA1DASH }
    fn name(&self) -> &'static str { "{SHA}" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        use sha1::{Sha1, Digest};
        use base64ct::{Base64, Encoding};
        let hash = Sha1::digest(password.as_bytes());
        let computed = Base64::encode_string(&hash);
        computed == entry.raw
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Sha1DashHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        let body = if let Some(b) = s.strip_prefix("{SHA}") { b } else if let Some(b) = s.strip_prefix("{sha}") { b } else { return None; };
        use base64ct::{Base64, Encoding};
        let bytes = Base64::decode_vec(body).ok()?;
        if bytes.len() != 20 { return None; }
        Some(HashEntry { raw: body.to_string(), hash_type: HashType::SHA1DASH,
            hash_bytes: bytes, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        (s.starts_with("{SHA}") || s.starts_with("{sha}")) && s.len() >= 28 && s.len() <= 32
    }
}

// ── SSHA-1 (LDAP Salted SHA1, base64) ──

pub struct Ssha1Hash;

impl HashCracker for Ssha1Hash {
    fn hash_type(&self) -> HashType { HashType::SSHA1 }
    fn name(&self) -> &'static str { "SSHA-1" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use sha1::{Sha1, Digest};
        let mut ctx = Sha1::new();
        ctx.update(password.as_bytes());
        ctx.update(salt.as_bytes());
        let hash = ctx.finalize();
        let mut expected = Vec::with_capacity(hash.len() + salt.len());
        expected.extend_from_slice(&hash);
        expected.extend_from_slice(salt.as_bytes());
        constant_time_eq(&entry.hash_bytes, &expected)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Ssha1Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        let body = if let Some(b) = s.strip_prefix("{SSHA}") { b } else if let Some(b) = s.strip_prefix("{ssha}") { b } else { return None; };
        use base64ct::{Base64, Encoding};
        let bytes = Base64::decode_vec(body).ok()?;
        if bytes.len() < 21 { return None; }
        let (hash, salt) = bytes.split_at(20);
        Some(HashEntry { raw: body.to_string(), hash_type: HashType::SSHA1,
            hash_bytes: hash.to_vec(), salt: Some(hex::encode(salt)),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        (s.starts_with("{SSHA}") || s.starts_with("{ssha}")) && s.len() > 28
    }
}

// ── SSHA-256 (LDAP Salted SHA256, base64) ──

pub struct Ssha256Hash;

impl HashCracker for Ssha256Hash {
    fn hash_type(&self) -> HashType { HashType::SSHA256 }
    fn name(&self) -> &'static str { "SSHA-256" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use sha2::{Sha256, Digest};
        let mut ctx = Sha256::new();
        ctx.update(password.as_bytes());
        ctx.update(salt.as_bytes());
        let hash = ctx.finalize();
        let mut expected = Vec::with_capacity(hash.len() + salt.len());
        expected.extend_from_slice(&hash);
        expected.extend_from_slice(salt.as_bytes());
        constant_time_eq(&entry.hash_bytes, &expected)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Ssha256Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let s = line.trim();
        let body = if let Some(b) = s.strip_prefix("{SSHA256}") { b } else if let Some(b) = s.strip_prefix("{ssha256}") { b } else { return None; };
        use base64ct::{Base64, Encoding};
        let bytes = Base64::decode_vec(body).ok()?;
        if bytes.len() < 33 { return None; }
        let (hash, salt) = bytes.split_at(32);
        Some(HashEntry { raw: body.to_string(), hash_type: HashType::SSHA256,
            hash_bytes: hash.to_vec(), salt: Some(hex::encode(salt)),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let s = line.trim();
        (s.starts_with("{SSHA256}") || s.starts_with("{ssha256}")) && s.len() > 40
    }
}

// ── CRC16 (16-bit checksum) ──

pub struct Crc16Hash;

fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &byte in data {
        crc ^= byte as u16;
        for _ in 0..8 {
            if crc & 0x0001 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFF
}

impl HashCracker for Crc16Hash {
    fn hash_type(&self) -> HashType { HashType::CRC16 }
    fn name(&self) -> &'static str { "CRC16" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let crc = crc16(password.as_bytes());
        let computed = format!("{:04x}", crc);
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Crc16Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() != 4 || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::CRC16,
            hash_bytes: hex::decode(t).ok()?, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim();
        t.len() == 4 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── CRC32C (Castagnoli, 32-bit checksum) ──

fn crc32c(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0x82F63B78;
            } else {
                crc >>= 1;
            }
        }
    }
    crc ^ 0xFFFFFFFF
}

pub struct Crc32cHash;

impl HashCracker for Crc32cHash {
    fn hash_type(&self) -> HashType { HashType::CRC32C }
    fn name(&self) -> &'static str { "CRC32C" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let crc = crc32c(password.as_bytes());
        let computed = format!("{:08x}", crc);
        computed.eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Crc32cHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() != 8 || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::CRC32C,
            hash_bytes: hex::decode(t).ok()?, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim();
        t.len() == 8 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── CRC8 (8-bit checksum) ──

fn crc8(data: &[u8]) -> u8 {
    let mut crc: u8 = 0;
    for &byte in data {
        crc ^= byte;
        for _ in 0..8 {
            if crc & 0x80 != 0 {
                crc = (crc << 1) ^ 0x07;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

pub struct Crc8Hash;

impl HashCracker for Crc8Hash {
    fn hash_type(&self) -> HashType { HashType::CRC8 }
    fn name(&self) -> &'static str { "CRC8" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let c = crc8(password.as_bytes());
        format!("{:02x}", c).eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Crc8Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() != 2 || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::CRC8,
            hash_bytes: hex::decode(t).ok()?, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim(); t.len() == 2 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Adler-32 checksum ──

fn adler32(data: &[u8]) -> u32 {
    let a = data.iter().fold(1u32, |a, &b| (a + b as u32) % 65521);
    let b = data.iter().fold(a, |b, &byte| {
        let mut new_b = b;
        for _ in 0..1 {
            new_b = (new_b + byte as u32) % 65521;
        }
        new_b
    });
    (b << 16) | a
}

pub struct Adler32Hash;

impl HashCracker for Adler32Hash {
    fn hash_type(&self) -> HashType { HashType::ADLER32 }
    fn name(&self) -> &'static str { "Adler-32" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let c = adler32(password.as_bytes());
        format!("{:08x}", c).eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for Adler32Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let t = line.trim();
        if t.len() != 8 || !t.chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: t.to_lowercase(), hash_type: HashType::ADLER32,
            hash_bytes: hex::decode(t).ok()?, salt: None, username: None,
            cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let t = line.trim(); t.len() == 8 && t.chars().all(|c| c.is_ascii_hexdigit())
    }
}

// ── Salted SHA-384 (SHA384(password + salt), hash:salt) ──

pub struct SaltedSha384Hash;

impl HashCracker for SaltedSha384Hash {
    fn hash_type(&self) -> HashType { HashType::SALTEDSHA384 }
    fn name(&self) -> &'static str { "Salted SHA-384" }
    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        use sha2::{Sha384, Digest};
        let mut ctx = Sha384::new();
        ctx.update(password.as_bytes());
        ctx.update(salt.as_bytes());
        hex::encode(ctx.finalize()).eq_ignore_ascii_case(&entry.raw)
    }
    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for SaltedSha384Hash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let parts: Vec<&str> = line.trim().split(':').collect();
        if parts.len() != 2 || parts[0].len() != 96 || !parts[0].chars().all(|c| c.is_ascii_hexdigit()) { return None; }
        Some(HashEntry { raw: parts[0].to_lowercase(), hash_type: HashType::SALTEDSHA384,
            hash_bytes: hex::decode(parts[0]).ok()?, salt: Some(parts[1].to_string()),
            username: None, cracked: false, password: None })
    }
    fn can_parse(&self, line: &str) -> bool {
        let parts: Vec<&str> = line.trim().split(':').collect();
        parts.len() == 2 && parts[0].len() == 96 && parts[0].chars().all(|c| c.is_ascii_hexdigit())
    }
}
