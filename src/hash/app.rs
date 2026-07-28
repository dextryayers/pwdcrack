use super::{HashCracker, HashEntry, HashType, HashParser};

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
