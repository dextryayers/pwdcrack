use md5::Md5;
use sha2::{Sha256, Sha512, Digest};
use super::{HashCracker, HashEntry, HashType, HashParser};

fn to64(from: u64, length: u32) -> String {
    let itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut res = String::new();
    let mut v = from;
    for _ in 0..length {
        res.push(itoa64.chars().nth((v & 0x3f) as usize).unwrap());
        v >>= 6;
    }
    res
}

fn is_md5_crypt(s: &str) -> bool {
    s.starts_with("$1$")
}

fn is_sha256_crypt(s: &str) -> bool {
    s.starts_with("$5$")
}

fn is_sha512_crypt(s: &str) -> bool {
    s.starts_with("$6$")
}

pub struct Md5Crypt;

impl Md5Crypt {
    fn crypt_raw(password: &[u8], salt: &[u8]) -> String {
        let magic = b"$1$";
        let mut ctx = Md5::new();
        ctx.update(password);
        ctx.update(magic);
        ctx.update(salt);

        let mut ctx1 = Md5::new();
        ctx1.update(password);
        ctx1.update(salt);
        ctx1.update(password);
        let final1 = ctx1.finalize();

        let mut i = password.len();
        while i > 0 {
            if i > 16 {
                let range = if i > 16 { 16 } else { i };
                ctx.update(&final1[..range]);
            } else {
                ctx.update(&final1[..i]);
            }
            i = i.wrapping_sub(16);
        }

        let mut i = password.len();
        while i > 0 {
            if i & 1 != 0 {
                ctx.update(&[0]);
            } else {
                ctx.update(&password[..1]);
            }
            i >>= 1;
        }

        let mut final2 = ctx.finalize();
        let mut passwd = String::from("$1$");
        passwd.push_str(std::str::from_utf8(salt).unwrap_or(""));
        passwd.push('$');

        for round in 0..1000 {
            let mut ctx2 = Md5::new();
            if round & 1 != 0 {
                ctx2.update(password);
            } else {
                ctx2.update(&final2);
            }
            if round % 3 != 0 {
                ctx2.update(salt);
            }
            if round % 7 != 0 {
                ctx2.update(password);
            }
            if round & 1 != 0 {
                ctx2.update(&final2);
            } else {
                ctx2.update(password);
            }
            final2 = ctx2.finalize();
        }

        let final_bytes = final2;
        let mut results = Vec::new();
        results.push((final_bytes[0] as u64) | ((final_bytes[10] as u64) << 8) | ((final_bytes[20] as u64) << 16) | ((final_bytes[30] as u64) << 24));
        results.push((final_bytes[1] as u64) | ((final_bytes[11] as u64) << 8) | ((final_bytes[21] as u64) << 16) | ((final_bytes[31] as u64) << 24));
        results.push((final_bytes[2] as u64) | ((final_bytes[12] as u64) << 8) | ((final_bytes[22] as u64) << 16));
        results.push((final_bytes[3] as u64) | ((final_bytes[13] as u64) << 8) | ((final_bytes[23] as u64) << 16));
        results.push((final_bytes[4] as u64) | ((final_bytes[14] as u64) << 8) | ((final_bytes[24] as u64) << 16));
        results.push((final_bytes[5] as u64) | ((final_bytes[15] as u64) << 8) | ((final_bytes[25] as u64) << 16));
        results.push((final_bytes[6] as u64) | ((final_bytes[16] as u64) << 8) | ((final_bytes[26] as u64) << 16));
        results.push((final_bytes[7] as u64) | ((final_bytes[17] as u64) << 8) | ((final_bytes[27] as u64) << 16));
        results.push((final_bytes[8] as u64) | ((final_bytes[18] as u64) << 8) | ((final_bytes[28] as u64) << 16));
        results.push((final_bytes[9] as u64) | ((final_bytes[19] as u64) << 8) | ((final_bytes[29] as u64) << 16));

        for v in results {
            passwd.push_str(&to64(v, 4));
        }

        passwd
    }
}

impl HashCracker for Md5Crypt {
    fn hash_type(&self) -> HashType { HashType::MD5Crypt }
    fn name(&self) -> &'static str { "MD5 Crypt" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        let computed = Self::crypt_raw(password.as_bytes(), salt.as_bytes());
        computed == entry.raw
    }
}

impl HashParser for Md5Crypt {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let trimmed = line.trim();
        if !is_md5_crypt(trimmed) { return None; }
        let parts: Vec<&str> = trimmed.split('$').collect();
        if parts.len() < 4 { return None; }
        let salt = parts[2].to_string();
        Some(HashEntry {
            raw: trimmed.to_string(),
            hash_type: HashType::MD5Crypt,
            hash_bytes: trimmed.as_bytes().to_vec(),
            salt: Some(salt),
            username: None,
            cracked: false,
            password: None,
        })
    }

    fn can_parse(&self, line: &str) -> bool {
        is_md5_crypt(line.trim())
    }
}

fn parse_rounds(raw: &str, prefix: &str) -> Option<u32> {
    let without_prefix = raw.strip_prefix(prefix)?;
    if let Some(rest) = without_prefix.strip_prefix("rounds=") {
        let end = rest.find('$')?;
        rest[..end].parse::<u32>().ok()
    } else {
        None
    }
}

pub struct Sha256Crypt;

impl Sha256Crypt {
    fn crypt_raw(password: &[u8], salt: &[u8], rounds: Option<u32>) -> String {
        let rounds_val = rounds.unwrap_or(5000);
        let rounds_str = format!("rounds={}", rounds_val);

        let mut ctx = Sha256::new();
        ctx.update(password);
        ctx.update(b"$5$");
        if rounds.is_some() {
            ctx.update(rounds_str.as_bytes());
            ctx.update(b"$");
        }
        ctx.update(salt);

        let mut ctx1 = Sha256::new();
        ctx1.update(password);
        ctx1.update(salt);
        ctx1.update(password);
        let digest1 = ctx1.finalize();

        let mut i = password.len() as u32;
        while i > 0 {
            if i > 32 {
                ctx.update(&digest1[..32]);
            } else {
                ctx.update(&digest1[..i as usize]);
            }
            i = i.wrapping_sub(32);
        }

        let mut i = password.len();
        let mut px = Vec::new();
        while i > 0 {
            if i & 1 != 0 {
                px.push(0u8);
            } else {
                px.push(password[0]);
            }
            i >>= 1;
        }
        ctx.update(&px);

        let mut digest2 = ctx.finalize();
        let mut p_bytes = digest2.to_vec();

        for round in 0..rounds_val.saturating_sub(1) {
            let mut ctx3 = Sha256::new();
            if round & 1 != 0 {
                ctx3.update(&p_bytes);
            } else {
                ctx3.update(password);
            }
            if round % 3 != 0 {
                ctx3.update(salt);
            }
            if round % 7 != 0 {
                ctx3.update(&p_bytes);
            }
            if round & 1 != 0 {
                ctx3.update(password);
            } else {
                ctx3.update(&p_bytes);
            }
            digest2 = ctx3.finalize();
            p_bytes = digest2.to_vec();
        }

        let b64 = encode_sha256_crypt(&digest2);
        let mut result = String::from("$5$");
        if rounds.is_some() {
            result.push_str(&rounds_str);
            result.push('$');
        }
        result.push_str(std::str::from_utf8(salt).unwrap_or(""));
        result.push('$');
        result.push_str(&b64);
        result
    }
}

fn encode_sha256_crypt(digest: &[u8]) -> String {
    let itoa64 = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut res = String::new();

    macro_rules! add {
        ($v:expr, $n:expr) => {
            let mut __i = $v as u64;
            for _ in 0..$n {
                res.push(itoa64[(__i & 0x3f) as usize] as char);
                __i >>= 6;
            }
        };
    }

    add!(digest[0] as u64 | ((digest[10] as u64) << 8) | ((digest[20] as u64) << 16), 4);
    add!(digest[21] as u64 | ((digest[1] as u64) << 8) | ((digest[11] as u64) << 16), 4);
    add!(digest[12] as u64 | ((digest[22] as u64) << 8) | ((digest[2] as u64) << 16), 4);
    add!(digest[3] as u64 | ((digest[13] as u64) << 8) | ((digest[23] as u64) << 16), 4);
    add!(digest[24] as u64 | ((digest[4] as u64) << 8) | ((digest[14] as u64) << 16), 4);
    add!(digest[15] as u64 | ((digest[25] as u64) << 8) | ((digest[5] as u64) << 16), 4);
    add!(digest[6] as u64 | ((digest[16] as u64) << 8) | ((digest[26] as u64) << 16), 4);
    add!(digest[27] as u64 | ((digest[7] as u64) << 8) | ((digest[17] as u64) << 16), 4);
    add!(digest[18] as u64 | ((digest[28] as u64) << 8) | ((digest[8] as u64) << 16), 4);
    add!(digest[9] as u64 | ((digest[19] as u64) << 8) | ((digest[29] as u64) << 16), 4);

    res.push(itoa64[(digest[31] as usize) & 0x3f] as char);

    res
}

impl HashCracker for Sha256Crypt {
    fn hash_type(&self) -> HashType { HashType::SHA256Crypt }
    fn name(&self) -> &'static str { "SHA-256 Crypt" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        let rounds = parse_rounds(&entry.raw, "$5$");
        let computed = Self::crypt_raw(password.as_bytes(), salt.as_bytes(), rounds);
        computed == entry.raw
    }
}

impl HashParser for Sha256Crypt {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let trimmed = line.trim();
        if !is_sha256_crypt(trimmed) { return None; }
        let parts: Vec<&str> = trimmed.split('$').collect();
        let salt = if parts.len() >= 4 { parts[2] } else { return None };
        if salt.starts_with("rounds=") {
            if parts.len() < 5 { return None; }
            Some(HashEntry {
                raw: trimmed.to_string(),
                hash_type: HashType::SHA256Crypt,
                hash_bytes: trimmed.as_bytes().to_vec(),
                salt: Some(parts[3].to_string()),
                username: None,
                cracked: false,
                password: None,
            })
        } else {
            Some(HashEntry {
                raw: trimmed.to_string(),
                hash_type: HashType::SHA256Crypt,
                hash_bytes: trimmed.as_bytes().to_vec(),
                salt: Some(salt.to_string()),
                username: None,
                cracked: false,
                password: None,
            })
        }
    }

    fn can_parse(&self, line: &str) -> bool {
        is_sha256_crypt(line.trim())
    }
}

pub struct Sha512Crypt;

impl Sha512Crypt {
    fn crypt_raw(password: &[u8], salt: &[u8], rounds: Option<u32>) -> String {
        let rounds_val = rounds.unwrap_or(5000);
        let rounds_str = format!("rounds={}", rounds_val);

        let mut ctx = Sha512::new();
        ctx.update(password);
        ctx.update(b"$6$");
        if rounds.is_some() {
            ctx.update(rounds_str.as_bytes());
            ctx.update(b"$");
        }
        ctx.update(salt);

        let mut ctx1 = Sha512::new();
        ctx1.update(password);
        ctx1.update(salt);
        ctx1.update(password);
        let digest1 = ctx1.finalize();

        let mut i = password.len() as u32;
        while i > 0 {
            if i > 64 {
                ctx.update(&digest1[..64]);
            } else {
                ctx.update(&digest1[..i as usize]);
            }
            i = i.wrapping_sub(64);
        }

        let mut i = password.len();
        let mut px = Vec::new();
        while i > 0 {
            if i & 1 != 0 {
                px.push(0u8);
            } else {
                px.push(password[0]);
            }
            i >>= 1;
        }
        ctx.update(&px);

        let mut digest2 = ctx.finalize();
        let mut p_bytes = digest2.to_vec();

        for round in 0..rounds_val.saturating_sub(1) {
            let mut ctx3 = Sha512::new();
            if round & 1 != 0 {
                ctx3.update(&p_bytes);
            } else {
                ctx3.update(password);
            }
            if round % 3 != 0 {
                ctx3.update(salt);
            }
            if round % 7 != 0 {
                ctx3.update(&p_bytes);
            }
            if round & 1 != 0 {
                ctx3.update(password);
            } else {
                ctx3.update(&p_bytes);
            }
            digest2 = ctx3.finalize();
            p_bytes = digest2.to_vec();
        }

        let b64 = encode_sha512_crypt(&digest2);
        let mut result = String::from("$6$");
        if rounds.is_some() {
            result.push_str(&rounds_str);
            result.push('$');
        }
        result.push_str(std::str::from_utf8(salt).unwrap_or(""));
        result.push('$');
        result.push_str(&b64);
        result
    }
}

fn encode_sha512_crypt(digest: &[u8]) -> String {
    let itoa64 = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let mut res = String::new();
    let mut i: u64;

    macro_rules! add {
        ($v:expr, $n:expr) => {
            i = $v as u64;
            for _ in 0..$n {
                res.push(itoa64[(i & 0x3f) as usize] as char);
                i >>= 6;
            }
        };
    }

    add!(digest[0] as u64 | ((digest[21] as u64) << 8) | ((digest[42] as u64) << 16), 4);
    add!(digest[22] as u64 | ((digest[43] as u64) << 8) | ((digest[1] as u64) << 16), 4);
    add!(digest[44] as u64 | ((digest[2] as u64) << 8) | ((digest[23] as u64) << 16), 4);
    add!(digest[3] as u64 | ((digest[24] as u64) << 8) | ((digest[45] as u64) << 16), 4);
    add!(digest[25] as u64 | ((digest[46] as u64) << 8) | ((digest[4] as u64) << 16), 4);
    add!(digest[47] as u64 | ((digest[5] as u64) << 8) | ((digest[26] as u64) << 16), 4);
    add!(digest[6] as u64 | ((digest[27] as u64) << 8) | ((digest[48] as u64) << 16), 4);
    add!(digest[28] as u64 | ((digest[49] as u64) << 8) | ((digest[7] as u64) << 16), 4);
    add!(digest[50] as u64 | ((digest[8] as u64) << 8) | ((digest[29] as u64) << 16), 4);
    add!(digest[9] as u64 | ((digest[30] as u64) << 8) | ((digest[51] as u64) << 16), 4);
    add!(digest[31] as u64 | ((digest[52] as u64) << 8) | ((digest[10] as u64) << 16), 4);
    add!(digest[53] as u64 | ((digest[11] as u64) << 8) | ((digest[32] as u64) << 16), 4);
    add!(digest[12] as u64 | ((digest[33] as u64) << 8) | ((digest[54] as u64) << 16), 4);
    add!(digest[34] as u64 | ((digest[55] as u64) << 8) | ((digest[13] as u64) << 16), 4);
    add!(digest[56] as u64 | ((digest[14] as u64) << 8) | ((digest[35] as u64) << 16), 4);
    add!(digest[15] as u64 | ((digest[36] as u64) << 8) | ((digest[57] as u64) << 16), 4);
    add!(digest[37] as u64 | ((digest[58] as u64) << 8) | ((digest[16] as u64) << 16), 4);
    add!(digest[59] as u64 | ((digest[17] as u64) << 8) | ((digest[38] as u64) << 16), 4);
    add!(digest[18] as u64 | ((digest[39] as u64) << 8) | ((digest[60] as u64) << 16), 4);
    add!(digest[40] as u64 | ((digest[61] as u64) << 8) | ((digest[19] as u64) << 16), 4);
    add!(digest[62] as u64 | ((digest[20] as u64) << 8) | ((digest[41] as u64) << 16), 4);

    res.push(itoa64[(digest[63] as usize) & 0x3f] as char);

    res
}

impl HashCracker for Sha512Crypt {
    fn hash_type(&self) -> HashType { HashType::SHA512Crypt }
    fn name(&self) -> &'static str { "SHA-512 Crypt" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let salt = entry.salt.as_deref().unwrap_or("");
        let rounds = parse_rounds(&entry.raw, "$6$");
        let computed = Self::crypt_raw(password.as_bytes(), salt.as_bytes(), rounds);
        computed == entry.raw
    }
}

impl HashParser for Sha512Crypt {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let trimmed = line.trim();
        if !is_sha512_crypt(trimmed) { return None; }
        let parts: Vec<&str> = trimmed.split('$').collect();
        let salt = if parts.len() >= 4 { parts[2] } else { return None };
        if salt.starts_with("rounds=") {
            if parts.len() < 5 { return None; }
            Some(HashEntry {
                raw: trimmed.to_string(),
                hash_type: HashType::SHA512Crypt,
                hash_bytes: trimmed.as_bytes().to_vec(),
                salt: Some(parts[3].to_string()),
                username: None,
                cracked: false,
                password: None,
            })
        } else {
            Some(HashEntry {
                raw: trimmed.to_string(),
                hash_type: HashType::SHA512Crypt,
                hash_bytes: trimmed.as_bytes().to_vec(),
                salt: Some(salt.to_string()),
                username: None,
                cracked: false,
                password: None,
            })
        }
    }

    fn can_parse(&self, line: &str) -> bool {
        is_sha512_crypt(line.trim())
    }
}
