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

/// Cracker and parser for Unix `$1$` MD5-crypt hashes.
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

        // Truncate the key length to the largest multiple of 16 that is not
        // greater than the key, then feed `final1` in at most 16 byte chunks
        // from that truncated length down to 1.
        //
        // The reference implementation loops `for (i = strlen(key); i; i -= 16)`
        // so the sequence is `len & !15, ..., 16, 1` for a non-multiple length
        // and `len, ..., 16, 1` for an exact multiple. The previous code used
        // `i.wrapping_sub(16)`, which wrapped to near usize::MAX for any length
        // that was not a multiple of 16 and never terminated.
        for i in (1..=password.len()).rev().step_by(16) {
            ctx.update(&final1[..i.min(16)]);
        }

        // Then, for every bit of the password length from low to high, add the
        // low byte of the password when the bit is set, otherwise a NUL byte.
        let mut px = Vec::new();
        let mut bit = 0usize;
        while (password.len() >> bit) != 0 {
            if password.len() >> bit & 1 == 1 {
                px.push(password[0]);
            } else {
                px.push(0u8);
            }
            bit += 1;
        }
        ctx.update(&px);

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

        // ── BLOCKED: tail encoding is incorrect, see note below ──
        //
        // History of this function, for whoever picks this up:
        //
        // 1. The loop that appends `final1` used `i.wrapping_sub(16)`. For any
        //    key length that was not an exact multiple of the block size the
        //    counter wrapped to near usize::MAX and the loop never returned.
        //    That part has been fixed (see above) and is provably correct.
        //
        // 2. The code below indexes the digest as `b[20]` and `b[30]`. `final2`
        //    is an MD5 digest, which is 16 bytes, so every one of those reads
        //    was out of bounds and panicked on every call. It never produced a
        //    correct hash, not even for a single input.
        //
        // 3. The correct md5crypt tail interleaves the 16 digest bytes into
        //    22 base64 characters (five groups of four plus one group of two)
        //    using a specific non linear byte order. That order has NOT been
        //    reproduced here yet.
        //
        // Verification status
        // -------------------
        // `openssl passwd -1` and `libcrypt.so.1` are available on the build
        // machine and agree with each other, so they are a usable oracle:
        //
        //     openssl passwd -1 -salt abcdefgh 'password'
        //     -> $1$abcdefgh$G//4keteveJp0qb8z2DxG/
        //
        // An implementation written from the algorithm description produced a
        // final digest that differs from the oracle in every byte position, not
        // merely in the ordering, so the discrepancy is in the core digest
        // computation rather than in the base64 tail. Do not "fix" only the
        // tail: that was tried and does not converge.
        //
        // Until a verified implementation replaces this, `verify` must return
        // false rather than a wrong answer, because a wrong answer here means
        // either a missed crack or a false positive report.

        let _ = final2;
        passwd
    }
}

impl HashCracker for Md5Crypt {
    fn hash_type(&self) -> HashType { HashType::MD5Crypt }
    fn name(&self) -> &'static str { "MD5 Crypt" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        // Not implemented yet, see the block comment in `crypt_raw`.
        // Returning false is deliberate: an unverified md5crypt that produced
        // a wrong hash would report false positives. See `crypt_raw`.
        let _ = (password, entry);
        false
    }

    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
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

/// Cracker and parser for Unix `$5$` SHA-256 crypt hashes.
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

        // See `Md5Crypt::crypt_raw` for why the previous `wrapping_sub` loop
        // never terminated for a key length that was not a multiple of the
        // digest size.
        for i in (1..=password.len()).rev().step_by(32) {
            ctx.update(&digest1[..i.min(32)]);
        }

        let mut px = Vec::new();
        let mut bit = 0usize;
        while (password.len() >> bit) != 0 {
            if password.len() >> bit & 1 == 1 {
                px.push(password[0]);
            } else {
                px.push(0u8);
            }
            bit += 1;
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

    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
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

/// Cracker and parser for Unix `$6$` SHA-512 crypt hashes.
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

        // See `Md5Crypt::crypt_raw` for why the previous `wrapping_sub` loop
        // never terminated for a key length that was not a multiple of the
        // digest size.
        for i in (1..=password.len()).rev().step_by(64) {
            ctx.update(&digest1[..i.min(64)]);
        }

        let mut px = Vec::new();
        let mut bit = 0usize;
        while (password.len() >> bit) != 0 {
            if password.len() >> bit & 1 == 1 {
                px.push(password[0]);
            } else {
                px.push(0u8);
            }
            bit += 1;
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

    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
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
