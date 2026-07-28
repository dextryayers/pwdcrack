use argon2::{Argon2, Algorithm, Version, Params as Argon2Params};
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use scrypt::Scrypt;
use scrypt::password_hash::PasswordHash as ScryptPH;

use super::{HashCracker, HashEntry, HashType, HashParser};

pub struct Argon2iHash;
pub struct Argon2dHash;
pub struct Argon2idHash;
pub struct ScryptHash;

fn parse_argon2_params(raw: &str) -> Option<Argon2Params> {
    let parts: Vec<&str> = raw.split('$').collect();
    if parts.len() < 4 { return None; }
    let params_str = parts[3];
    let mut m_cost = 19456u32;
    let mut t_cost = 2u32;
    let mut p_cost = 1u32;
    for kv in params_str.split(',') {
        let mut kv_split = kv.splitn(2, '=');
        match (kv_split.next(), kv_split.next()) {
            (Some("m"), Some(v)) => m_cost = v.parse().unwrap_or(m_cost),
            (Some("t"), Some(v)) => t_cost = v.parse().unwrap_or(t_cost),
            (Some("p"), Some(v)) => p_cost = v.parse().unwrap_or(p_cost),
            _ => {}
        }
    }
    Argon2Params::new(m_cost, t_cost, p_cost, None).ok()
}

impl HashCracker for Argon2iHash {
    fn hash_type(&self) -> HashType { HashType::Argon2i }
    fn name(&self) -> &'static str { "Argon2i" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let params = match parse_argon2_params(&entry.raw) {
            Some(p) => p,
            None => return false,
        };
        let argon2 = Argon2::new(Algorithm::Argon2i, Version::V0x13, params);
        let ph = match PasswordHash::new(&entry.raw) {
            Ok(ph) => ph,
            Err(_) => return false,
        };
        argon2.verify_password(password.as_bytes(), &ph).is_ok()
    }
}

impl HashParser for Argon2iHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let trimmed = line.trim();
        if trimmed.starts_with("$argon2i$") {
            Some(HashEntry {
                raw: trimmed.to_string(),
                hash_type: HashType::Argon2i,
                hash_bytes: trimmed.as_bytes().to_vec(),
                salt: None,
                username: None,
                cracked: false,
                password: None,
            })
        } else {
            None
        }
    }

    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("$argon2i$")
    }
}

impl HashCracker for Argon2dHash {
    fn hash_type(&self) -> HashType { HashType::Argon2d }
    fn name(&self) -> &'static str { "Argon2d" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let params = match parse_argon2_params(&entry.raw) {
            Some(p) => p,
            None => return false,
        };
        let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, params);
        let ph = match PasswordHash::new(&entry.raw) {
            Ok(ph) => ph,
            Err(_) => return false,
        };
        argon2.verify_password(password.as_bytes(), &ph).is_ok()
    }
}

impl HashParser for Argon2dHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let trimmed = line.trim();
        if trimmed.starts_with("$argon2d$") {
            Some(HashEntry {
                raw: trimmed.to_string(),
                hash_type: HashType::Argon2d,
                hash_bytes: trimmed.as_bytes().to_vec(),
                salt: None,
                username: None,
                cracked: false,
                password: None,
            })
        } else {
            None
        }
    }

    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("$argon2d$")
    }
}

impl HashCracker for Argon2idHash {
    fn hash_type(&self) -> HashType { HashType::Argon2id }
    fn name(&self) -> &'static str { "Argon2id" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let params = match parse_argon2_params(&entry.raw) {
            Some(p) => p,
            None => return false,
        };
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let ph = match PasswordHash::new(&entry.raw) {
            Ok(ph) => ph,
            Err(_) => return false,
        };
        argon2.verify_password(password.as_bytes(), &ph).is_ok()
    }
}

impl HashParser for Argon2idHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let trimmed = line.trim();
        if trimmed.starts_with("$argon2id$") {
            Some(HashEntry {
                raw: trimmed.to_string(),
                hash_type: HashType::Argon2id,
                hash_bytes: trimmed.as_bytes().to_vec(),
                salt: None,
                username: None,
                cracked: false,
                password: None,
            })
        } else {
            None
        }
    }

    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("$argon2id$")
    }
}

impl HashCracker for ScryptHash {
    fn hash_type(&self) -> HashType { HashType::Scrypt }
    fn name(&self) -> &'static str { "scrypt" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let parsed = ScryptPH::new(&entry.raw).ok();
        match parsed {
            Some(ph) => {
                PasswordVerifier::verify_password(&Scrypt, password.as_bytes(), &ph).is_ok()
            }
            None => false,
        }
    }
}

impl HashParser for ScryptHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let trimmed = line.trim();
        if trimmed.starts_with("$scrypt$") {
            Some(HashEntry {
                raw: trimmed.to_string(),
                hash_type: HashType::Scrypt,
                hash_bytes: trimmed.as_bytes().to_vec(),
                salt: None,
                username: None,
                cracked: false,
                password: None,
            })
        } else {
            None
        }
    }

    fn can_parse(&self, line: &str) -> bool {
        line.trim().starts_with("$scrypt$")
    }
}
