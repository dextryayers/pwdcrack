use argon2::{Argon2, Algorithm, Version, Params as Argon2Params};
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use scrypt::Scrypt;
use scrypt::password_hash::PasswordHash as ScryptPH;

use super::{HashCracker, HashEntry, HashType, HashParser};

pub struct Argon2iHash;
pub struct Argon2dHash;
pub struct Argon2idHash;
pub struct ScryptHash;

impl HashCracker for Argon2iHash {
    fn hash_type(&self) -> HashType { HashType::Argon2i }
    fn name(&self) -> &'static str { "Argon2i" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        let parsed = PasswordHash::new(&entry.raw).ok();
        match parsed {
            Some(ph) => {
                let argon2 = Argon2::new(Algorithm::Argon2i, Version::V0x13, Argon2Params::default());
                argon2.verify_password(password.as_bytes(), &ph).is_ok()
            }
            None => false,
        }
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
        let parsed = PasswordHash::new(&entry.raw).ok();
        match parsed {
            Some(ph) => {
                let argon2 = Argon2::new(Algorithm::Argon2d, Version::V0x13, Argon2Params::default());
                argon2.verify_password(password.as_bytes(), &ph).is_ok()
            }
            None => false,
        }
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
        let parsed = PasswordHash::new(&entry.raw).ok();
        match parsed {
            Some(ph) => {
                let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, Argon2Params::default());
                argon2.verify_password(password.as_bytes(), &ph).is_ok()
            }
            None => false,
        }
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
