use bcrypt::verify;
use super::{HashCracker, HashEntry, HashType, HashParser};

/// Cracker and parser for `$2b$` / `$2y$` bcrypt hashes.
pub struct BcryptHash;
/// Cracker and parser for `$2a$` bcrypt hashes.
pub struct BcryptAHash;

impl HashCracker for BcryptHash {
    fn hash_type(&self) -> HashType { HashType::BCrypt }
    fn name(&self) -> &'static str { "bcrypt" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        verify(password, &entry.raw).unwrap_or(false)
    }

    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for BcryptHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let trimmed = line.trim();
        if trimmed.starts_with("$2b$") || trimmed.starts_with("$2y$") {
            Some(HashEntry {
                raw: trimmed.to_string(),
                hash_type: HashType::BCrypt,
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
        let t = line.trim();
        t.starts_with("$2b$") || t.starts_with("$2y$")
    }
}

impl HashCracker for BcryptAHash {
    fn hash_type(&self) -> HashType { HashType::BCryptA }
    fn name(&self) -> &'static str { "bcrypt ($2a$)" }

    fn verify(&self, password: &str, entry: &HashEntry) -> bool {
        verify(password, &entry.raw).unwrap_or(false)
    }

    fn clone_box(&self) -> Box<dyn HashCracker> { Box::new(Self) }
}

impl HashParser for BcryptAHash {
    fn parse(&self, line: &str) -> Option<HashEntry> {
        let trimmed = line.trim();
        if trimmed.starts_with("$2a$") {
            Some(HashEntry {
                raw: trimmed.to_string(),
                hash_type: HashType::BCryptA,
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
        line.trim().starts_with("$2a$")
    }
}
