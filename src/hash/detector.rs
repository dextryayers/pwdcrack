use super::{HashCracker, HashEntry, HashType, HashParser};
use super::raw::*;
use super::unix::*;
use super::argon2_scrypt::*;
use super::bcrypt_::*;

/// Auto-detects hash formats and provides matching cracker and parser instances.
pub struct Detector {
    parsers: Vec<Box<dyn HashParser>>,
    crackers: Vec<Box<dyn HashCracker>>,
}

impl Detector {
    /// Creates a new `Detector` pre-loaded with all built-in parsers and crackers.
    pub fn new() -> Self {
        let parsers: Vec<Box<dyn HashParser>> = vec![
            Box::new(Md5Hash),
            Box::new(Sha1Hash),
            Box::new(Sha224Hash),
            Box::new(Sha256Hash),
            Box::new(Sha384Hash),
            Box::new(Sha512Hash),
            Box::new(Sha3_512Hash),
            Box::new(Blake2s256Hash),
            Box::new(Blake2b512Hash),
            Box::new(Ripemd160Hash),
            Box::new(NtlmHash),
            Box::new(LmHash),
            Box::new(Md5Crypt),
            Box::new(Sha256Crypt),
            Box::new(Sha512Crypt),
            Box::new(BcryptHash),
            Box::new(BcryptAHash),
            Box::new(Argon2iHash),
            Box::new(Argon2dHash),
            Box::new(Argon2idHash),
            Box::new(ScryptHash),
        ];
        let crackers: Vec<Box<dyn HashCracker>> = vec![
            Box::new(Md5Hash),
            Box::new(Sha1Hash),
            Box::new(Sha224Hash),
            Box::new(Sha256Hash),
            Box::new(Sha384Hash),
            Box::new(Sha512Hash),
            Box::new(Sha3_512Hash),
            Box::new(Blake2s256Hash),
            Box::new(Blake2b512Hash),
            Box::new(Ripemd160Hash),
            Box::new(NtlmHash),
            Box::new(LmHash),
            Box::new(Md5Crypt),
            Box::new(Sha256Crypt),
            Box::new(Sha512Crypt),
            Box::new(BcryptHash),
            Box::new(BcryptAHash),
            Box::new(Argon2iHash),
            Box::new(Argon2dHash),
            Box::new(Argon2idHash),
            Box::new(ScryptHash),
        ];
        Detector { parsers, crackers }
    }

    /// Identifies a hash string and returns a matching cracker along with its parsed entry.
    pub fn detect(&self, line: &str) -> Option<(Box<dyn HashCracker>, HashEntry)> {
        for parser in &self.parsers {
            if parser.can_parse(line) {
                if let Some(entry) = parser.parse(line) {
                    for cracker in &self.crackers {
                        if cracker.hash_type() == entry.hash_type {
                            return Some((clone_cracker(cracker.as_ref()), entry));
                        }
                    }
                }
            }
        }
        None
    }

    /// Returns a cracker for a specific [`HashType`], if registered.
    pub fn cracker_for_type(&self, hash_type: HashType) -> Option<Box<dyn HashCracker>> {
        self.crackers.iter()
            .find(|c| c.hash_type() == hash_type)
            .map(|c| clone_cracker(c.as_ref()))
    }

    /// Returns a reference to all registered crackers.
    pub fn crackers(&self) -> &[Box<dyn HashCracker>] {
        &self.crackers
    }

    /// Reads a hash file and returns a list of (raw hash, detected type) pairs.
    pub fn identify(&self, path: &str) -> Vec<(String, HashType)> {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        content.lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() { return None; }
                for parser in &self.parsers {
                    if parser.can_parse(trimmed) {
                        if let Some(entry) = parser.parse(trimmed) {
                            return Some((trimmed.to_string(), entry.hash_type));
                        }
                    }
                }
                Some((trimmed.to_string(), HashType::Unknown))
            })
            .collect()
    }
}

fn clone_cracker(c: &dyn HashCracker) -> Box<dyn HashCracker> {
    c.clone_box()
}
