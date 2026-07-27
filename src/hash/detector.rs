use super::{HashCracker, HashEntry, HashType, HashParser};
use super::raw::*;
use super::unix::*;
use super::argon2_scrypt::*;
use super::bcrypt_::*;

pub struct Detector {
    parsers: Vec<Box<dyn HashParser>>,
    crackers: Vec<Box<dyn HashCracker>>,
}

impl Detector {
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

    pub fn cracker_for_type(&self, hash_type: HashType) -> Option<Box<dyn HashCracker>> {
        self.crackers.iter()
            .find(|c| c.hash_type() == hash_type)
            .map(|c| clone_cracker(c.as_ref()))
    }

    pub fn crackers(&self) -> &[Box<dyn HashCracker>] {
        &self.crackers
    }

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
    let t = c.hash_type();
    match t {
        HashType::MD5 => Box::new(Md5Hash),
        HashType::SHA1 => Box::new(Sha1Hash),
        HashType::SHA224 => Box::new(Sha224Hash),
        HashType::SHA256 => Box::new(Sha256Hash),
        HashType::SHA384 => Box::new(Sha384Hash),
        HashType::SHA512 => Box::new(Sha512Hash),
        HashType::SHA3512 => Box::new(Sha3_512Hash),
        HashType::BLAKE2B256 => Box::new(Blake2s256Hash),
        HashType::BLAKE2B512 => Box::new(Blake2b512Hash),
        HashType::RIPEMD160 => Box::new(Ripemd160Hash),
        HashType::NTLM => Box::new(NtlmHash),
        HashType::LM => Box::new(LmHash),
        HashType::MD5Crypt => Box::new(Md5Crypt),
        HashType::SHA256Crypt => Box::new(Sha256Crypt),
        HashType::SHA512Crypt => Box::new(Sha512Crypt),
        HashType::BCrypt => Box::new(BcryptHash),
        HashType::BCryptA => Box::new(BcryptAHash),
        HashType::Argon2i => Box::new(Argon2iHash),
        HashType::Argon2d => Box::new(Argon2dHash),
        HashType::Argon2id => Box::new(Argon2idHash),
        HashType::Scrypt => Box::new(ScryptHash),
        HashType::Unknown => Box::new(Md5Hash),
    }
}
