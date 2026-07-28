pub mod raw;
pub mod unix;
pub mod argon2_scrypt;
pub mod bcrypt_;
pub mod detector;

use std::fmt::Display;

use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashEntry {
    pub raw: String,
    pub hash_type: HashType,
    pub hash_bytes: Vec<u8>,
    pub salt: Option<String>,
    pub username: Option<String>,
    pub cracked: bool,
    pub password: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HashType {
    MD5,
    MD5Crypt,
    SHA1,
    SHA224,
    SHA256,
    SHA256Crypt,
    SHA384,
    SHA512,
    SHA512Crypt,
    SHA3512,
    BLAKE2B256,
    BLAKE2B512,
    RIPEMD160,
    NTLM,
    LM,
    BCrypt,
    BCryptA,
    Argon2i,
    Argon2d,
    Argon2id,
    Scrypt,
    Unknown,
}

impl HashType {
    pub fn name(&self) -> &'static str {
        match self {
            HashType::MD5 => "MD5",
            HashType::MD5Crypt => "MD5 Crypt",
            HashType::SHA1 => "SHA-1",
            HashType::SHA224 => "SHA-224",
            HashType::SHA256 => "SHA-256",
            HashType::SHA256Crypt => "SHA-256 Crypt",
            HashType::SHA384 => "SHA-384",
            HashType::SHA512 => "SHA-512",
            HashType::SHA512Crypt => "SHA-512 Crypt",
            HashType::SHA3512 => "SHA3-512",
            HashType::BLAKE2B256 => "BLAKE2b-256",
            HashType::BLAKE2B512 => "BLAKE2b-512",
            HashType::RIPEMD160 => "RIPEMD-160",
            HashType::NTLM => "NTLM",
            HashType::LM => "LM",
            HashType::BCrypt => "bcrypt",
            HashType::BCryptA => "bcrypt ($2a$)",
            HashType::Argon2i => "Argon2i",
            HashType::Argon2d => "Argon2d",
            HashType::Argon2id => "Argon2id",
            HashType::Scrypt => "scrypt",
            HashType::Unknown => "Unknown",
        }
    }

    pub fn bit_length(&self) -> Option<usize> {
        match self {
            HashType::MD5 => Some(128),
            HashType::SHA1 => Some(160),
            HashType::SHA224 => Some(224),
            HashType::SHA256 => Some(256),
            HashType::SHA384 => Some(384),
            HashType::SHA512 => Some(512),
            HashType::SHA3512 => Some(512),
            HashType::BLAKE2B256 => Some(256),
            HashType::BLAKE2B512 => Some(512),
            HashType::RIPEMD160 => Some(160),
            HashType::NTLM => Some(128),
            HashType::LM => Some(64),
            _ => None,
        }
    }
}

impl Display for HashType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

pub trait HashCracker: Send + Sync {
    fn hash_type(&self) -> HashType;
    fn verify(&self, password: &str, hash: &HashEntry) -> bool;
    fn name(&self) -> &'static str;
}

pub trait HashParser: Send + Sync {
    fn parse(&self, line: &str) -> Option<HashEntry>;
    fn can_parse(&self, line: &str) -> bool;
}
