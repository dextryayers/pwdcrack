pub mod raw;
pub mod unix;
pub mod argon2_scrypt;
pub mod bcrypt_;
pub mod detector;

use std::fmt::Display;

use serde::{Serialize, Deserialize};

/// A single hash entry with its metadata and crack status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashEntry {
    /// The raw hash string as read from the input file.
    pub raw: String,
    /// The detected hash type.
    pub hash_type: HashType,
    /// Decoded bytes of the hash portion (excluding prefix/salt).
    pub hash_bytes: Vec<u8>,
    /// Optional salt extracted from the hash string.
    pub salt: Option<String>,
    /// Optional username extracted from format `user:hash`.
    pub username: Option<String>,
    /// Whether this hash has been cracked.
    pub cracked: bool,
    /// The plaintext password if cracked, or `None`.
    pub password: Option<String>,
}

/// Supported hash algorithms and format variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HashType {
    /// MD5 (128-bit hex digest).
    MD5,
    /// Unix `$1$` MD5-based crypt.
    MD5Crypt,
    /// SHA-1 (160-bit hex digest).
    SHA1,
    /// SHA-224 (224-bit hex digest).
    SHA224,
    /// SHA-256 (256-bit hex digest).
    SHA256,
    /// Unix `$5$` SHA-256 crypt.
    SHA256Crypt,
    /// SHA-384 (384-bit hex digest).
    SHA384,
    /// SHA-512 (512-bit hex digest).
    SHA512,
    /// Unix `$6$` SHA-512 crypt.
    SHA512Crypt,
    /// SHA3-512 (512-bit hex digest).
    SHA3512,
    /// BLAKE2b-256 (256-bit hex digest).
    BLAKE2B256,
    /// BLAKE2b-512 (512-bit hex digest).
    BLAKE2B512,
    /// RIPEMD-160 (160-bit hex digest).
    RIPEMD160,
    /// NTLM (MD4-based Windows NT hash, 128-bit hex).
    NTLM,
    /// LM (DES-based LAN Manager hash).
    LM,
    /// bcrypt `$2b$` / `$2y$` variant.
    BCrypt,
    /// bcrypt `$2a$` variant.
    BCryptA,
    /// Argon2i (data-independent memory-hard hash).
    Argon2i,
    /// Argon2d (data-dependent memory-hard hash).
    Argon2d,
    /// Argon2id (hybrid memory-hard hash).
    Argon2id,
    /// scrypt (memory-hard key-derivation function).
    Scrypt,
    /// Unrecognized or unsupported hash format.
    Unknown,
}

impl HashType {
    /// Returns a human-readable display name for this hash type.
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

    /// Returns the bit length of the hash output, if applicable.
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

/// Provides hash verification against candidate passwords.
pub trait HashCracker: Send + Sync {
    /// Returns the [`HashType`] this cracker handles.
    fn hash_type(&self) -> HashType;
    /// Returns `true` if `password` matches the given hash entry.
    fn verify(&self, password: &str, hash: &HashEntry) -> bool;
    /// Returns a human-readable name for this cracker.
    fn name(&self) -> &'static str;
    /// Returns a boxed clone of this cracker.
    fn clone_box(&self) -> Box<dyn HashCracker>;
}

/// Parses raw hash strings into [`HashEntry`] values.
pub trait HashParser: Send + Sync {
    /// Parses a hash line into a [`HashEntry`], or `None` if the format is unrecognised.
    fn parse(&self, line: &str) -> Option<HashEntry>;
    /// Returns `true` if the line looks like a hash this parser understands.
    fn can_parse(&self, line: &str) -> bool;
}
