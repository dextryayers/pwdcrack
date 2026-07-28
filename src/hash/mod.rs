pub mod app;
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
    /// SHA-512/224 (224-bit truncated SHA-512).
    SHA512_224,
    /// SHA-512/256 (256-bit truncated SHA-512).
    SHA512_256,
    /// Unix `$6$` SHA-512 crypt.
    SHA512Crypt,
    /// SHA3-224 (224-bit hex digest).
    SHA3224,
    /// SHA3-256 (256-bit hex digest).
    SHA3256,
    /// SHA3-384 (384-bit hex digest).
    SHA3384,
    /// SHA3-512 (512-bit hex digest).
    SHA3512,
    /// BLAKE2b-256 (256-bit hex digest).
    BLAKE2B256,
    /// BLAKE2s-256 (256-bit hex digest, 32-bit variant).
    BLAKE2S256,
    /// BLAKE2b-512 (512-bit hex digest).
    BLAKE2B512,
    /// RIPEMD-128 (128-bit hex digest).
    RIPEMD128,
    /// RIPEMD-160 (160-bit hex digest).
    RIPEMD160,
    /// RIPEMD-256 (256-bit hex digest).
    RIPEMD256,
    /// RIPEMD-320 (320-bit hex digest).
    RIPEMD320,
    /// MD2 (128-bit hex digest).
    MD2,
    /// MD4 (128-bit hex digest).
    MD4,
    /// Whirlpool (512-bit hex digest).
    WHIRLPOOL,
    /// Streebog (GOST R 34.11-2012) 256-bit hex digest.
    STREEBOG256,
    /// Streebog (GOST R 34.11-2012) 512-bit hex digest.
    STREEBOG512,
    /// Tiger-192 (192-bit hex digest).
    TIGER192,
    /// JH-224 (224-bit hex digest).
    JH224,
    /// JH-256 (256-bit hex digest).
    JH256,
    /// JH-384 (384-bit hex digest).
    JH384,
    /// JH-512 (512-bit hex digest).
    JH512,
    /// Skein-256 (256-bit hex digest).
    SKEIN256,
    /// Skein-512 (512-bit hex digest).
    SKEIN512,
    /// Shabal-192 (192-bit hex digest).
    SHABAL192,
    /// Shabal-224 (224-bit hex digest).
    SHABAL224,
    /// Shabal-256 (256-bit hex digest).
    SHABAL256,
    /// Shabal-384 (384-bit hex digest).
    SHABAL384,
    /// Shabal-512 (512-bit hex digest).
    SHABAL512,
    /// GOST R 34.11-94 256-bit hex digest.
    GOST94256,
    /// GOST R 34.11-94 512-bit hex digest.
    GOST94512,
    /// BLAKE2b-384 (384-bit hex digest).
    BLAKE2B384,
    /// BLAKE2b-224 (224-bit hex digest).
    BLAKE2B224,
    /// BLAKE2b-160 (160-bit hex digest).
    BLAKE2B160,
    /// BLAKE2s-128 (128-bit hex digest).
    BLAKE2S128,
    /// BLAKE2s-160 (160-bit hex digest).
    BLAKE2S160,
    /// BLAKE3-256 (256-bit hex digest).
    BLAKE3256,
    /// Apache MD5 (`$apr1$`).
    APR1MD5,
    /// PHPass / WordPress (`$P$` / `$H$`).
    PHPASS,
    /// Drupal 7 (`$S$`).
    DRUPAL7,
    /// osCommerce / xt:Commerce / AEF.
    OSCOMMERCE,
    /// PostgreSQL MD5.
    POSTGRESQL,
    /// MySQL 4.1/5.x.
    MYSQL41,
    /// Oracle 10g.
    ORACLE10G,
    /// Oracle 11g/12c.
    ORACLE11G,
    /// MSSQL 2005.
    MSSQL2005,
    /// MSSQL 2012.
    MSSQL2012,
    /// vBulletin 3.x/4.x.
    VBULLETIN3,
    /// vBulletin 5.x.
    VBULLETIN5,
    /// SMF 1.x/2.x.
    SMF,
    /// IPB 2.x / MyBB 1.x.
    IPB2,
    /// IPB 3.x+.
    IPB3,
    /// MediaWiki.
    MEDIAWIKI,
    /// Cisco PIX hash.
    CISCOPIX,
    /// Cisco Type 5 (enable secret).
    CISCO5,
    /// HMAC-SHA1.
    HMACSHA1,
    /// HMAC-SHA256.
    HMACSHA256,
    /// HMAC-MD5.
    HMACMD5,
    /// HMAC-SHA512.
    HMACSHA512,
    /// HMAC-SHA224.
    HMACSHA224,
    /// HMAC-SHA384.
    HMACSHA384,
    /// HMAC-RIPEMD160.
    HMACRIPEMD160,
    /// PBKDF2-HMAC-SHA256.
    PBKDF2SHA256,
    /// PBKDF2-HMAC-SHA512.
    PBKDF2SHA512,
    /// PBKDF2-HMAC-SHA1.
    PBKDF2SHA1,
    /// DCC1 (Domain Cached Credentials).
    DCC1,
    /// DCC2 (Domain Cached Credentials 2).
    DCC2,
    /// NTLMv2.
    NTLMV2,
    /// Salted MD5 (MD5(password + salt)).
    SALTEDMD5,
    /// Salted SHA-1 (SHA1(password + salt)).
    SALTEDSHA1,
    /// Salted SHA-256 (SHA256(password + salt)).
    SALTEDSHA256,
    /// Salted SHA-512 (SHA512(password + salt)).
    SALTEDSHA512,
    /// Salted SHA-384 (SHA384(password + salt)).
    SALTEDSHA384,
    /// Double MD5 (MD5(MD5(password))).
    DOUBLEMD5,
    /// Double SHA-1 (SHA1(SHA1(password))).
    DOUBLESHA1,
    /// Double SHA-256 (SHA256(SHA256(password))).
    DOUBLESHA256,
    /// {SHA} base64-encoded SHA-1.
    SHA1DASH,
    /// LDAP SSHA1 (Salted SHA1 in base64).
    SSHA1,
    /// LDAP SSHA256 (Salted SHA256 in base64).
    SSHA256,
    /// CRC8 checksum.
    CRC8,
    /// CRC16 checksum.
    CRC16,
    /// CRC32C (Castagnoli) checksum.
    CRC32C,
    /// CRC32 checksum.
    CRC32,
    /// CRC64 checksum.
    CRC64,
    /// Adler-32 checksum.
    ADLER32,
    /// macOS 10.8+ PBKDF2.
    MACOSPBKDF2,
    /// Sun MD5 Crypt (`$md5$`).
    SUNMD5,
    /// BSDi Crypt (`_`).
    BSDICRYPT,
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
            HashType::SHA512_224 => "SHA-512/224",
            HashType::SHA512_256 => "SHA-512/256",
            HashType::SHA512Crypt => "SHA-512 Crypt",
            HashType::SHA3224 => "SHA3-224",
            HashType::SHA3256 => "SHA3-256",
            HashType::SHA3384 => "SHA3-384",
            HashType::SHA3512 => "SHA3-512",
            HashType::BLAKE2B256 => "BLAKE2b-256",
            HashType::BLAKE2S256 => "BLAKE2s-256",
            HashType::BLAKE2B512 => "BLAKE2b-512",
            HashType::RIPEMD128 => "RIPEMD-128",
            HashType::RIPEMD160 => "RIPEMD-160",
            HashType::RIPEMD256 => "RIPEMD-256",
            HashType::RIPEMD320 => "RIPEMD-320",
            HashType::MD2 => "MD2",
            HashType::MD4 => "MD4",
            HashType::WHIRLPOOL => "Whirlpool",
            HashType::STREEBOG256 => "Streebog-256",
            HashType::STREEBOG512 => "Streebog-512",
            HashType::TIGER192 => "Tiger-192",
            HashType::JH224 => "JH-224",
            HashType::JH256 => "JH-256",
            HashType::JH384 => "JH-384",
            HashType::JH512 => "JH-512",
            HashType::SKEIN256 => "Skein-256",
            HashType::SKEIN512 => "Skein-512",
            HashType::SHABAL192 => "Shabal-192",
            HashType::SHABAL224 => "Shabal-224",
            HashType::SHABAL256 => "Shabal-256",
            HashType::SHABAL384 => "Shabal-384",
            HashType::SHABAL512 => "Shabal-512",
            HashType::GOST94256 => "GOST94-256",
            HashType::GOST94512 => "GOST94-512",
            HashType::BLAKE2B384 => "BLAKE2b-384",
            HashType::BLAKE2B224 => "BLAKE2b-224",
            HashType::BLAKE2B160 => "BLAKE2b-160",
            HashType::BLAKE2S128 => "BLAKE2s-128",
            HashType::BLAKE2S160 => "BLAKE2s-160",
            HashType::BLAKE3256 => "BLAKE3-256",
            HashType::APR1MD5 => "Apache MD5",
            HashType::PHPASS => "PHPass",
            HashType::DRUPAL7 => "Drupal 7",
            HashType::OSCOMMERCE => "osCommerce",
            HashType::POSTGRESQL => "PostgreSQL MD5",
            HashType::MYSQL41 => "MySQL 4.1/5.x",
            HashType::ORACLE10G => "Oracle 10g",
            HashType::ORACLE11G => "Oracle 11g/12c",
            HashType::MSSQL2005 => "MSSQL 2005",
            HashType::MSSQL2012 => "MSSQL 2012",
            HashType::VBULLETIN3 => "vBulletin 3/4",
            HashType::VBULLETIN5 => "vBulletin 5",
            HashType::SMF => "SMF 1/2",
            HashType::IPB2 => "IPB 2 / MyBB",
            HashType::IPB3 => "IPB 3+",
            HashType::MEDIAWIKI => "MediaWiki",
            HashType::CISCOPIX => "Cisco PIX",
            HashType::CISCO5 => "Cisco Type 5",
            HashType::HMACSHA1 => "HMAC-SHA1",
            HashType::HMACSHA256 => "HMAC-SHA256",
            HashType::HMACMD5 => "HMAC-MD5",
            HashType::HMACSHA512 => "HMAC-SHA512",
            HashType::HMACSHA224 => "HMAC-SHA224",
            HashType::HMACSHA384 => "HMAC-SHA384",
            HashType::HMACRIPEMD160 => "HMAC-RIPEMD160",
            HashType::PBKDF2SHA256 => "PBKDF2-SHA256",
            HashType::PBKDF2SHA512 => "PBKDF2-SHA512",
            HashType::PBKDF2SHA1 => "PBKDF2-SHA1",
            HashType::DCC1 => "DCC1",
            HashType::DCC2 => "DCC2",
            HashType::NTLMV2 => "NTLMv2",
            HashType::SALTEDMD5 => "Salted MD5",
            HashType::SALTEDSHA1 => "Salted SHA-1",
            HashType::SALTEDSHA256 => "Salted SHA-256",
            HashType::SALTEDSHA512 => "Salted SHA-512",
            HashType::SALTEDSHA384 => "Salted SHA-384",
            HashType::DOUBLEMD5 => "Double MD5",
            HashType::DOUBLESHA1 => "Double SHA-1",
            HashType::DOUBLESHA256 => "Double SHA-256",
            HashType::SHA1DASH => "{SHA}",
            HashType::SSHA1 => "SSHA-1",
            HashType::SSHA256 => "SSHA-256",
            HashType::CRC8 => "CRC8",
            HashType::CRC16 => "CRC16",
            HashType::CRC32C => "CRC32C",
            HashType::ADLER32 => "Adler-32",
            HashType::CRC32 => "CRC32",
            HashType::CRC64 => "CRC64",
            HashType::MACOSPBKDF2 => "macOS PBKDF2",
            HashType::SUNMD5 => "Sun MD5",
            HashType::BSDICRYPT => "BSDi Crypt",
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
            HashType::SHA512_224 => Some(224),
            HashType::SHA512_256 => Some(256),
            HashType::SHA3224 => Some(224),
            HashType::SHA3256 => Some(256),
            HashType::SHA3384 => Some(384),
            HashType::SHA3512 => Some(512),
            HashType::BLAKE2B256 => Some(256),
            HashType::BLAKE2S256 => Some(256),
            HashType::BLAKE2B512 => Some(512),
            HashType::RIPEMD128 => Some(128),
            HashType::RIPEMD160 => Some(160),
            HashType::RIPEMD256 => Some(256),
            HashType::RIPEMD320 => Some(320),
            HashType::MD2 => Some(128),
            HashType::MD4 => Some(128),
            HashType::WHIRLPOOL => Some(512),
            HashType::STREEBOG256 => Some(256),
            HashType::STREEBOG512 => Some(512),
            HashType::TIGER192 => Some(192),
            HashType::JH224 => Some(224),
            HashType::JH256 => Some(256),
            HashType::JH384 => Some(384),
            HashType::JH512 => Some(512),
            HashType::SKEIN256 => Some(256),
            HashType::SKEIN512 => Some(512),
            HashType::SHABAL192 => Some(192),
            HashType::SHABAL224 => Some(224),
            HashType::SHABAL256 => Some(256),
            HashType::SHABAL384 => Some(384),
            HashType::SHABAL512 => Some(512),
            HashType::GOST94256 => Some(256),
            HashType::GOST94512 => Some(512),
            HashType::BLAKE2B384 => Some(384),
            HashType::BLAKE2B224 => Some(224),
            HashType::BLAKE2B160 => Some(160),
            HashType::BLAKE2S128 => Some(128),
            HashType::BLAKE2S160 => Some(160),
            HashType::BLAKE3256 => Some(256),
            HashType::CRC8 => Some(8),
            HashType::CRC16 => Some(16),
            HashType::CRC32 => Some(32),
            HashType::CRC32C => Some(32),
            HashType::ADLER32 => Some(32),
            HashType::CRC64 => Some(64),
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
