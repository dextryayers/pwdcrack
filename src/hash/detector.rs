use super::{HashCracker, HashEntry, HashType, HashParser};
use super::app::*;
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
            Box::new(Sha512_224Hash),
            Box::new(Sha512_256Hash),
            Box::new(Sha3_224Hash),
            Box::new(Sha3_256Hash),
            Box::new(Sha3_384Hash),
            Box::new(Sha3_512Hash),
            Box::new(Blake2b256Hash),
            Box::new(Blake2s256Hash),
            Box::new(Blake2b512Hash),
            Box::new(Blake2b384Hash),
            Box::new(Blake2b224Hash),
            Box::new(Blake2b160Hash),
            Box::new(Blake2s128Hash),
            Box::new(Blake2s160Hash),
            Box::new(Ripemd128Hash),
            Box::new(Ripemd160Hash),
            Box::new(Ripemd256Hash),
            Box::new(Ripemd320Hash),
            Box::new(WhirlpoolHash),
            Box::new(Streebog256Hash),
            Box::new(Streebog512Hash),
            Box::new(Tiger192Hash),
            Box::new(Jh224Hash),
            Box::new(Jh256Hash),
            Box::new(Jh384Hash),
            Box::new(Jh512Hash),
            Box::new(Skein256Hash),
            Box::new(Skein512Hash),
            Box::new(Shabal192Hash),
            Box::new(Shabal224Hash),
            Box::new(Shabal256Hash),
            Box::new(Shabal384Hash),
            Box::new(Shabal512Hash),
            Box::new(Gost94CryptoProHash),
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
            Box::new(Md4Hash),
            Box::new(Blake3Hash),
            Box::new(Crc32Hash),
            Box::new(Crc64Hash),
            Box::new(Apr1Hash),
            Box::new(Mysql41Hash),
            Box::new(PostgresqlHash),
            Box::new(PhpassHash),
            Box::new(Drupal7Hash),
            Box::new(OscommerceHash),
            Box::new(Oracle10gHash),
            Box::new(Oracle11gHash),
            Box::new(Mssql2005Hash),
            Box::new(Mssql2012Hash),
            Box::new(Vbulletin3Hash),
            Box::new(Vbulletin5Hash),
            Box::new(SmfHash),
            Box::new(Ipb2Hash),
            Box::new(Ipb3Hash),
            Box::new(MediawikiHash),
            Box::new(CiscoPixHash),
            Box::new(Cisco5Hash),
            Box::new(Dcc1Hash),
            Box::new(Dcc2Hash),
            Box::new(Ntlmv2Hash),
            Box::new(SunMd5Hash),
            Box::new(BsdiCryptHash),
            Box::new(MacosPbkdf2Hash),
            Box::new(HmacSha1Hash),
            Box::new(HmacSha256Hash),
            Box::new(HmacMd5Hash),
            Box::new(HmacSha512Hash),
            Box::new(HmacSha224Hash),
            Box::new(HmacSha384Hash),
            Box::new(HmacRipemd160Hash),
            Box::new(Pbkdf2Sha256Hash),
            Box::new(Pbkdf2Sha512Hash),
            Box::new(Pbkdf2Sha1Hash),
            Box::new(SaltedMd5Hash),
            Box::new(SaltedSha1Hash),
            Box::new(SaltedSha256Hash),
            Box::new(SaltedSha512Hash),
            Box::new(DoubleMd5Hash),
            Box::new(DoubleSha1Hash),
            Box::new(DoubleSha256Hash),
            Box::new(Sha1DashHash),
            Box::new(Ssha1Hash),
            Box::new(Ssha256Hash),
            Box::new(Crc16Hash),
            Box::new(Crc8Hash),
            Box::new(Crc32cHash),
            Box::new(Adler32Hash),
            Box::new(SaltedSha384Hash),
        ];
        let crackers: Vec<Box<dyn HashCracker>> = vec![
            Box::new(Md5Hash),
            Box::new(Sha1Hash),
            Box::new(Sha224Hash),
            Box::new(Sha256Hash),
            Box::new(Sha384Hash),
            Box::new(Sha512Hash),
            Box::new(Sha512_224Hash),
            Box::new(Sha512_256Hash),
            Box::new(Sha3_224Hash),
            Box::new(Sha3_256Hash),
            Box::new(Sha3_384Hash),
            Box::new(Sha3_512Hash),
            Box::new(Blake2b256Hash),
            Box::new(Blake2s256Hash),
            Box::new(Blake2b512Hash),
            Box::new(Blake2b384Hash),
            Box::new(Blake2b224Hash),
            Box::new(Blake2b160Hash),
            Box::new(Blake2s128Hash),
            Box::new(Blake2s160Hash),
            Box::new(Ripemd128Hash),
            Box::new(Ripemd160Hash),
            Box::new(Ripemd256Hash),
            Box::new(Ripemd320Hash),
            Box::new(WhirlpoolHash),
            Box::new(Streebog256Hash),
            Box::new(Streebog512Hash),
            Box::new(Tiger192Hash),
            Box::new(Jh224Hash),
            Box::new(Jh256Hash),
            Box::new(Jh384Hash),
            Box::new(Jh512Hash),
            Box::new(Skein256Hash),
            Box::new(Skein512Hash),
            Box::new(Shabal192Hash),
            Box::new(Shabal224Hash),
            Box::new(Shabal256Hash),
            Box::new(Shabal384Hash),
            Box::new(Shabal512Hash),
            Box::new(Gost94CryptoProHash),
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
            Box::new(Md4Hash),
            Box::new(Blake3Hash),
            Box::new(Crc32Hash),
            Box::new(Crc64Hash),
            Box::new(Apr1Hash),
            Box::new(Mysql41Hash),
            Box::new(PostgresqlHash),
            Box::new(PhpassHash),
            Box::new(Drupal7Hash),
            Box::new(OscommerceHash),
            Box::new(Oracle10gHash),
            Box::new(Oracle11gHash),
            Box::new(Mssql2005Hash),
            Box::new(Mssql2012Hash),
            Box::new(Vbulletin3Hash),
            Box::new(Vbulletin5Hash),
            Box::new(SmfHash),
            Box::new(Ipb2Hash),
            Box::new(Ipb3Hash),
            Box::new(MediawikiHash),
            Box::new(CiscoPixHash),
            Box::new(Cisco5Hash),
            Box::new(Dcc1Hash),
            Box::new(Dcc2Hash),
            Box::new(Ntlmv2Hash),
            Box::new(SunMd5Hash),
            Box::new(BsdiCryptHash),
            Box::new(MacosPbkdf2Hash),
            Box::new(HmacSha1Hash),
            Box::new(HmacSha256Hash),
            Box::new(HmacMd5Hash),
            Box::new(HmacSha512Hash),
            Box::new(HmacSha224Hash),
            Box::new(HmacSha384Hash),
            Box::new(HmacRipemd160Hash),
            Box::new(Pbkdf2Sha256Hash),
            Box::new(Pbkdf2Sha512Hash),
            Box::new(Pbkdf2Sha1Hash),
            Box::new(SaltedMd5Hash),
            Box::new(SaltedSha1Hash),
            Box::new(SaltedSha256Hash),
            Box::new(SaltedSha512Hash),
            Box::new(DoubleMd5Hash),
            Box::new(DoubleSha1Hash),
            Box::new(DoubleSha256Hash),
            Box::new(Sha1DashHash),
            Box::new(Ssha1Hash),
            Box::new(Ssha256Hash),
            Box::new(Crc16Hash),
            Box::new(Crc8Hash),
            Box::new(Crc32cHash),
            Box::new(Adler32Hash),
            Box::new(SaltedSha384Hash),
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
