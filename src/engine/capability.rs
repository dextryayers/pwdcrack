//! Algorithm capability declarations.
//!
//! An engine must state which hash families it implements. This exists because
//! the previous design let an engine accept any work: `engine-tensor` and
//! `engine-warp` reported `is_available() == true` unconditionally and then ran
//! a scalar CPU MD5 loop, so the scheduler believed hardware acceleration was in
//! use when none was.
//!
//! Declaring capabilities is how that class of lie becomes impossible to
//! express. [`CapabilitySet`] is a small bitset carried in [`crate::engine::EngineInfo`],
//! and the scheduler never routes a hash type to an engine that did not declare
//! it.
//!
//! Adding a capability means adding a variant and a bit. Nothing else changes.

use std::fmt;

/// One algorithm an engine can verify.
///
/// Grouped by family rather than by individual type, because engines implement
/// whole families. A GPU that runs MD5 runs every MD5 variant; an engine that
/// implements the Blowfish core runs bcrypt.
///
/// The families are deliberately coarse. A finer list would be more precise but
/// would need a variant per hash type, which is 354 variants and a maintenance
/// burden that guarantees the list goes stale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Capability {
    /// MD2, MD4, MD5 and their salted and truncated variants.
    Md,
    /// SHA-1.
    Sha1,
    /// SHA-224, SHA-256.
    Sha2_256,
    /// SHA-384, SHA-512.
    Sha2_512,
    /// SHA-3 and Keccak.
    Sha3,
    /// BLAKE2b, BLAKE2s, BLAKE3.
    Blake,
    /// RIPEMD-128, RIPEMD-160, RIPEMD-256, RIPEMD-320.
    Ripemd,
    /// Whirlpool.
    Whirlpool,
    /// Streebog 256 and 512.
    Streebog,
    /// GOST R 34.11 and GOST 94.
    Gost,
    /// Tiger and Tiger2.
    Tiger,
    /// Skein 256 and 512.
    Skein,
    /// NTLM, which is MD4 with a different initialisation.
    Ntlm,
    /// HMAC of any supported digest.
    Hmac,
    /// PBKDF2 with any supported digest.
    Pbkdf2,
    /// bcrypt and its variants.
    Bcrypt,
    /// Argon2i, Argon2d, Argon2id.
    Argon2,
    /// scrypt.
    Scrypt,
    /// The traditional DES based crypt, and BSDi crypt.
    DesCrypt,
    /// The MD5 and SHA crypt variants, `$1$`, `$5$`, and `$6$`.
    UnixCrypt,
    /// Any non cryptographic checksum.
    Checksum,
    /// Masks over printable ASCII. Most engines can do this for free.
    MaskAscii,
    /// Masks over arbitrary bytes, which needs a wider candidate buffer.
    MaskBytes,
    /// Applying mangling rules.
    RuleApply,
}

impl Capability {
    /// Every capability, used by tests and by the exhaustive checker.
    pub const ALL: &'static [Capability] = &[
        Capability::Md,
        Capability::Sha1,
        Capability::Sha2_256,
        Capability::Sha2_512,
        Capability::Sha3,
        Capability::Blake,
        Capability::Ripemd,
        Capability::Whirlpool,
        Capability::Streebog,
        Capability::Gost,
        Capability::Tiger,
        Capability::Skein,
        Capability::Ntlm,
        Capability::Hmac,
        Capability::Pbkdf2,
        Capability::Bcrypt,
        Capability::Argon2,
        Capability::Scrypt,
        Capability::DesCrypt,
        Capability::UnixCrypt,
        Capability::Checksum,
        Capability::MaskAscii,
        Capability::MaskBytes,
        Capability::RuleApply,
    ];

    /// Bit position in the bitset.
    fn bit(self) -> usize {
        match self {
            Capability::Md => 0,
            Capability::Sha1 => 1,
            Capability::Sha2_256 => 2,
            Capability::Sha2_512 => 3,
            Capability::Sha3 => 4,
            Capability::Blake => 5,
            Capability::Ripemd => 6,
            Capability::Whirlpool => 7,
            Capability::Streebog => 8,
            Capability::Gost => 9,
            Capability::Tiger => 10,
            Capability::Skein => 11,
            Capability::Ntlm => 12,
            Capability::Hmac => 13,
            Capability::Pbkdf2 => 14,
            Capability::Bcrypt => 15,
            Capability::Argon2 => 16,
            Capability::Scrypt => 17,
            Capability::DesCrypt => 18,
            Capability::UnixCrypt => 19,
            Capability::Checksum => 20,
            Capability::MaskAscii => 21,
            Capability::MaskBytes => 22,
            Capability::RuleApply => 23,
        }
    }

    /// Short stable name for logs and `doctor` output.
    pub fn short_name(self) -> &'static str {
        match self {
            Capability::Md => "md",
            Capability::Sha1 => "sha1",
            Capability::Sha2_256 => "sha256",
            Capability::Sha2_512 => "sha512",
            Capability::Sha3 => "sha3",
            Capability::Blake => "blake",
            Capability::Ripemd => "ripemd",
            Capability::Whirlpool => "whirlpool",
            Capability::Streebog => "streebog",
            Capability::Gost => "gost",
            Capability::Tiger => "tiger",
            Capability::Skein => "skein",
            Capability::Ntlm => "ntlm",
            Capability::Hmac => "hmac",
            Capability::Pbkdf2 => "pbkdf2",
            Capability::Bcrypt => "bcrypt",
            Capability::Argon2 => "argon2",
            Capability::Scrypt => "scrypt",
            Capability::DesCrypt => "descrypt",
            Capability::UnixCrypt => "unixcrypt",
            Capability::Checksum => "checksum",
            Capability::MaskAscii => "mask-ascii",
            Capability::MaskBytes => "mask-bytes",
            Capability::RuleApply => "rules",
        }
    }

    /// Whether this capability needs a lot of memory per candidate.
    ///
    /// The scheduler uses this to avoid putting memory hard work on a device
    /// that cannot hold it.
    pub fn is_memory_hard(self) -> bool {
        matches!(
            self,
            Capability::Argon2 | Capability::Scrypt | Capability::Bcrypt | Capability::Pbkdf2
        )
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.short_name())
    }
}

/// The set of capabilities an engine declares.
///
/// A small bitset rather than a `HashSet`, so cloning it for every
/// [`crate::engine::EngineInfo`] copy is two words rather than a heap
/// allocation. [`crate::engine::EngineInfo`] is cloned on every scheduling
/// decision, so this matters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapabilitySet {
    bits: u32,
}

impl CapabilitySet {
    /// Number of capabilities that exist. A `u32` holds 24, leaving headroom.
    pub const WIDTH: usize = 24;

    /// An empty set.
    pub fn empty() -> Self {
        CapabilitySet { bits: 0 }
    }

    /// A set containing every capability. Used by the CPU fallback and by tests.
    pub fn all() -> Self {
        let mut s = CapabilitySet::empty();
        for c in Capability::ALL {
            s.insert(*c);
        }
        s
    }

    /// The set a portable CPU implementation can reasonably claim.
    ///
    /// This deliberately excludes `UnixCrypt`, because the implementation in
    /// `src/hash/unix.rs` is not correct yet and claiming it would be a lie. See
    /// `docs/UNIX_CRYPT_STATUS.md`.
    pub fn baseline() -> Self {
        let mut s = CapabilitySet::empty();
        for c in [
            Capability::Md,
            Capability::Sha1,
            Capability::Sha2_256,
            Capability::Sha2_512,
            Capability::Sha3,
            Capability::Blake,
            Capability::Ripemd,
            Capability::Whirlpool,
            Capability::Streebog,
            Capability::Gost,
            Capability::Tiger,
            Capability::Skein,
            Capability::Ntlm,
            Capability::Hmac,
            Capability::Pbkdf2,
            Capability::Bcrypt,
            Capability::Argon2,
            Capability::Scrypt,
            Capability::DesCrypt,
            Capability::Checksum,
            Capability::MaskAscii,
            Capability::MaskBytes,
            Capability::RuleApply,
        ] {
            s.insert(c);
        }
        s
    }

    /// Adds one capability.
    pub fn insert(&mut self, c: Capability) -> &mut Self {
        self.bits |= 1 << c.bit();
        self
    }

    /// Removes one capability.
    pub fn remove(&mut self, c: Capability) -> &mut Self {
        self.bits &= !(1 << c.bit());
        self
    }

    /// Whether a capability is present.
    pub fn contains(&self, c: Capability) -> bool {
        self.bits & (1 << c.bit()) != 0
    }

    /// Whether the set has nothing in it.
    pub fn is_empty(&self) -> bool {
        self.bits == 0
    }

    /// How many capabilities are present.
    pub fn len(&self) -> usize {
        self.bits.count_ones() as usize
    }

    /// Every present capability, in declaration order.
    pub fn iter(&self) -> impl Iterator<Item = Capability> + '_ {
        Capability::ALL.iter().copied().filter(move |c| self.contains(*c))
    }

    /// Comma separated short names, for `doctor` output.
    pub fn names(&self) -> String {
        self.iter().map(|c| c.short_name()).collect::<Vec<_>>().join(",")
    }

    /// Union of two sets.
    pub fn union(&self, other: &CapabilitySet) -> CapabilitySet {
        CapabilitySet { bits: self.bits | other.bits }
    }
}

impl fmt::Display for CapabilitySet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.names())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_contains_are_inverses() {
        let mut s = CapabilitySet::empty();
        assert!(!s.contains(Capability::Md));
        s.insert(Capability::Md);
        assert!(s.contains(Capability::Md));
        s.remove(Capability::Md);
        assert!(!s.contains(Capability::Md));
    }

    #[test]
    fn every_capability_has_a_unique_bit() {
        // Two capabilities sharing a bit would silently alias, so the test walks
        // all of them and checks the set length equals the insert count.
        let mut s = CapabilitySet::empty();
        for c in Capability::ALL {
            s.insert(*c);
        }
        assert_eq!(s.len(), Capability::ALL.len());
    }

    #[test]
    fn short_names_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for c in Capability::ALL {
            assert!(seen.insert(c.short_name()), "duplicate name for {c:?}");
        }
    }

    #[test]
    fn all_contains_every_capability() {
        let all = CapabilitySet::all();
        for c in Capability::ALL {
            assert!(all.contains(*c), "all() is missing {c}");
        }
        assert_eq!(all.len(), Capability::ALL.len());
    }

    #[test]
    fn baseline_excludes_unixcrypt_which_is_not_correct_yet() {
        let b = CapabilitySet::baseline();
        assert!(
            !b.contains(Capability::UnixCrypt),
            "baseline must not claim unix crypt while it returns false unconditionally"
        );
        assert!(b.contains(Capability::Md));
    }

    #[test]
    fn empty_set_reports_empty() {
        let e = CapabilitySet::empty();
        assert!(e.is_empty());
        assert_eq!(e.len(), 0);
        assert_eq!(e.names(), "");
    }

    #[test]
    fn iteration_is_in_declaration_order() {
        let mut s = CapabilitySet::empty();
        s.insert(Capability::Sha3);
        s.insert(Capability::Md);
        let names: Vec<&str> = s.iter().map(|c| c.short_name()).collect();
        assert_eq!(names, vec!["md", "sha3"]);
    }

    #[test]
    fn memory_hard_capabilities_are_flagged() {
        assert!(Capability::Argon2.is_memory_hard());
        assert!(Capability::Scrypt.is_memory_hard());
        assert!(Capability::Bcrypt.is_memory_hard());
        assert!(!Capability::Md.is_memory_hard());
        assert!(!Capability::Sha1.is_memory_hard());
    }

    #[test]
    fn union_combines_two_sets() {
        let mut a = CapabilitySet::empty();
        a.insert(Capability::Md);
        let mut b = CapabilitySet::empty();
        b.insert(Capability::Sha1);
        let u = a.union(&b);
        assert!(u.contains(Capability::Md));
        assert!(u.contains(Capability::Sha1));
        assert_eq!(u.len(), 2);
    }
}
