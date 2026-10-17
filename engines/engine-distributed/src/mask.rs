//! Candidate generation for `AttackType::BruteForce`, ported from the main
//! crate's `src/attack/mask.rs`.
//!
//! # Why this is a second copy
//!
//! `engine-distributed` is a dependency of the root `pwdcrack` crate, so it
//! cannot depend on the root crate, and the root crate's mask expander cannot be
//! reached from a worker running in a different process. The previous version of
//! this module was not a port but a paraphrase: it ignored the index in `?1` to
//! `?9`, so `?1` and `?2` both expanded to lowercase, it had no `?w`, no literal
//! range `(?abc)`, no alternation `[?u?l]`, and no escape. A cluster run and a
//! local run of the same mask therefore tested different candidate sets, which is
//! the worst kind of disagreement: both report success.
//!
//! So this is a faithful copy rather than a paraphrase, and
//! `tests/distributed_mask_agreement.rs` in the root crate asserts that the two
//! agree, candidate for candidate and keyspace for keyspace, over a corpus. That
//! test is what makes a second copy safe: it fails the moment either side is
//! edited without the other.
//!
//! # Index order
//!
//! The last token varies fastest, matching hashcat and the root crate. An index
//! is `u128` here even though a work unit's keyspace is `u64`, because
//! `keyspace` is computed in `u128` and refusing to compute it is better than
//! computing a wrong answer with wrapping arithmetic.

use std::fmt;

/// Lowercase letters.
pub static LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
/// Uppercase letters.
pub static UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// Decimal digits.
pub static DIGIT: &[u8] = b"0123456789";
/// Punctuation commonly seen in passwords.
pub static SPECIAL: &[u8] = b"!@#$%^&*()-_+=~`[]{}|;:',.<>?/";
/// Lowercase hex digits.
pub static HEX_LOWER: &[u8] = b"0123456789abcdef";
/// Uppercase hex digits.
pub static HEX_UPPER: &[u8] = b"0123456789ABCDEF";
/// All printable ASCII, space through tilde.
pub static PRINTABLE: &[u8] = b" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";

/// The default set for `?1` to `?4` when the user supplies nothing.
pub const DEFAULT_CUSTOM: &[u8] = LOWER;

/// All 256 byte values, built once on first use.
pub fn all_bytes() -> &'static [u8] {
    use std::sync::LazyLock;
    static ALL: LazyLock<Vec<u8>> = LazyLock::new(|| (0..=255u8).collect());
    &ALL
}

/// A single token in a parsed mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// One position that expands over a charset.
    Class(Charset),
    /// A run of literal bytes, kept grouped so long literals stay cheap.
    Literal(Vec<u8>),
}

/// A source of candidate bytes for one mask position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Charset {
    Lower,
    Upper,
    Digit,
    Special,
    /// `?a`: lower, upper, digit and special.
    All,
    HexLower,
    HexUpper,
    /// `?b`: every byte value.
    Byte,
    /// `?w`: all printable ASCII.
    Printable,
    /// `?1` through `?4`.
    Custom(usize),
    /// A literal range such as `(?abc)`.
    Range(Vec<u8>),
    /// An alternation such as `[?u?l]`.
    Alternation(Vec<Charset>),
}

/// Why a mask string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskError {
    UnknownToken { token: String, position: usize },
    Unterminated { opener: char, position: usize },
    BadCustomIndex { index: usize },
    EmptyRange { position: usize },
    Empty,
    /// The keyspace does not fit in a `u64`, so it cannot be split into chunks.
    ///
    /// Separate from [`MaskError::Empty`] because it needs a different answer: a
    /// keyspace that is merely large is normal, and refusing to schedule it
    /// rather than wrapping around to a small number is the safe behaviour.
    KeyspaceTooLarge { keyspace: u128 },
}

impl fmt::Display for MaskError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MaskError::UnknownToken { token, position } => write!(
                f,
                "unknown mask token '{token}' at position {position}. \
                 Supported: ?l ?u ?d ?s ?a ?h ?H ?b ?w ?1 ?2 ?3 ?4"
            ),
            MaskError::Unterminated { opener, position } => write!(
                f,
                "unterminated '{opener}' at position {position}. Missing the closing brace."
            ),
            MaskError::BadCustomIndex { index } => {
                write!(f, "custom charset {index} is out of range, expected 1 to 4")
            }
            MaskError::EmptyRange { position } => {
                write!(f, "empty character range at position {position}")
            }
            MaskError::Empty => write!(f, "mask produced no candidate positions"),
            MaskError::KeyspaceTooLarge { keyspace } => write!(
                f,
                "mask keyspace {keyspace} exceeds the {MAX_KEYSPACE} a work unit can address"
            ),
        }
    }
}

impl std::error::Error for MaskError {}

/// The largest keyspace a `u64` addressed work unit can describe.
///
/// `?b` nine times is 2^72, which is a legitimate mask and cannot be scheduled
/// by this engine. The limit is named so the refusal can name the real ceiling.
pub const MAX_KEYSPACE: u128 = u64::MAX as u128;

/// A parsed mask: an ordered list of tokens plus the byte sets they need.
#[derive(Debug, Clone)]
pub struct Mask {
    tokens: Vec<Token>,
}

impl Mask {
    /// Parses a mask string.
    ///
    /// `custom` supplies the four `?1` to `?4` charsets; a `None` entry falls
    /// back to lowercase.
    pub fn parse(spec: &str, custom: &[Option<Vec<u8>>]) -> Result<Self, MaskError> {
        let mut classes: Vec<Vec<u8>> = vec![DEFAULT_CUSTOM.to_vec(); 4];
        for (i, slot) in custom.iter().take(4).enumerate() {
            if let Some(bytes) = slot {
                if !bytes.is_empty() {
                    classes[i] = bytes.clone();
                }
            }
        }

        let bytes = spec.as_bytes();
        let mut tokens: Vec<Token> = Vec::new();
        let mut literal: Vec<u8> = Vec::new();
        let mut i = 0usize;

        while i < bytes.len() {
            match bytes[i] {
                b'\\' => {
                    if i + 1 >= bytes.len() {
                        return Err(MaskError::Unterminated {
                            opener: '\\',
                            position: i,
                        });
                    }
                    literal.push(bytes[i + 1]);
                    i += 2;
                }
                b'?' => {
                    if !literal.is_empty() {
                        tokens.push(Token::Literal(std::mem::take(&mut literal)));
                    }
                    if i + 1 >= bytes.len() {
                        return Err(MaskError::Unterminated {
                            opener: '?',
                            position: i,
                        });
                    }
                    let token_pos = i;
                    let c = bytes[i + 1];
                    let charset = match c {
                        b'l' => Charset::Lower,
                        b'u' => Charset::Upper,
                        b'd' => Charset::Digit,
                        b's' => Charset::Special,
                        b'a' => Charset::All,
                        b'h' => Charset::HexLower,
                        b'H' => Charset::HexUpper,
                        b'b' => Charset::Byte,
                        b'w' => Charset::Printable,
                        b'1'..=b'4' => Charset::Custom((c - b'1') as usize),
                        _ => {
                            return Err(MaskError::UnknownToken {
                                token: format!("?{}", c as char),
                                position: token_pos,
                            })
                        }
                    };
                    tokens.push(Token::Class(charset));
                    i += 2;
                }
                b'(' => {
                    if !literal.is_empty() {
                        tokens.push(Token::Literal(std::mem::take(&mut literal)));
                    }
                    let open_pos = i;
                    let close = bytes[i + 1..]
                        .iter()
                        .position(|&b| b == b')')
                        .map(|p| p + i + 1);
                    let end = match close {
                        Some(e) => e,
                        None => {
                            return Err(MaskError::Unterminated {
                                opener: '(',
                                position: open_pos,
                            })
                        }
                    };
                    let set: Vec<u8> = bytes[i + 1..end].to_vec();
                    if set.is_empty() {
                        return Err(MaskError::EmptyRange { position: open_pos });
                    }
                    tokens.push(Token::Class(Charset::Range(set)));
                    i = end + 1;
                }
                b'[' => {
                    if !literal.is_empty() {
                        tokens.push(Token::Literal(std::mem::take(&mut literal)));
                    }
                    let open_pos = i;
                    let close = bytes[i + 1..]
                        .iter()
                        .position(|&b| b == b']')
                        .map(|p| p + i + 1);
                    let end = match close {
                        Some(e) => e,
                        None => {
                            return Err(MaskError::Unterminated {
                                opener: '[',
                                position: open_pos,
                            })
                        }
                    };
                    let inner = &bytes[i + 1..end];
                    let mut alts: Vec<Charset> = Vec::new();
                    let mut j = 0;
                    while j + 1 < inner.len() && inner[j] == b'?' {
                        let sub = match inner[j + 1] {
                            b'l' => Charset::Lower,
                            b'u' => Charset::Upper,
                            b'd' => Charset::Digit,
                            b's' => Charset::Special,
                            b'h' => Charset::HexLower,
                            b'H' => Charset::HexUpper,
                            b'w' => Charset::Printable,
                            b'a' => Charset::All,
                            b'b' => Charset::Byte,
                            other => {
                                return Err(MaskError::UnknownToken {
                                    token: format!("?{}", other as char),
                                    position: open_pos + j,
                                })
                            }
                        };
                        alts.push(sub);
                        j += 2;
                    }
                    if alts.is_empty() {
                        return Err(MaskError::EmptyRange { position: open_pos });
                    }
                    tokens.push(Token::Class(Charset::Alternation(alts)));
                    i = end + 1;
                }
                other => {
                    literal.push(other);
                    i += 1;
                }
            }
        }

        if !literal.is_empty() {
            tokens.push(Token::Literal(literal));
        }
        if tokens.is_empty() {
            return Err(MaskError::Empty);
        }

        let mask = Mask { tokens };
        // Resolve every charset once so an empty class is caught at parse time
        // rather than producing a candidate that silently matches nothing.
        let classes_as_options: Vec<Option<Vec<u8>>> = classes.into_iter().map(Some).collect();
        mask.charsets(&classes_as_options)?;
        Ok(mask)
    }

    fn token_charset(&self, token: &Token, custom: &[Vec<u8>]) -> Result<Vec<u8>, MaskError> {
        let cs = match token {
            Token::Literal(_) => return Ok(Vec::new()),
            Token::Class(cs) => cs,
        };
        Ok(match cs {
            Charset::Lower => LOWER.to_vec(),
            Charset::Upper => UPPER.to_vec(),
            Charset::Digit => DIGIT.to_vec(),
            Charset::Special => SPECIAL.to_vec(),
            Charset::All => {
                let mut v = Vec::with_capacity(95);
                v.extend_from_slice(LOWER);
                v.extend_from_slice(UPPER);
                v.extend_from_slice(DIGIT);
                v.extend_from_slice(SPECIAL);
                v
            }
            Charset::HexLower => HEX_LOWER.to_vec(),
            Charset::HexUpper => HEX_UPPER.to_vec(),
            Charset::Byte => all_bytes().to_vec(),
            Charset::Printable => PRINTABLE.to_vec(),
            Charset::Custom(i) => {
                let idx = *i;
                match custom.get(idx) {
                    Some(v) if !v.is_empty() => v.clone(),
                    Some(_) => DEFAULT_CUSTOM.to_vec(),
                    None => return Err(MaskError::BadCustomIndex { index: idx + 1 }),
                }
            }
            Charset::Range(set) => set.clone(),
            Charset::Alternation(parts) => {
                let mut v = Vec::new();
                for p in parts {
                    let sub = self.class_bytes(p, custom)?;
                    for b in sub {
                        if !v.contains(&b) {
                            v.push(b);
                        }
                    }
                }
                v
            }
        })
    }

    fn class_bytes(&self, cs: &Charset, custom: &[Vec<u8>]) -> Result<Vec<u8>, MaskError> {
        self.token_charset(&Token::Class(cs.clone()), custom)
    }

    /// The resolved byte set for every token. Literals yield an empty slice,
    /// which means "does not multiply the keyspace".
    pub fn charsets(&self, custom: &[Option<Vec<u8>>]) -> Result<Vec<Vec<u8>>, MaskError> {
        let classes: Vec<Vec<u8>> = (0..4)
            .map(|i| match custom.get(i).and_then(|o| o.clone()) {
                Some(v) if !v.is_empty() => v,
                _ => DEFAULT_CUSTOM.to_vec(),
            })
            .collect();
        self.tokens
            .iter()
            .map(|t| self.token_charset(t, &classes))
            .collect()
    }

    /// Number of tokens, including literals.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// True when the mask has no tokens.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Exact keyspace size, computed in `u128`.
    pub fn keyspace(&self, custom: &[Option<Vec<u8>>]) -> Result<u128, MaskError> {
        let sets = self.charsets(custom)?;
        let mut total: u128 = 1;
        for s in sets.iter() {
            if !s.is_empty() {
                total = total
                    .checked_mul(s.len() as u128)
                    .ok_or(MaskError::KeyspaceTooLarge { keyspace: u128::MAX })?;
            }
        }
        Ok(total)
    }

    /// Keyspace as a `u64`, refusing a mask that does not fit.
    ///
    /// The scheduler addresses work units with `u64` offsets, so a mask whose
    /// keyspace exceeds `u64::MAX` cannot be split into chunks this engine can
    /// hand out. Wrapping instead would silently scan a completely different
    /// range, so it is an error.
    pub fn keyspace_u64(&self, custom: &[Option<Vec<u8>>]) -> Result<u64, MaskError> {
        let k = self.keyspace(custom)?;
        if k > MAX_KEYSPACE {
            return Err(MaskError::KeyspaceTooLarge { keyspace: k });
        }
        Ok(k as u64)
    }

    /// Human readable keyspace.
    pub fn describe_keyspace(&self, custom: &[Option<Vec<u8>>]) -> String {
        match self.keyspace(custom) {
            Ok(n) => {
                if n >= 1_000_000_000_000 {
                    format!("{n} ({:.3} trillion)", n as f64 / 1e12)
                } else if n >= 1_000_000_000 {
                    format!("{n} ({:.3} billion)", n as f64 / 1e9)
                } else if n >= 1_000_000 {
                    format!("{n} ({:.3} million)", n as f64 / 1e6)
                } else {
                    format!("{n}")
                }
            }
            Err(_) => "unbounded".to_string(),
        }
    }

    /// Converts a zero based index into the candidate it represents.
    ///
    /// The last token varies fastest. Indices beyond the keyspace are not
    /// validated; the scheduler respects the keyspace it computed.
    pub fn candidate(
        &self,
        mut index: u128,
        custom: &[Option<Vec<u8>>],
    ) -> Result<Vec<u8>, MaskError> {
        let sets = self.charsets(custom)?;
        let mut rev: Vec<u8> = Vec::with_capacity(self.tokens.len());

        for (token, set) in self.tokens.iter().zip(sets.iter()).rev() {
            if let Token::Literal(lit) = token {
                rev.extend(lit.iter().rev().copied());
                continue;
            }
            if set.is_empty() {
                continue;
            }
            let n = set.len() as u128;
            let idx = (index % n) as usize;
            rev.push(set[idx]);
            index /= n;
        }
        rev.reverse();
        Ok(rev)
    }

    /// Renders a candidate as a `String`, replacing invalid UTF-8 with the
    /// replacement character so `?b` masks remain printable.
    pub fn candidate_string(
        &self,
        index: u128,
        custom: &[Option<Vec<u8>>],
    ) -> Result<String, MaskError> {
        Ok(String::from_utf8_lossy(&self.candidate(index, custom)?).into_owned())
    }
}

/// Keyspace of a mask string, for the master to size a job.
///
/// A thin wrapper so the master does not need to know that `keyspace_u64` lives
/// on `Mask` and not on `MaskError`.
pub fn keyspace_size(mask: &str) -> Result<u64, MaskError> {
    Mask::parse(mask, &[])?.keyspace_u64(&[])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(m: &str) -> u128 {
        Mask::parse(m, &[]).expect("mask should parse").keyspace(&[]).expect("keyspace")
    }

    fn cand(m: &str, i: u128) -> String {
        Mask::parse(m, &[])
            .expect("mask should parse")
            .candidate_string(i, &[])
            .expect("candidate")
    }

    #[test]
    fn a_single_class_has_the_class_size() {
        assert_eq!(key("?l"), 26);
        assert_eq!(key("?d"), 10);
        assert_eq!(key("?s"), SPECIAL.len() as u128);
        // 26 lower plus 26 upper plus 10 digits plus 30 punctuation. Not 95: the
        // root crate sizes its `?a` buffer with `with_capacity(95)` while the set
        // it fills holds 92, so an assertion written from the hint rather than
        // from the bytes failed here. The first assertion counts the bytes; the
        // second pins the number so a change to `SPECIAL` is noticed.
        assert_eq!(
            key("?a"),
            (LOWER.len() + UPPER.len() + DIGIT.len() + SPECIAL.len()) as u128
        );
        assert_eq!(key("?a"), 92);
        assert_eq!(key("?w"), PRINTABLE.len() as u128);
        assert_eq!(key("?b"), 256);
    }

    #[test]
    fn classes_multiply() {
        assert_eq!(key("?l?l"), 676);
        assert_eq!(key("?u?l?d?d"), 26 * 26 * 10 * 10);
    }

    #[test]
    fn literals_do_not_multiply() {
        assert_eq!(key("admin?d"), 10);
        assert_eq!(key("x?l!y"), 26);
    }

    /// A parenthesised range is **one position** drawn from the bytes inside.
    ///
    /// So `(?abc)` is a single character, one of `?`, `a`, `b` or `c`, not the
    /// three character string `abc`. hashcat's convention is the same for the
    /// position count. The root crate's comment says `(?abc)` expands to the
    /// characters `a`, `b`, `c`, which its code does not do, because it copies
    /// the bytes between the parentheses verbatim including the `?` and then
    /// treats the result as one charset. The code is what both implementations
    /// do, so the code is what this port matches and what
    /// `tests/distributed_mask_agreement.rs` asserts. The misleading comment in
    /// the root crate is worth fixing there, but fixing it in one place only
    /// would break the guarantee that a local run and a cluster run of the same
    /// mask test the same candidates.
    #[test]
    fn a_parenthesised_range_is_one_position_over_those_bytes() {
        assert_eq!(key("(?abc)"), 4);
        assert_eq!(cand("(?abc)", 0), "?");
        assert_eq!(cand("(?abc)", 1), "a");
        assert_eq!(cand("(?abc)", 3), "c");
        // Two positions when it is combined with a class. Three bytes inside
        // the parentheses here, not four, because this spelling has three.
        assert_eq!(key("(?ab)?d"), 3 * 10);
    }

    /// The bug this port was written to fix: `?1` and `?2` are different
    /// charsets, and the previous implementation returned lowercase for all of
    /// them regardless of index.
    #[test]
    fn custom_charsets_are_distinguished_by_index() {
        let custom = vec![
            Some(b"ABC".to_vec()),
            Some(b"xyz".to_vec()),
            None,
            None,
        ];
        let m = Mask::parse("?1?2", &custom).unwrap();
        assert_eq!(m.keyspace(&custom).unwrap(), 9);
        assert_eq!(m.candidate_string(0, &custom).unwrap(), "Ax");
        assert_eq!(m.candidate_string(1, &custom).unwrap(), "Ay");
        assert_eq!(m.candidate_string(3, &custom).unwrap(), "Bx");
        assert_eq!(m.candidate_string(8, &custom).unwrap(), "Cz");
    }

    #[test]
    fn an_alternation_is_the_union_of_its_parts() {
        assert_eq!(key("[?u?l]?d"), 52 * 10);
        assert_eq!(cand("[?u?l]0", 0), "A0");
        assert_eq!(cand("[?u?l]0", 25), "Z0");
        assert_eq!(cand("[?u?l]0", 26), "a0");
    }

    /// `\?l` is a literal `?` followed by a literal `l`, so it is one candidate.
    /// Writing the mask `?l` needs no escape at all.
    #[test]
    fn a_backslash_escapes_the_next_byte() {
        assert_eq!(key("\\?l"), 1);
        assert_eq!(cand("\\?l", 0), "?l");
    }

    #[test]
    fn the_last_position_varies_fastest() {
        assert_eq!(cand("?l?d", 0), "a0");
        assert_eq!(cand("?l?d", 1), "a1");
        assert_eq!(cand("?l?d", 10), "b0");
    }

    #[test]
    fn an_unknown_token_is_an_error() {
        assert!(matches!(
            Mask::parse("?q", &[]),
            Err(MaskError::UnknownToken { .. })
        ));
    }

    #[test]
    fn an_unterminated_group_is_an_error() {
        assert!(matches!(
            Mask::parse("(?ab", &[]),
            Err(MaskError::Unterminated { .. })
        ));
        assert!(matches!(
            Mask::parse("[?u?l", &[]),
            Err(MaskError::Unterminated { .. })
        ));
    }

    #[test]
    fn an_empty_mask_is_an_error_rather_than_one_empty_candidate() {
        assert_eq!(Mask::parse("", &[]).unwrap_err(), MaskError::Empty);
    }

    /// A mask can legitimately be larger than a `u64` can address. Scheduling it
    /// by wrapping would scan the wrong range entirely, so it is refused.
    #[test]
    fn a_keyspace_beyond_u64_is_refused() {
        let m = Mask::parse("?b?b?b?b?b?b?b?b?b?b", &[]).unwrap();
        assert!(m.keyspace(&[]).unwrap() > MAX_KEYSPACE);
        assert!(matches!(
            m.keyspace_u64(&[]),
            Err(MaskError::KeyspaceTooLarge { .. })
        ));
    }

    #[test]
    fn a_keyspace_that_just_fits_is_accepted() {
        // 256^8 = 2^64, one past u64::MAX. 256^7 = 2^56 fits.
        assert!(Mask::parse("?b?b?b?b?b?b?b?b", &[])
            .unwrap()
            .keyspace_u64(&[])
            .is_err());
        assert_eq!(
            Mask::parse("?b?b?b?b?b?b?b", &[]).unwrap().keyspace_u64(&[]).unwrap(),
            1u64 << 56
        );
    }

    #[test]
    fn the_convenience_wrapper_agrees_with_the_type() {
        assert_eq!(keyspace_size("?l?d").unwrap(), 260);
        assert!(keyspace_size("?nope").is_err());
    }
}