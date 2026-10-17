//! Mask parsing, keyspace sizing, and candidate iteration.
//!
//! This module is the single source of truth for mask handling. Before it
//! existed the same logic lived in three places: `brute.rs` for the attack,
//! `cmd_mask` for the dry run, and `cmd_expand` for the full expansion. The
//! copies drifted, most visibly in the `?1` to `?4` fallback and in overflow
//! behaviour on large keyspaces.
//!
//! Supported syntax, matching the hashcat convention:
//!
//! | Token        | Meaning                                  | Size   |
//! |--------------|------------------------------------------|--------|
//! | `?l`         | lowercase `a-z`                          | 26     |
//! | `?u`         | uppercase `A-Z`                          | 26     |
//! | `?d`         | digits `0-9`                             | 10     |
//! | `?s`         | the special set below                    | 33     |
//! | `?a`         | `?l?u?d?s` combined                       | 95     |
//! | `?h`         | lowercase hex `0-9a-f`                   | 16     |
//! | `?H`         | uppercase hex `0-9A-F`                   | 16     |
//! | `?b`         | every byte `0x00`-`0xFF`                 | 256    |
//! | `?w`         | all printable ASCII                      | 100    |
//! | `?1`..`?4`   | a user supplied charset                   | varies |
//! | `(abc)`      | a literal range, characters used in order | varies |
//! | `[?u?l]`     | alternation over the listed classes      | varies |
//! | `\%`         | a literal percent sign                   | 1      |
//! | any other c  | that literal character                   | 1      |
//!
//! Two design decisions worth stating:
//!
//! * An unknown `?X` token is an error rather than a literal `?X`. Silently
//!   treating `?q` as a literal produces a keyspace the user did not ask for,
//!   which in a cracking tool means a silently wrong run.
//! * Keyspace is computed in `u128`. A mask such as `?b?b?b?b?b?b?b?b` is
//!   2^64 and would overflow `u64`; the run is refused instead of wrapping to a
//!   small number and finishing early having covered almost nothing.

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

/// Returns all 256 byte values. Built at first use to keep the static table
/// readable.
pub fn bytes() -> &'static [u8] {
    use std::sync::LazyLock;
    static ALL: LazyLock<Vec<u8>> = LazyLock::new(|| (0..=255u8).collect());
    &ALL
}
/// A single token in a parsed mask.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// One position that expands over `charset`.
    Class(Charset),
    /// A run of literal bytes, kept grouped so long literals are cheap.
    Literal(Vec<u8>),
}

/// A source of candidate bytes for one mask position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Charset {
    Lower,
    Upper,
    Digit,
    Special,
    /// `?a`: the union of lower, upper, digit, and special.
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
    /// A `?` was not followed by a recognised token.
    UnknownToken { token: String, position: usize },
    /// A `?` or a `(` or `[` reached the end of the string.
    Unterminated { opener: char, position: usize },
    /// A custom charset index outside `?1` to `?4` was referenced.
    BadCustomIndex { index: usize },
    /// A literal range contained no characters.
    EmptyRange { position: usize },
    /// The mask expanded to an empty set of positions.
    Empty,
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
            MaskError::EmptyRange { position } => write!(
                f,
                "empty character range at position {position}"
            ),
            MaskError::Empty => write!(f, "mask produced no candidate positions"),
        }
    }
}

impl std::error::Error for MaskError {}

/// A parsed mask: an ordered list of tokens, plus the byte sets it needs.
#[derive(Debug, Clone)]
pub struct Mask {
    tokens: Vec<Token>,
}

/// The default set for `?1` to `?4` when the user supplies nothing.
pub const DEFAULT_CUSTOM: &[u8] = LOWER;

impl Mask {
    /// Parses a mask string.
    ///
    /// `custom` supplies the four `?1` to `?4` charsets; a `None` entry falls
    /// back to lowercase, matching the historical behaviour.
    pub fn parse(spec: &str, custom: &[Option<Vec<u8>>]) -> Result<Self, MaskError> {
        // Missing entries in `custom` default to lowercase so callers may pass
        // a short slice without special-casing every index.
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
                    // Escape: the next byte is literal.
                    if i + 1 >= bytes.len() {
                        return Err(MaskError::Unterminated { opener: '\\', position: i });
                    }
                    literal.push(bytes[i + 1]);
                    i += 2;
                }
                b'?' => {
                    // A class token. Flush any pending literal first.
                    if !literal.is_empty() {
                        tokens.push(Token::Literal(std::mem::take(&mut literal)));
                    }
                    if i + 1 >= bytes.len() {
                        return Err(MaskError::Unterminated { opener: '?', position: i });
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
                    // Literal range: (?abc) or (a-z) style, but every character
                    // inside is literal in the order written.
                    if !literal.is_empty() {
                        tokens.push(Token::Literal(std::mem::take(&mut literal)));
                    }
                    let open_pos = i;
                    // Search only after the opening paren so that a nested or
                    // preceding paren cannot truncate the range. Searching from
                    // `i` and then slicing from `i + 1` used to skip the first
                    // character, turning `(?abc)` into `a, c`.
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
                    let inner = &bytes[i + 1..end];
                    // Every byte inside `(...)` is literal, which is the
                    // hashcat convention. `(?abc)` is the three characters
                    // `a`, `b`, `c`.
                    //
                    // An earlier version tried to detect a leading `?` and
                    // expand class names, stepping two bytes at a time. That
                    // made `(?abc)` expand to `a` and `c` only, because `b` sat
                    // at an odd offset the loop never visited. A user writing
                    // `(?abc)` expects three characters, not two.
                    //
                    // To include class members in a range, use the alternation
                    // form `[?l?d]`, which is explicit about what it expands.
                    let set: Vec<u8> = inner.to_vec();
                    if set.is_empty() {
                        return Err(MaskError::EmptyRange { position: open_pos });
                    }
                    tokens.push(Token::Class(Charset::Range(set)));
                    i = end + 1;
                }
                b'[' => {
                    // Alternation: [?u?l] expands over the union of the classes.
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
        let classes_as_options: Vec<Option<Vec<u8>>> =
            classes.into_iter().map(Some).collect();
        mask.charsets(&classes_as_options)?;
        Ok(mask)
    }

    /// Returns the byte set for one token, given the resolved custom charsets.
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
            Charset::Byte => bytes().to_vec(),
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

    /// Returns the resolved byte set for every token. Literals yield an empty
    /// slice, which means "does not multiply the keyspace".
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
                    .ok_or(MaskError::Empty)?;
            }
        }
        Ok(total)
    }

    /// Human readable keyspace, used in the run banner.
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
    /// The last token varies fastest, which matches hashcat ordering. Indices
    /// beyond the keyspace are not validated here; callers must respect the
    /// keyspace they computed.
    pub fn candidate(&self, mut index: u128, custom: &[Option<Vec<u8>>]) -> Result<Vec<u8>, MaskError> {
        let sets = self.charsets(custom)?;
        // Build from the last token backwards, which is the order the index
        // digits come off, then reverse at the end so the result reads left to
        // right. Literals are prepended rather than appended, because they are
        // written in forward order inside the mask but visited in reverse here.
        let mut rev: Vec<u8> = Vec::with_capacity(self.tokens.len());

        for (token, set) in self.tokens.iter().zip(sets.iter()).rev() {
            if let Token::Literal(lit) = token {
                // A literal occupies no keyspace, so it consumes no index
                // digit. Its bytes are pushed in reverse so that the final
                // `rev` restores the written order.
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
    pub fn candidate_string(&self, index: u128, custom: &[Option<Vec<u8>>]) -> Result<String, MaskError> {
        Ok(String::from_utf8_lossy(&self.candidate(index, custom)?).into_owned())
    }

    /// Iterates the first `count` candidates starting at `offset`.
    pub fn preview(
        &self,
        offset: u128,
        count: usize,
        custom: &[Option<Vec<u8>>],
    ) -> Result<Vec<String>, MaskError> {
        let total = self.keyspace(custom)?;
        let mut out = Vec::with_capacity(count);
        let mut idx = offset;
        while out.len() < count && idx < total {
            out.push(self.candidate_string(idx, custom)?);
            idx += 1;
        }
        Ok(out)
    }
}

/// Expands a mask into every length in `min..=max`.
///
/// A mask such as `?d` with `min_length = 4, max_length = 6` yields `?d?d?d?d`,
/// `?d?d?d?d?d`, and `?d?d?d?d?d?d`. `max_length = None` means the natural
/// length of the mask only.
///
/// Returns the masks in ascending length order, which is the cheapest order
/// because shorter keys are far more common.
pub fn expand_lengths(
    spec: &str,
    min_length: usize,
    max_length: Option<usize>,
    custom: &[Option<Vec<u8>>],
) -> Result<Vec<Mask>, MaskError> {
    let base = Mask::parse(spec, custom)?;
    // A literal token contributes exactly one position and one byte.
    let base_len = base.len();

    let natural = base_len;
    let hi = max_length.unwrap_or(natural);

    if min_length > hi {
        return Err(MaskError::Empty);
    }

    let mut out = Vec::new();
    if min_length == natural && hi == natural {
        out.push(base);
        return Ok(out);
    }

    // The unit to repeat when growing or shrinking is the last class, since a
    // repeated mask position is what actually multiplies the keyspace.
    let grow_spec = spec.to_string();
    for len in min_length..=hi {
        if len == natural {
            out.push(Mask::parse(&grow_spec, custom)?);
        } else if len < natural {
            // Shrinking drops trailing class positions. Only classes may be
            // dropped: removing a literal would change the literal text of
            // every candidate.
            let class_count = base.tokens.iter().filter(|t| matches!(t, Token::Class(_))).count();
            let keep = class_count.saturating_sub(natural - len);
            out.push(shrink(&base, keep, custom)?);
        } else {
            // Growing repeats the last class position.
            out.push(grow(&base, len - natural, custom)?);
        }
    }
    Ok(out)
}

/// Builds a mask with the last `keep` class positions retained.
fn shrink(base: &Mask, keep: usize, custom: &[Option<Vec<u8>>]) -> Result<Mask, MaskError> {
    // Drop trailing class tokens until only `keep` remain, but never drop a
    // literal because that would change the literal part of the candidate.
    let class_count = base.tokens.iter().filter(|t| matches!(t, Token::Class(_))).count();
    // Named `remaining_drops` rather than `to_drop` because `drop` is also a
    // function in scope and the shadowing is confusing to read.
    let mut remaining_drops = class_count.saturating_sub(keep);

    let mut tokens: Vec<Token> = Vec::new();
    for tok in base.tokens.iter().rev() {
        if matches!(tok, Token::Class(_)) {
            if remaining_drops > 0 {
                remaining_drops -= 1;
                continue;
            }
        }
        tokens.push(tok.clone());
    }
    tokens.reverse();
    let m = Mask { tokens };
    m.charsets(custom)?;
    Ok(m)
}

/// Builds a mask with `extra` copies of the final class position appended.
fn grow(base: &Mask, extra: usize, custom: &[Option<Vec<u8>>]) -> Result<Mask, MaskError> {
    let unit = match base.tokens.iter().rev().find_map(|t| match t {
        Token::Class(cs) => Some(cs.clone()),
        Token::Literal(_) => None,
    }) {
        Some(cs) => cs,
        // A mask made only of literals has no class to repeat, so it cannot be
        // length expanded. Reporting the empty mask is clearer than a silent
        // no-op.
        None => return Err(MaskError::Empty),
    };

    let mut tokens = base.tokens.clone();
    for _ in 0..extra {
        tokens.push(Token::Class(unit.clone()));
    }
    let m = Mask { tokens };
    m.charsets(custom)?;
    Ok(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_custom() -> Vec<Option<Vec<u8>>> {
        vec![None, None, None, None]
    }

    #[test]
    fn parses_classes_and_literals() {
        let m = Mask::parse("?u?l?l?l?d?d", &no_custom()).unwrap();
        assert_eq!(m.len(), 6);
    }

    #[test]
    fn unknown_token_is_an_error_not_a_literal() {
        let err = Mask::parse("?q", &no_custom()).unwrap_err();
        assert!(matches!(err, MaskError::UnknownToken { .. }));
    }

    #[test]
    fn keyspace_of_common_masks() {
        let c = no_custom();
        assert_eq!(Mask::parse("?d?d?d?d?d?d", &c).unwrap().keyspace(&c).unwrap(), 1_000_000);
        assert_eq!(Mask::parse("?l?l?l?l?l?l?l?l", &c).unwrap().keyspace(&c).unwrap(), 26u128.pow(8));
        assert_eq!(Mask::parse("abc", &c).unwrap().keyspace(&c).unwrap(), 1);
    }

    #[test]
    fn huge_keyspace_does_not_overflow() {
        let c = no_custom();
        let m = Mask::parse("?b?b?b?b?b?b?b?b?b?b", &c).unwrap();
        let ks = m.keyspace(&c).unwrap();
        assert_eq!(ks, 256u128.pow(10));
    }

    #[test]
    fn last_position_varies_fastest() {
        let c = no_custom();
        let m = Mask::parse("?d?d", &c).unwrap();
        assert_eq!(m.candidate_string(0, &c).unwrap(), "00");
        assert_eq!(m.candidate_string(1, &c).unwrap(), "01");
        assert_eq!(m.candidate_string(10, &c).unwrap(), "10");
        assert_eq!(m.candidate_string(99, &c).unwrap(), "99");
    }

    #[test]
    fn literals_do_not_consume_keyspace_digits() {
        let c = no_custom();
        let m = Mask::parse("pw?d", &c).unwrap();
        assert_eq!(m.keyspace(&c).unwrap(), 10);
        assert_eq!(m.candidate_string(0, &c).unwrap(), "pw0");
        assert_eq!(m.candidate_string(7, &c).unwrap(), "pw7");
    }

    #[test]
    fn preview_respects_keyspace_bound() {
        let c = no_custom();
        let m = Mask::parse("?d?d", &c).unwrap();
        assert_eq!(m.preview(98, 20, &c).unwrap().len(), 2);
    }

    #[test]
    fn custom_charsets_are_used() {
        let c = vec![Some(b"abc".to_vec()), None, None, None];
        let m = Mask::parse("?1?1", &c).unwrap();
        assert_eq!(m.keyspace(&c).unwrap(), 9);
        assert_eq!(m.candidate_string(0, &c).unwrap(), "aa");
        assert_eq!(m.candidate_string(8, &c).unwrap(), "cc");
    }

    #[test]
    fn literal_range_expands() {
        let c = no_custom();
        // `(abc)` is the literal set {a, b, c}: three characters.
        let m = Mask::parse("(abc)?d", &c).unwrap();
        assert_eq!(m.keyspace(&c).unwrap(), 30);
        assert_eq!(m.candidate_string(0, &c).unwrap(), "a0");
        // The last position varies fastest, so the ten digits for `a` come
        // before the ten digits for `b`.
        assert_eq!(m.candidate_string(1, &c).unwrap(), "a1");
        assert_eq!(m.candidate_string(10, &c).unwrap(), "b0");
        assert_eq!(m.candidate_string(20, &c).unwrap(), "c0");
    }

    #[test]
    fn question_mark_inside_a_range_is_a_literal_byte() {
        // `?` has no special meaning inside `(...)`. This test pins that down
        // because an earlier implementation stripped it, which silently changed
        // the keyspace a user asked for.
        let c = no_custom();
        let m = Mask::parse("(a?c)", &c).unwrap();
        assert_eq!(m.keyspace(&c).unwrap(), 3);
        assert_eq!(m.candidate_string(1, &c).unwrap(), "?");
    }

    #[test]
    fn alternation_unions_classes() {
        let c = no_custom();
        let m = Mask::parse("[?d?l]", &c).unwrap();
        assert_eq!(m.keyspace(&c).unwrap(), 36);
    }

    #[test]
    fn escaped_percent_is_literal() {
        let c = no_custom();
        // `\%` yields a literal `%`, and the `d` that follows is an ordinary
        // literal character. The backslash must not swallow the next token's
        // meaning, so this mask has no expanding position at all.
        let m = Mask::parse("\\%d", &c).unwrap();
        assert_eq!(m.keyspace(&c).unwrap(), 1);
        assert_eq!(m.candidate_string(0, &c).unwrap(), "%d");

        // A backslash before a real token keeps the token live, so `\%?d` is a
        // literal `%` followed by one digit and has a keyspace of 10.
        let m2 = Mask::parse("\\%?d", &c).unwrap();
        assert_eq!(m2.keyspace(&c).unwrap(), 10);
        assert_eq!(m2.candidate_string(3, &c).unwrap(), "%3");
    }

    #[test]
    fn length_expansion_grows_the_keyspace() {
        let c = no_custom();
        let masks = expand_lengths("?d", 4, Some(6), &c).unwrap();
        assert_eq!(masks.len(), 3);
        assert_eq!(masks[0].keyspace(&c).unwrap(), 10_000);
        assert_eq!(masks[1].keyspace(&c).unwrap(), 100_000);
        assert_eq!(masks[2].keyspace(&c).unwrap(), 1_000_000);
    }

    #[test]
    fn preview_of_expanded_range_covers_each_length() {
        let c = no_custom();
        let masks = expand_lengths("?d", 2, Some(3), &c).unwrap();
        let all: Vec<String> = masks.iter().flat_map(|m| m.preview(0, 3, &c).unwrap()).collect();
        assert_eq!(all, vec!["00", "01", "02", "000", "001", "002"]);
    }
}


