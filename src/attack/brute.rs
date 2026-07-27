use std::sync::atomic::{AtomicUsize, Ordering};
use rayon::prelude::*;

use crate::hash::{HashCracker, HashEntry};
use crate::attack::{CrackResult, setup_progress};

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SPECIAL: &[u8] = b"!@#$%^&*()-_+=~`[]{}|;:',.<>?/";
const HEX_LOWER: &[u8] = b"0123456789abcdef";
const HEX_UPPER: &[u8] = b"0123456789ABCDEF";

#[derive(Debug, Clone)]
pub enum MaskChar {
    Lower,
    Upper,
    Digit,
    Special,
    All,
    HexLower,
    HexUpper,
    Byte,
    Custom(usize),
    Literal(char),
}

pub fn parse_mask(mask: &str) -> Vec<MaskChar> {
    let mut result = Vec::new();
    let mut chars = mask.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '?' {
            match chars.next() {
                Some('l') => result.push(MaskChar::Lower),
                Some('u') => result.push(MaskChar::Upper),
                Some('d') => result.push(MaskChar::Digit),
                Some('s') => result.push(MaskChar::Special),
                Some('a') => result.push(MaskChar::All),
                Some('h') => result.push(MaskChar::HexLower),
                Some('H') => result.push(MaskChar::HexUpper),
                Some('b') => result.push(MaskChar::Byte),
                Some('1') => result.push(MaskChar::Custom(0)),
                Some('2') => result.push(MaskChar::Custom(1)),
                Some('3') => result.push(MaskChar::Custom(2)),
                Some('4') => result.push(MaskChar::Custom(3)),
                Some(c) => result.push(MaskChar::Literal(c)),
                None => result.push(MaskChar::Literal('?')),
            }
        } else {
            result.push(MaskChar::Literal(c));
        }
    }

    result
}

fn charset_for<'a>(mc: &'a MaskChar, custom: &'a [&'a [u8]]) -> &'a [u8] {
    match mc {
        MaskChar::Lower => LOWERCASE,
        MaskChar::Upper => UPPERCASE,
        MaskChar::Digit => DIGITS,
        MaskChar::Special => SPECIAL,
        MaskChar::All => {
            let v: Vec<u8> = [LOWERCASE, UPPERCASE, DIGITS, SPECIAL].concat();
            Box::leak(v.into_boxed_slice())
        }
        MaskChar::HexLower => HEX_LOWER,
        MaskChar::HexUpper => HEX_UPPER,
        MaskChar::Byte => {
            let v: Vec<u8> = (0..=255).collect();
            Box::leak(v.into_boxed_slice())
        }
        MaskChar::Custom(i) => {
            if *i < custom.len() && !custom[*i].is_empty() {
                custom[*i]
            } else {
                LOWERCASE
            }
        }
        MaskChar::Literal(_) => b"",
    }
}

fn total_combinations(mask: &[MaskChar], custom: &[&[u8]]) -> u64 {
    let mut total: u64 = 1;
    for mc in mask {
        let cs = charset_for(mc, custom);
        if !cs.is_empty() {
            total = total.saturating_mul(cs.len() as u64);
        }
    }
    total
}

fn index_to_password(mut idx: u64, mask: &[MaskChar], custom: &[&[u8]]) -> String {
    let mut result = Vec::new();
    for mc in mask.iter().rev() {
        let cs = charset_for(mc, custom);
        if cs.is_empty() {
            if let MaskChar::Literal(c) = mc {
                result.push(*c as u8);
            }
            continue;
        }
        let ch = cs[(idx % cs.len() as u64) as usize];
        result.push(ch);
        idx /= cs.len() as u64;
    }
    result.reverse();
    String::from_utf8(result).unwrap_or_default()
}

pub fn run_bruteforce(
    hashes: &[HashEntry],
    cracker: &dyn HashCracker,
    mask_str: &str,
    custom_charsets: &[Option<String>],
    threads: usize,
    quiet: bool,
) -> Vec<CrackResult> {
    let mask = parse_mask(mask_str);
    let custom: Vec<&[u8]> = custom_charsets.iter()
        .map(|opt| match opt {
            Some(s) => {
                let v = s.as_bytes().to_vec();
                Box::leak(v.into_boxed_slice())
            }
            None => LOWERCASE,
        })
        .collect();

    let total = total_combinations(&mask, &custom);

    if !quiet {
        eprintln!("[*] Mask: {}", mask_str);
        eprintln!("[*] Keyspace: {} ({:.2} billion)", total, total as f64 / 1_000_000_000.0);
    }

    let pb = setup_progress(total, quiet);

    let counter = AtomicUsize::new(0);
    let chunk_size = (100_000).max(total as usize / (threads * 100).max(1));

    let results: Vec<CrackResult> = (0..threads).into_par_iter()
        .flat_map(|_| {
            let mut local_results = Vec::new();
            loop {
                let start = counter.fetch_add(chunk_size, Ordering::SeqCst) as u64;
                if start >= total {
                    break;
                }
                let end = (start + chunk_size as u64).min(total);

                for idx in start..end {
                    let password = index_to_password(idx, &mask, &custom);

                    for entry in hashes.iter() {
                        if cracker.verify(&password, entry) {
                            local_results.push(CrackResult {
                                original: entry.raw.clone(),
                                hash_type: cracker.name().to_string(),
                                password: Some(password.clone()),
                            });
                        }
                    }

                    if let Some(ref pb) = pb {
                        pb.inc(1);
                    }
                }
            }
            local_results
        })
        .collect();

    if let Some(ref pb) = pb {
        pb.finish_with_message("Done!");
    }

    results
}
