use std::collections::VecDeque;

/// A single rule operation for mutating a word (hashcat-style).
#[derive(Debug, Clone)]
pub enum RuleOp {
    /// Convert the word to lowercase.
    Lowercase,
    /// Convert the word to uppercase.
    Uppercase,
    /// Capitalise the first character.
    Capitalize,
    /// Invert the capitalisation of the first character.
    InvertCapitalize,
    /// Toggle the case of every character.
    ToggleAll,
    /// Toggle the case of the character at position `n`.
    ToggleAt(usize),
    /// Reverse the word.
    Reverse,
    /// Duplicate the word.
    Duplicate,
    /// Reflect the word (word + reversed without first char).
    Reflect,
    /// Rotate the word left by one character.
    RotateLeft,
    /// Rotate the word right by one character.
    RotateRight,
    /// Append a character to the end.
    Append(char),
    /// Prepend a character to the beginning.
    Prepend(char),
    /// Truncate the word to `n` characters.
    Truncate(usize),
    /// Delete the character at position `n`.
    DeleteAt(usize),
    /// Extract `l` characters starting at position `n`.
    ExtractRange(usize, usize),
    /// Overwrite the character at position `n` with `c`.
    OverwriteAt(usize, char),
    /// Insert character `c` at position `n`.
    InsertAt(usize, char),
    /// Swap the characters at positions `n` and `m`.
    SwapAt(usize, usize),
    /// Substitute all occurrences of character `a` with `b`.
    Substitute(char, char),
    /// No operation (pass-through).
    Pure,
}

/// Parses a hashcat-style rule string into a sequence of [`RuleOp`] values.
pub fn parse_rule(rule_str: &str) -> Result<Vec<RuleOp>, String> {
    let mut ops = VecDeque::new();
    let mut chars = rule_str.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            ':' => ops.push_back(RuleOp::Pure),
            'l' => ops.push_back(RuleOp::Lowercase),
            'u' => ops.push_back(RuleOp::Uppercase),
            'c' => ops.push_back(RuleOp::Capitalize),
            'C' => ops.push_back(RuleOp::InvertCapitalize),
            't' => ops.push_back(RuleOp::ToggleAll),
            'T' => {
                let n = parse_num(&mut chars)?;
                ops.push_back(RuleOp::ToggleAt(n));
            }
            'r' => ops.push_back(RuleOp::Reverse),
            'd' => ops.push_back(RuleOp::Duplicate),
            'f' => ops.push_back(RuleOp::Reflect),
            '{' => ops.push_back(RuleOp::RotateLeft),
            '}' => ops.push_back(RuleOp::RotateRight),
            '$' => {
                let x = chars.next().ok_or("Expected char after $")?;
                ops.push_back(RuleOp::Append(x));
            }
            '^' => {
                let x = chars.next().ok_or("Expected char after ^")?;
                ops.push_back(RuleOp::Prepend(x));
            }
            '[' => ops.push_back(RuleOp::Truncate(0)),
            ']' => ops.push_back(RuleOp::DeleteAt(0)),
            '\'' => {
                let n = parse_num(&mut chars)?;
                ops.push_back(RuleOp::Truncate(n));
            }
            'D' => {
                let n = parse_num(&mut chars)?;
                ops.push_back(RuleOp::DeleteAt(n));
            }
            'x' => {
                let n1 = chars.next().and_then(|c| c.to_digit(10)).ok_or("Expected digit for x")? as usize;
                let n2 = chars.next().and_then(|c| c.to_digit(10)).ok_or("Expected digit for x")? as usize;
                ops.push_back(RuleOp::ExtractRange(n1, n2));
            }
            'O' => {
                let n = parse_num(&mut chars)?;
                let x = chars.next().ok_or("Expected char after O")?;
                ops.push_back(RuleOp::OverwriteAt(n, x));
            }
            'i' => {
                let n = parse_num(&mut chars)?;
                let x = chars.next().ok_or("Expected char after i")?;
                ops.push_back(RuleOp::InsertAt(n, x));
            }
            's' => {
                let a = chars.next().ok_or("Expected char for s")?;
                let b = chars.next().ok_or("Expected second char for s")?;
                ops.push_back(RuleOp::Substitute(a, b));
            }
            '@' => {
                ops.push_back(RuleOp::Pure);
            }
            _ => return Err(format!("Unknown rule operator: '{}'", c)),
        }
    }

    Ok(ops.into())
}

fn parse_num(chars: &mut std::iter::Peekable<std::str::Chars>) -> Result<usize, String> {
    let mut s = String::new();
    loop {
        match chars.peek() {
            Some(c) if c.is_ascii_digit() => {
                s.push(*c);
                chars.next();
            }
            _ => break,
        }
    }
    s.parse::<usize>().map_err(|_| "Expected number".to_string())
}

fn toggle_char(ch: char) -> char {
    if ch.is_ascii_lowercase() {
        ch.to_ascii_uppercase()
    } else if ch.is_ascii_uppercase() {
        ch.to_ascii_lowercase()
    } else {
        ch
    }
}

/// Applies a sequence of [`RuleOp`] values to a word, returning all mutated forms.
pub fn apply_rule(word: &str, rule: &[RuleOp]) -> Vec<String> {
    let mut results = vec![word.to_string()];

    for op in rule {
        let mut new_results = Vec::new();
        for w in &results {
            match op {
                RuleOp::Pure => new_results.push(w.clone()),
                RuleOp::Lowercase => new_results.push(w.to_lowercase()),
                RuleOp::Uppercase => new_results.push(w.to_uppercase()),
                RuleOp::Capitalize => {
                    let mut s = w.to_lowercase();
                    if let Some(c) = s.get_mut(0..1) {
                        c.make_ascii_uppercase();
                    }
                    new_results.push(s);
                }
                RuleOp::InvertCapitalize => {
                    let mut s = w.to_lowercase();
                    if let Some(c) = s.get_mut(0..1) {
                        c.make_ascii_lowercase();
                    }
                    new_results.push(s);
                }
                RuleOp::ToggleAll => {
                    let s: String = w.chars().map(toggle_char).collect();
                    new_results.push(s);
                }
                RuleOp::ToggleAt(n) => {
                    let mut chars: Vec<char> = w.chars().collect();
                    if *n < chars.len() {
                        chars[*n] = toggle_char(chars[*n]);
                    }
                    new_results.push(chars.into_iter().collect());
                }
                RuleOp::Reverse => {
                    new_results.push(w.chars().rev().collect());
                }
                RuleOp::Duplicate => new_results.push(format!("{}{}", w, w)),
                RuleOp::Reflect => {
                    if w.is_empty() {
                        new_results.push(w.clone());
                    } else {
                        let rev: String = w.chars().rev().collect();
                        new_results.push(format!("{}{}", w, &rev[1..]));
                    }
                }
                RuleOp::RotateLeft => {
                    let mut chars: Vec<char> = w.chars().collect();
                    if !chars.is_empty() {
                        chars.rotate_left(1);
                    }
                    new_results.push(chars.into_iter().collect());
                }
                RuleOp::RotateRight => {
                    let mut chars: Vec<char> = w.chars().collect();
                    if !chars.is_empty() {
                        chars.rotate_right(1);
                    }
                    new_results.push(chars.into_iter().collect());
                }
                RuleOp::Append(c) => new_results.push(format!("{}{}", w, c)),
                RuleOp::Prepend(c) => new_results.push(format!("{}{}", c, w)),
                RuleOp::Truncate(n) => {
                    let s: String = w.chars().take(*n).collect();
                    new_results.push(s);
                }
                RuleOp::DeleteAt(n) => {
                    let s: String = w.chars().enumerate()
                        .filter(|(i, _)| *i != *n)
                        .map(|(_, c)| c)
                        .collect();
                    new_results.push(s);
                }
                RuleOp::ExtractRange(s, l) => {
                    let chars: Vec<char> = w.chars().collect();
                    let end = (*s + *l).min(chars.len());
                    if *s < chars.len() {
                        let extracted: String = chars[*s..end].iter().collect();
                        new_results.push(extracted);
                    } else {
                        new_results.push(w.clone());
                    }
                }
                RuleOp::OverwriteAt(n, c) => {
                    let mut chars: Vec<char> = w.chars().collect();
                    if *n < chars.len() {
                        chars[*n] = *c;
                    }
                    new_results.push(chars.into_iter().collect());
                }
                RuleOp::InsertAt(n, c) => {
                    let mut chars: Vec<char> = w.chars().collect();
                    if *n <= chars.len() {
                        chars.insert(*n, *c);
                    }
                    new_results.push(chars.into_iter().collect());
                }
                RuleOp::SwapAt(a, b) => {
                    let chars: Vec<char> = w.chars().collect();
                    if *a < chars.len() && *b < chars.len() && a != b {
                        let mut new_chars = chars.clone();
                        new_chars[*b] = chars[*a];
                        new_chars[*a] = chars[*b];
                        new_results.push(new_chars.into_iter().collect());
                    } else {
                        new_results.push(w.clone());
                    }
                }
                RuleOp::Substitute(a, b) => {
                    new_results.push(w.chars().map(|c| if c == *a { *b } else { c }).collect());
                }
            }
        }
        results = new_results;
        if results.is_empty() {
            break;
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lowercase() {
        let ops = parse_rule("l").unwrap();
        let result = apply_rule("HELLO", &ops);
        assert_eq!(result, vec!["hello"]);
    }

    #[test]
    fn test_uppercase() {
        let ops = parse_rule("u").unwrap();
        let result = apply_rule("hello", &ops);
        assert_eq!(result, vec!["HELLO"]);
    }

    #[test]
    fn test_reverse() {
        let ops = parse_rule("r").unwrap();
        let result = apply_rule("hello", &ops);
        assert_eq!(result, vec!["olleh"]);
    }

    #[test]
    fn test_duplicate() {
        let ops = parse_rule("d").unwrap();
        let result = apply_rule("abc", &ops);
        assert_eq!(result, vec!["abcabc"]);
    }

    #[test]
    fn test_append() {
        let ops = parse_rule("$1").unwrap();
        let result = apply_rule("pass", &ops);
        assert_eq!(result, vec!["pass1"]);
    }

    #[test]
    fn test_prepend() {
        let ops = parse_rule("^!").unwrap();
        let result = apply_rule("pass", &ops);
        assert_eq!(result, vec!["!pass"]);
    }

    #[test]
    fn test_toggle_at() {
        let ops = parse_rule("T0").unwrap();
        let result = apply_rule("Hello", &ops);
        assert_eq!(result, vec!["hello"]);
    }

    #[test]
    fn test_substitute() {
        let ops = parse_rule("so0").unwrap();
        let result = apply_rule("hello world", &ops);
        assert_eq!(result, vec!["hell0 w0rld"]);
    }

    #[test]
    fn test_extract_range() {
        let ops = parse_rule("x23").unwrap();
        let result = apply_rule("hello", &ops);
        assert_eq!(result, vec!["llo"]);
    }

    #[test]
    fn test_swap_at() {
        let ops = vec![RuleOp::SwapAt(2, 3)];
        let result = apply_rule("abcdef", &ops);
        assert_eq!(result, vec!["abdcef"]);
    }

    #[test]
    fn test_reflect_empty() {
        let ops = vec![RuleOp::Reflect];
        let result = apply_rule("", &ops);
        assert_eq!(result, vec![""]);
    }
}
