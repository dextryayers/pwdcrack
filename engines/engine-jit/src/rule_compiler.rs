// TODO: implement JIT codegen via Cranelift for 3-5x rule application speedup.
// The current implementation is an interpreter fallback that applies the IR
// rules at runtime without native code generation.

use std::sync::Mutex;

use crate::ir::{IrProgram, IrInstruction, RuleOp};

pub struct RuleCompiler;

static RULE_OPS: Mutex<Option<&'static [RuleOp]>> = Mutex::new(None);

extern "C" fn rule_interpreter(input: *const u8, len: u32, output: *mut u8) -> u32 {
    let ops_guard = RULE_OPS.lock().unwrap();
    let ops = match *ops_guard {
        Some(o) => o,
        None => return 0,
    };

    // SAFETY: Caller guarantees `input` is valid for `len` bytes and `output`
    // points to at least 256 bytes of writable memory.
    let input_bytes = unsafe { std::slice::from_raw_parts(input, len as usize) };
    let word = unsafe { std::str::from_utf8_unchecked(input_bytes) };

    let mut words = vec![word.to_string()];
    for op in ops {
        let mut next = Vec::new();
        for w in &words {
            match *op {
                RuleOp::Lowercase => next.push(w.to_lowercase()),
                RuleOp::Uppercase => next.push(w.to_uppercase()),
                RuleOp::Capitalize => {
                    let mut s = w.clone();
                    if let Some(c) = s.get_mut(0..1) {
                        c.make_ascii_uppercase();
                    }
                    next.push(s);
                }
                RuleOp::Invert => {
                    let mut s = w.clone();
                    if let Some(c) = s.get_mut(0..1) {
                        c.make_ascii_lowercase();
                    }
                    next.push(s);
                }
                RuleOp::ToggleAll => {
                    let s: String = w.chars().map(|c| {
                        if c.is_ascii_lowercase() { c.to_ascii_uppercase() }
                        else if c.is_ascii_uppercase() { c.to_ascii_lowercase() }
                        else { c }
                    }).collect();
                    next.push(s);
                }
                RuleOp::Toggle(pos) => {
                    let mut chars: Vec<char> = w.chars().collect();
                    let p = pos as usize;
                    if p < chars.len() {
                        let c = chars[p];
                        chars[p] = if c.is_ascii_lowercase() { c.to_ascii_uppercase() }
                            else if c.is_ascii_uppercase() { c.to_ascii_lowercase() }
                            else { c };
                    }
                    next.push(chars.into_iter().collect());
                }
                RuleOp::Reverse => next.push(w.chars().rev().collect()),
                RuleOp::Duplicate => next.push(format!("{}{}", w, w)),
                RuleOp::Reflect => {
                    if w.is_empty() {
                        next.push(w.clone());
                    } else {
                        let rev: String = w.chars().rev().collect();
                        next.push(format!("{}{}", w, &rev[1..]));
                    }
                }
                RuleOp::RotateLeft => {
                    let mut chars: Vec<char> = w.chars().collect();
                    if !chars.is_empty() {
                        chars.rotate_left(1);
                    }
                    next.push(chars.into_iter().collect());
                }
                RuleOp::RotateRight => {
                    let mut chars: Vec<char> = w.chars().collect();
                    if !chars.is_empty() {
                        chars.rotate_right(1);
                    }
                    next.push(chars.into_iter().collect());
                }
                RuleOp::Append(ref suffix) => {
                    let suffix_str = unsafe { std::str::from_utf8_unchecked(suffix) };
                    next.push(format!("{}{}", w, suffix_str));
                }
                RuleOp::Prepend(ref prefix) => {
                    let prefix_str = unsafe { std::str::from_utf8_unchecked(prefix) };
                    next.push(format!("{}{}", prefix_str, w));
                }
                RuleOp::DeleteFirst(n) => {
                    next.push(w.chars().skip(n as usize).collect());
                }
                RuleOp::DeleteLast(n) => {
                    let chars: Vec<char> = w.chars().collect();
                    let l = chars.len();
                    if (n as usize) >= l {
                        next.push(String::new());
                    } else {
                        next.push(chars[..l - n as usize].iter().collect());
                    }
                }
                RuleOp::DeleteAt(pos) => {
                    let p = pos as usize;
                    let s: String = w.chars().enumerate()
                        .filter(|(i, _)| *i != p)
                        .map(|(_, c)| c)
                        .collect();
                    next.push(s);
                }
                RuleOp::TruncateLeft(n) => {
                    next.push(w.chars().take(n as usize).collect());
                }
                RuleOp::TruncateRight(n) => {
                    let chars: Vec<char> = w.chars().collect();
                    let l = chars.len();
                    if (n as usize) >= l {
                        next.push(String::new());
                    } else {
                        next.push(chars[n as usize..].iter().collect());
                    }
                }
                RuleOp::Substitute(pos, byte) => {
                    let mut chars: Vec<char> = w.chars().collect();
                    let p = pos as usize;
                    if p < chars.len() {
                        chars[p] = byte as char;
                    }
                    next.push(chars.into_iter().collect());
                }
                RuleOp::Insert(pos, byte) => {
                    let mut chars: Vec<char> = w.chars().collect();
                    let p = pos as usize;
                    if p <= chars.len() {
                        chars.insert(p, byte as char);
                    }
                    next.push(chars.into_iter().collect());
                }
                RuleOp::ReplaceAll(from, to) => {
                    next.push(w.chars()
                        .map(|c| if c == from as char { to as char } else { c })
                        .collect());
                }
                RuleOp::Purge(ch) => {
                    next.push(w.chars().filter(|c| *c != ch as char).collect());
                }
                RuleOp::DuplicateFirstN(n) => {
                    let prefix: String = w.chars().take(n as usize).collect();
                    next.push(format!("{}{}", w, prefix));
                }
                RuleOp::DuplicateLastN(n) => {
                    let suffix: String = w.chars().rev().take(n as usize).collect::<Vec<_>>()
                        .into_iter().rev().collect();
                    next.push(format!("{}{}", w, suffix));
                }
            }
        }
        words = next;
        if words.is_empty() {
            break;
        }
    }

    if let Some(result) = words.first() {
        let bytes = result.as_bytes();
        let out_len = bytes.len().min(255);
        // SAFETY: `output` is valid for at least 256 bytes (caller guarantees).
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, out_len);
        }
        out_len as u32
    } else {
        0
    }
}

impl RuleCompiler {
    pub fn new() -> Self { RuleCompiler }

    pub fn compile(&self, rule: &str) -> Option<IrProgram> {
        let ops = self.parse_rules(rule)?;
        let mut prog = IrProgram::new();
        for op in ops { prog.push(IrInstruction::Rule(op)); }
        Some(prog)
    }

    pub fn parse_rules(&self, rule: &str) -> Option<Vec<RuleOp>> {
        let mut ops = Vec::new();
        let bytes = rule.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let op = match bytes[i] {
                b'l' => RuleOp::Lowercase,
                b'u' => RuleOp::Uppercase,
                b'c' => RuleOp::Capitalize,
                b'C' => RuleOp::Invert,
                b't' => {
                    let pos = (bytes.get(i + 1).copied()? - b'0') as u32;
                    i += 1; RuleOp::Toggle(pos)
                }
                b'T' => RuleOp::ToggleAll,
                b'r' => RuleOp::Reverse,
                b'd' => RuleOp::Duplicate,
                b'f' => RuleOp::Reflect,
                b'{' => RuleOp::RotateLeft,
                b'}' => RuleOp::RotateRight,
                b'D' => {
                    let n = (bytes.get(i + 1).copied()? - b'0') as u32;
                    i += 1; RuleOp::DeleteFirst(n)
                }
                b'Z' => {
                    let n = (bytes.get(i + 1).copied()? - b'0') as u32;
                    i += 1; RuleOp::DeleteLast(n)
                }
                b'X' => {
                    let pos = (bytes.get(i + 1).copied()? - b'0') as u32;
                    i += 2; RuleOp::DeleteAt(pos)
                }
                b's' if i + 3 < bytes.len() && bytes[i + 2] == b'-' => {
                    let from = bytes[i + 1];
                    let to = bytes[i + 3];
                    i += 3; RuleOp::ReplaceAll(from, to)
                }
                b'S' => {
                    let pos = (bytes.get(i + 1).copied()? - b'0') as u32;
                    let ch = bytes.get(i + 2).copied()?;
                    i += 2; RuleOp::Substitute(pos, ch)
                }
                b'@' => {
                    let ch = bytes.get(i + 1).copied()?;
                    i += 1; RuleOp::Purge(ch)
                }
                b'^' => {
                    i += 1;
                    let mut prefix = Vec::new();
                    while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\n' {
                        prefix.push(bytes[i]); i += 1;
                    }
                    RuleOp::Prepend(prefix)
                }
                b'$' => {
                    i += 1;
                    let mut suffix = Vec::new();
                    while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\n' {
                        suffix.push(bytes[i]); i += 1;
                    }
                    RuleOp::Append(suffix)
                }
                b'k' => {
                    let n = (bytes.get(i + 1).copied()? - b'0') as u32;
                    i += 1; RuleOp::DuplicateFirstN(n)
                }
                b'K' => {
                    let n = (bytes.get(i + 1).copied()? - b'0') as u32;
                    i += 1; RuleOp::DuplicateLastN(n)
                }
                _ => { i += 1; continue; }
            };
            ops.push(op);
            i += 1;
        }
        Some(ops)
    }

    pub fn jit_compile(&self, program: &IrProgram) -> Option<super::RuleFn> {
        // TODO: implement real codegen using cranelift-jit for 3-5x rule application speedup.
        // For now, this is an interpreter fallback.

        let ops: Vec<RuleOp> = program.instructions.iter()
            .filter_map(|inst| match inst {
                IrInstruction::Rule(op) => Some(op.clone()),
                _ => None,
            })
            .collect();

        if ops.is_empty() {
            return None;
        }

        // Leak the ops into a static so the extern "C" fn can access them.
        // This is acceptable because JIT compilation happens infrequently.
        let leaked: &'static [RuleOp] = Box::leak(ops.into_boxed_slice());
        *RULE_OPS.lock().unwrap() = Some(leaked);

        Some(rule_interpreter)
    }
}
