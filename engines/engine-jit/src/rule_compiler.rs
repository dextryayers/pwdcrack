use crate::ir::{IrProgram, IrInstruction, RuleOp};

pub struct RuleCompiler;

impl RuleCompiler {
    pub fn new() -> Self {
        RuleCompiler
    }

    pub fn compile(&self, rule: &str) -> Option<IrProgram> {
        let ops = self.parse_rules(rule)?;
        let mut prog = IrProgram::new();
        for op in ops {
            prog.push(IrInstruction::Rule(op));
        }
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
                    if i + 1 < bytes.len() {
                        let pos = (bytes[i + 1] - b'0') as u32;
                        i += 1;
                        RuleOp::Toggle(pos)
                    } else { return None; }
                }
                b'T' => RuleOp::ToggleAll,
                b'r' => RuleOp::Reverse,
                b'd' => RuleOp::Duplicate,
                b'f' => RuleOp::Reflect,
                b'{' => RuleOp::RotateLeft,
                b'}' => RuleOp::RotateRight,
                b'D' => {
                    if i + 1 < bytes.len() {
                        let n = (bytes[i + 1] - b'0') as u32;
                        i += 1;
                        RuleOp::DeleteFirst(n)
                    } else { return None; }
                }
                b'Z' => {
                    if i + 1 < bytes.len() {
                        let n = (bytes[i + 1] - b'0') as u32;
                        i += 1;
                        RuleOp::DeleteLast(n)
                    } else { return None; }
                }
                b'X' => {
                    if i + 2 < bytes.len() {
                        let pos = (bytes[i + 1] - b'0') as u32;
                        i += 2;
                        RuleOp::DeleteAt(pos)
                    } else { return None; }
                }
                b's' => {
                    if i + 3 < bytes.len() && bytes[i + 2] == b'-' {
                        let from = bytes[i + 1];
                        let to = bytes[i + 3];
                        i += 3;
                        RuleOp::ReplaceAll(from, to)
                    } else { return None; }
                }
                b'S' => {
                    if i + 2 < bytes.len() {
                        let pos = (bytes[i + 1] - b'0') as u32;
                        let ch = bytes[i + 2];
                        i += 2;
                        RuleOp::Substitute(pos, ch)
                    } else { return None; }
                }
                b'@' => {
                    if i + 1 < bytes.len() {
                        let ch = bytes[i + 1];
                        i += 1;
                        RuleOp::Purge(ch)
                    } else { return None; }
                }
                b'^' => {
                    i += 1;
                    let mut prefix = Vec::new();
                    while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\n' {
                        prefix.push(bytes[i]);
                        i += 1;
                    }
                    RuleOp::Prepend(prefix)
                }
                b'$' => {
                    i += 1;
                    let mut suffix = Vec::new();
                    while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\n' {
                        suffix.push(bytes[i]);
                        i += 1;
                    }
                    RuleOp::Append(suffix)
                }
                b'k' => {
                    if i + 1 < bytes.len() {
                        let n = (bytes[i + 1] - b'0') as u32;
                        i += 1;
                        RuleOp::DuplicateFirstN(n)
                    } else { return None; }
                }
                b'K' => {
                    if i + 1 < bytes.len() {
                        let n = (bytes[i + 1] - b'0') as u32;
                        i += 1;
                        RuleOp::DuplicateLastN(n)
                    } else { return None; }
                }
                _ => { i += 1; continue; }
            };
            ops.push(op);
            i += 1;
        }

        Some(ops)
    }

    pub fn jit_compile(&self, _program: &IrProgram) -> Option<super::RuleFn> {
        // Cranelift JIT for rule application
        // Would compile the rule chain to native code for 3-5x speedup
        // Uses cranelift-jit for function generation and memory management
        None
    }
}
