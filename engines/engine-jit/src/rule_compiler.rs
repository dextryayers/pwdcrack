use crate::ir::{IrProgram, IrInstruction, RuleOp};

pub struct RuleCompiler;

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

    pub fn jit_compile(&self, _program: &IrProgram) -> Option<super::RuleFn> {
        // Cranelift JIT codegen: compile rule IR to a native `RuleFn`.
        // TODO: implement real codegen using cranelift-jit for 3-5x rule application speedup.
        // Returns None to fall back to the interpreter.
        None
    }
}
