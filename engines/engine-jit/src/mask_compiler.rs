use crate::ir::{IrProgram, IrInstruction, MaskOp, CharClass};

pub struct MaskCompiler;

impl MaskCompiler {
    pub fn new() -> Self { MaskCompiler }

    pub fn compile(&self, mask: &str) -> Option<IrProgram> {
        let ops = self.parse(mask)?;
        let mut prog = IrProgram::new();
        prog.push(IrInstruction::Mask(MaskOp::Concat { ops }));
        Some(prog)
    }

    pub fn parse(&self, mask: &str) -> Option<Vec<MaskOp>> {
        let mut ops = Vec::new();
        let bytes = mask.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'?' && i + 1 < bytes.len() {
                let class = match bytes[i + 1] {
                    b'l' => CharClass::Lowercase,
                    b'u' => CharClass::Uppercase,
                    b'd' => CharClass::Digit,
                    b'h' => CharClass::HexLower,
                    b'H' => CharClass::HexUpper,
                    b's' => CharClass::Special,
                    b'a' => CharClass::All,
                    b'1'..=b'3' => CharClass::Custom,
                    _ => return None,
                };
                ops.push(MaskOp::CharClass { class });
                i += 2;
            } else if bytes[i] == b'[' {
                let start_byte = bytes.get(i + 1).copied()?;
                let end_byte = bytes.get(i + 3).copied()?;
                ops.push(MaskOp::Range { start: start_byte, end: end_byte });
                i += 4;
                if bytes.get(i).copied() == Some(b']') { i += 1; }
            } else {
                ops.push(MaskOp::Literal { byte: bytes[i] });
                i += 1;
            }
        }
        Some(ops)
    }

    pub fn jit_compile(&self, _program: &IrProgram) -> Option<super::MaskFn> {
        // Cranelift JIT codegen: compile mask IR to a native `MaskFn`.
        // TODO: implement real codegen using cranelift-jit for 5-10x mask expansion speedup.
        // Returns None to fall back to the interpreter.
        None
    }
}
