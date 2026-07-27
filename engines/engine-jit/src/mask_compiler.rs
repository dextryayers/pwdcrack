use crate::ir::{IrProgram, IrInstruction, MaskOp, CharClass};
use target_lexicon::Triple;

pub struct MaskCompiler;

impl MaskCompiler {
    pub fn new() -> Self {
        MaskCompiler
    }

    /// Parse a mask pattern into IR instructions
    /// e.g. "?l?l?l?d" → 3 lowercase + 1 digit char classes concatenated
    pub fn compile(&self, mask: &str) -> Option<IrProgram> {
        let ops = self.parse(mask)?;
        let mut prog = IrProgram::new();
        prog.push(IrInstruction::Mask(MaskOp::Concat { ops }));
        Some(prog)
    }

    /// Parse mask string into MaskOp list
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
                    b'1' => CharClass::Custom,
                    b'2' => CharClass::Custom,
                    b'3' => CharClass::Custom,
                    _ => return None,
                };
                ops.push(MaskOp::CharClass { class });
                i += 2;
            } else if bytes[i] == b'[' {
                let end = i + 1;
                let mut start_byte = 0u8;
                let mut end_byte = 0u8;
                if end < bytes.len() {
                    start_byte = bytes[end];
                }
                let mut j = end + 1;
                while j < bytes.len() && bytes[j] != b']' {
                    if bytes[j] == b'-' && j + 1 < bytes.len() {
                        end_byte = bytes[j + 1];
                        j += 2;
                    } else {
                        j += 1;
                    }
                }
                ops.push(MaskOp::Range { start: start_byte, end: end_byte });
                i = j + 1;
            } else {
                ops.push(MaskOp::Literal { byte: bytes[i] });
                i += 1;
            }
        }

        Some(ops)
    }

    /// Generate native code via Cranelift
    pub fn jit_compile(&self, program: &IrProgram) -> Option<super::MaskFn> {
        let flag_builder = cranelift_codegen::isa::Builder::new(
            Triple::host(),
            cranelift_codegen::isa::CallConv::SystemV,
        );
        let isa = flag_builder.finish(cranelift_codegen::settings::Flags::new(
            cranelift_codegen::settings::builder(),
        )).ok()?;

        let module = cranelift_module::Module::new(
            cranelift_module::default_libcall_names(),
            isa,
            cranelift_module::Module::new(
                cranelift_codegen::context::Context::new(),
            ),
        );
        None
    }
}
