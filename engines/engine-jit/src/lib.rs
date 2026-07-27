pub mod mask_compiler;
pub mod rule_compiler;
pub mod ir;

pub struct JitEngine {
    mask_compiler: mask_compiler::MaskCompiler,
    rule_compiler: rule_compiler::RuleCompiler,
}

impl JitEngine {
    pub fn new() -> Self {
        JitEngine {
            mask_compiler: mask_compiler::MaskCompiler::new(),
            rule_compiler: rule_compiler::RuleCompiler::new(),
        }
    }

    pub fn compile_mask(&self, mask: &str) -> Option<MaskFn> {
        log::info!("JIT compile mask: {}", mask);
        let prog = self.mask_compiler.compile(mask)?;
        self.mask_compiler.jit_compile(&prog)
    }

    pub fn compile_rule(&self, rule: &str) -> Option<RuleFn> {
        log::info!("JIT compile rule: {}", rule);
        let prog = self.rule_compiler.compile(rule)?;
        self.rule_compiler.jit_compile(&prog)
    }

    pub fn mask_compiler(&self) -> &mask_compiler::MaskCompiler {
        &self.mask_compiler
    }

    pub fn rule_compiler(&self) -> &rule_compiler::RuleCompiler {
        &self.rule_compiler
    }
}

pub type MaskFn = extern "C" fn(keyspace_start: u64, keyspace_end: u64, output: *mut u8) -> i32;

pub type RuleFn = extern "C" fn(input: *const u8, len: u32, output: *mut u8) -> u32;
