use cranelift_codegen::{
    ir::{AbiParam, types, InstBuilder, UserFuncName, condcodes::IntCC, MemFlagsData},
    settings::{self, Configurable},
};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{Module, Linkage, default_libcall_names, DataDescription};

use crate::ir::{IrProgram, IrInstruction, MaskOp, CharClass};

pub struct MaskCompiler;

fn charset_bytes(class: CharClass) -> &'static [u8] {
    match class {
        CharClass::Lowercase => b"abcdefghijklmnopqrstuvwxyz",
        CharClass::Uppercase => b"ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        CharClass::Digit => b"0123456789",
        CharClass::HexLower => b"0123456789abcdef",
        CharClass::HexUpper => b"0123456789ABCDEF",
        CharClass::Special => b"!@#$%^&*()-_+=~`[]{}|;:',.<>?/",
        CharClass::All => b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=~`[]{}|;:',.<>?/",
        CharClass::Custom => b"",
    }
}

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

    fn flatten_mask(ops: &[MaskOp]) -> Vec<(Vec<u8>, u64)> {
        let mut positions = Vec::new();
        for op in ops {
            match op {
                MaskOp::Literal { byte } => positions.push((vec![*byte], 1u64)),
                MaskOp::CharClass { class } => {
                    let data = charset_bytes(*class).to_vec();
                    let len = data.len() as u64;
                    positions.push((data, len));
                }
                MaskOp::Range { start, end } => {
                    let data: Vec<u8> = (*start..=*end).collect();
                    let len = data.len() as u64;
                    positions.push((data, len));
                }
                _ => positions.push((vec![b'?'], 1u64)),
            }
        }
        positions
    }

    pub fn jit_compile(&self, program: &IrProgram) -> Option<super::MaskFn> {
        let ops = match program.instructions.first()? {
            IrInstruction::Mask(MaskOp::Concat { ops }) => ops.clone(),
            _ => return None,
        };
        let positions = Self::flatten_mask(&ops);
        if positions.is_empty() || positions.len() > 64 {
            return None;
        }
        let pw_len = positions.len() as u64;

        let mut flag_builder = settings::builder();
        flag_builder.set("use_colocated_libcalls", "false").ok();
        flag_builder.set("is_pic", "false").ok();
        let builder = JITBuilder::new(default_libcall_names()).ok()?;
        let mut module = JITModule::new(builder);
        let mut ctx = module.make_context();
        let mut bcx_ctx = FunctionBuilderContext::new();

        let mut sig = module.make_signature();
        sig.params.push(AbiParam::new(types::I64)); // keyspace_start
        sig.params.push(AbiParam::new(types::I64)); // keyspace_end
        sig.params.push(AbiParam::new(types::I64)); // output ptr
        sig.returns.push(AbiParam::new(types::I32));

        let func_id = module.declare_function("mask_fn", Linkage::Local, &sig).ok()?;
        ctx.func.signature = sig;
        ctx.func.name = UserFuncName::user(0, func_id.as_u32());

        // Build charset data section
        let mut data_section = Vec::new();
        let mut data_offsets = Vec::new();
        let mut offset: u64 = 0;
        for (charset, _) in &positions {
            data_offsets.push(offset);
            data_section.extend_from_slice(charset);
            offset += charset.len() as u64;
        }
        let data_id = module.declare_data("mask_data", Linkage::Local, true, false).ok()?;
        let mut data_desc = DataDescription::new();
        data_desc.define(data_section.into_boxed_slice());
        module.define_data(data_id, &data_desc).ok()?;
        let data_gv = module.declare_data_in_func(data_id, &mut ctx.func);

        // Build function body
        {
            let mut func_ctx = FunctionBuilder::new(&mut ctx.func, &mut bcx_ctx);
            let entry = func_ctx.create_block();
            let loop_hdr = func_ctx.create_block();
            let loop_body = func_ctx.create_block();
            let exit = func_ctx.create_block();

            func_ctx.switch_to_block(entry);
            func_ctx.append_block_params_for_function_params(entry);
            let params = func_ctx.block_params(entry);
            let start = params[0];
            let end = params[1];
            let out_ptr = params[2];

            let idx = func_ctx.declare_var(types::I64);
            let written = func_ctx.declare_var(types::I32);
            func_ctx.def_var(idx, start);
            let zero_i32 = func_ctx.ins().iconst(types::I32, 0i64);
            func_ctx.def_var(written, zero_i32);
            func_ctx.ins().jump(loop_hdr, &[]);

            func_ctx.switch_to_block(loop_hdr);
            let cur_idx = func_ctx.use_var(idx);
            let cmp = func_ctx.ins().icmp(IntCC::UnsignedLessThan, cur_idx, end);
            func_ctx.ins().brif(cmp, loop_body, &[], exit, &[]);

            func_ctx.switch_to_block(loop_body);
            let mut temp = cur_idx;

            for pos in (0..positions.len()).rev() {
                let (_, size) = &positions[pos];
                let sz = *size;
                let sz_val = func_ctx.ins().iconst(types::I64, sz as i64);
                let char_idx = if sz <= 1 {
                    func_ctx.ins().iconst(types::I64, 0i64)
                } else {
                    func_ctx.ins().urem(temp, sz_val)
                };
                temp = if sz <= 1 {
                    temp
                } else {
                    func_ctx.ins().udiv(temp, sz_val)
                };

                let base = func_ctx.ins().symbol_value(types::I64, data_gv);
                let base_off = func_ctx.ins().iconst(types::I64, data_offsets[pos] as i64);
                let base_plus_off = func_ctx.ins().iadd(base, base_off);
                let addr = func_ctx.ins().iadd(base_plus_off, char_idx);
                let byte_val = func_ctx.ins().load(types::I8, MemFlagsData::trusted(), addr, 0);

                let written_val = func_ctx.use_var(written);
                let w = func_ctx.ins().uextend(types::I64, written_val);
                let pw_len_val = func_ctx.ins().iconst(types::I64, pw_len as i64);
                let w_off = func_ctx.ins().imul(w, pw_len_val);
                let p_off = func_ctx.ins().iconst(types::I64, pos as i64);
                let out_plus_w = func_ctx.ins().iadd(out_ptr, w_off);
                let s_addr = func_ctx.ins().iadd(out_plus_w, p_off);
                func_ctx.ins().store(MemFlagsData::trusted(), byte_val, s_addr, 0);
            }

            let one_i64 = func_ctx.ins().iconst(types::I64, 1i64);
            let next_idx = func_ctx.ins().iadd(cur_idx, one_i64);
            func_ctx.def_var(idx, next_idx);
            let written_cur = func_ctx.use_var(written);
            let one_i32 = func_ctx.ins().iconst(types::I32, 1i64);
            let next_written = func_ctx.ins().iadd(written_cur, one_i32);
            func_ctx.def_var(written, next_written);
            func_ctx.ins().jump(loop_hdr, &[]);

            func_ctx.switch_to_block(exit);
            let final_written = func_ctx.use_var(written);
            func_ctx.ins().return_(&[final_written]);
            func_ctx.seal_all_blocks();
            func_ctx.finalize(module.target_config());
        }

        module.define_function(func_id, &mut ctx).ok()?;
        module.finalize_definitions().ok()?;
        let code = module.get_finalized_function(func_id);
        // SAFETY: `code` is a `*const u8` pointing to executable memory containing
        // a valid function with the signature `MaskFn`. Data and function pointers
        // have the same representation on x86_64 and AArch64 (our only supported
        // targets), so this transmute is safe.
        let fn_ptr: super::MaskFn = unsafe { std::mem::transmute::<*const u8, super::MaskFn>(code) };
        Some(fn_ptr)
    }
}
