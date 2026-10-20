# Unsupported shaders

These files are **not** built, validated, or dispatched. They are kept because
they were committed in earlier revisions, not because they work.

Every file in this directory fails `naga` 26, the parser wgpu 26 uses, with at
least one of:

- `unknown type: u8`, which WGSL does not have;
- `name target is a reserved keyword`, used as a binding name;
- 64 bit hex literals without a representable type, on shaders that also use
  `u64`, which wgpu 26 cannot enable;
- constant array sizes that do not match their initialiser, for example a
  1024-entry SBox declared with 96 values.

The supported kernels live one directory up: `md5.wgsl`, `md4.wgsl` (also used
for NTLM over UTF-16LE), `sha1.wgsl`, `sha256.wgsl`, `sha512.wgsl`,
`ripemd160.wgsl` and `blake2b.wgsl`. `docs/GPU_SHADERS.md` records their entry
point, bindings, workgroup size and verification.

Do not add these files back to `src/shaders` without making them parse, build a
pipeline, and pass the differential test in `tests/kernels.rs`. The build script
will reject anything that does not parse, which is how this directory kept its
files after being moved.
