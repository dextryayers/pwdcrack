# GPU shader inventory

Engine: `engines/engine-gpu`, wgpu 26.0.1 (Vulkan on this host), naga 26.
Every supported shader is parsed and validated at build time by
`engines/engine-gpu/build.rs` and again by `tests/shaders.rs`.

## Bind layout

All supported kernels share one layout, declared at the top of `md5.wgsl`:

| Binding | Declaration | Contents |
|---------|-------------|----------|
| 0 | `var<storage, read> candidates: array<Candidate>` | 68 bytes per candidate: 16 little endian message words followed by the byte length |
| 1 | `var<storage, read_write> results: array<u32>` | one match flag per candidate, 4 bytes each |
| 2 | `var<storage, read> expected: array<u32, 16>` | target digest, digest bytes in order, four bytes per word, zero padded to 64 bytes |
| 3 | `var<uniform> count: u32` | number of candidates in the dispatch |

`Candidate.data` holds the first 64 message bytes. `Candidate.len` is the byte
count before padding. A message of 55 bytes or less pads into one 64 byte block;
56 to 64 bytes pads into two. SHA-512 and BLAKE2b always use one 128 byte block,
which is enough for 64 bytes of message plus padding.

The target buffer is always interpreted as digest bytes, not as algorithm state.
MD5, MD4, NTLM and RIPEMD-160 compare their state words directly (little endian
output). SHA-1, SHA-256 and SHA-512 byte swap the state before comparing (big
endian output). BLAKE2b compares its little endian words directly.

Every supported kernel declares `@compute @workgroup_size(64)`. A dispatch of
`n` candidates launches `ceil(n / 64)` workgroups, and the shader returns early
for the invocation index at or above `count`.

## Supported kernels

| File | Entry point | Hash types | Digest | Padding length field |
|------|-------------|------------|--------|----------------------|
| `md5.wgsl` | `main` | md5 | 16 bytes | 64 bit little endian, low word at block word 14 |
| `md4.wgsl` | `main` | md4, ntlm | 16 bytes | 64 bit little endian, low word at block word 14 |
| `sha1.wgsl` | `main` | sha1 | 20 bytes | 64 bit big endian, byte swapped into block word 15 |
| `sha256.wgsl` | `main` | sha256 | 32 bytes | 64 bit big endian, byte swapped into block word 15 |
| `sha512.wgsl` | `main` | sha512 | 64 bytes | 128 bit big endian, byte swapped into block word 31 |
| `ripemd160.wgsl` | `main` | ripemd160 | 20 bytes | 64 bit little endian, low word at block word 14 |
| `blake2b.wgsl` | `main` | blake2b | 64 bytes | none; BLAKE2 pads with zeros and carries the length in `v[12]` |

NTLM has no shader of its own. It is MD4 over the UTF-16LE encoding of the
candidate, and `GpuCracker::pack_candidate` performs that encoding before the MD4
kernel runs. The pipeline is registered once and both hash names resolve to it.

SHA-512 and BLAKE2b hold 64 bit words as two `u32` halves (`struct U64` in both
files). wgpu 26 does not expose a feature that enables 64 bit integers in WGSL,
so the pair form is the only portable implementation.

## Verification

`tests/kernels.rs` runs on a real adapter and checks:

1. `gpu_matches_published_vectors`: one known answer per hash type, taken from
   RFC 1321, RFC 1320, FIPS 180-4, the RIPEMD-160 paper, RFC 7693 and the NTLM
   specification. `ntlm("password") = 8846f7eaee8fb117ad06bdd830b7586c`.
2. `gpu_kernels_match_the_reference_on_one_thousand_candidates`: 1,000
   deterministic candidates per hash type with lengths 0, 1, 55, 56, 63 and 64
   included, compared against the RustCrypto implementation. Exactly one
   candidate matches, and `verify_many` returns the same flags through the batch
   API.
3. `a_target_of_the_wrong_length_is_rejected`: a 32 byte target is refused for
   MD5, and a partial candidate record is refused.

The test calls `dispatch_batch` directly, not `verify_many`, because `verify_many`
falls back to the CPU when a dispatch fails. A fallback would otherwise hide a
broken kernel behind correct answers.

## Drivers and memory

`src/hw.rs` reads `mem_info_vram_total` and `mem_info_gtt_total` from the DRM card
whose PCI vendor and device ids match `wgpu::AdapterInfo`. On a host with no
matching card, or on a non-Linux platform, both values are `None` and
`AdapterInfo::memory_summary` prints "unknown" rather than a guessed size.

On the development host (AMD Ryzen 7 5700U, Radeon Lucienne, RADV) this reports
512 MiB dedicated and 9687 MiB shared. The batch size is computed from
`max_storage_buffer_binding_size * 0.8 / 68`, clamped to between 64 and 1,048,576
candidates.

## Files under `src/shaders/unsupported`

26 files are kept for reference and are not compiled, validated or dispatched:
`argon2i_core`, `bcrypt`, `bcrypt_init`, `blake3`, `double_md5`, `gost94`,
`hmac_sha1`, `hmac_sha256`, `lm_hash`, `md2`, `md5_opt`, `ntlm`,
`pbkdf2_sha256`, `pbkdf2_sha512`, `ripemd128`, `ripemd160_opt`,
`salted_sha256`, `sha1_opt`, `sha256_opt`, `sha3_256`, `sha384`, `sha512_224`,
`sha512_opt`, `streebog256`, `tiger192` and `whirlpool`. The `ntlm` copy in that
directory is one of them; NTLM itself is supported through `md4.wgsl`.

They fail naga 26 with `unknown type: u8`, the reserved word `target` used as a
binding, 64 bit literals with no representable type, or a constant array whose
initialiser does not match its declared length. `src/shaders/unsupported/README.md`
records the exact reasons. The build script and the shader test only look at the
top level of `src/shaders`, so a file moved back without being fixed fails the
build.
