# Phase 5 status: GPU engine, WGSL and wgpu

Date: 2026-10-21.
Crate: `engines/engine-gpu`.

## What was wrong before this phase

The phase started from three defects that made the GPU engine unable to compute a
single correct hash:

1. **The crate did not build.** It pinned `wgpu = "30"`, whose `naga-30` uses
   `const Vec::len` and needs rustc 1.87. The toolchain here is 1.85.1, and
   `--ignore-rust-version` fails with E0658.
2. **Every shader was invalid.** `tests/shaders.rs` parses and validates all
   shader files with naga 26. All 33 failed, including the 8 that `cracker.rs`
   claimed to load. The common causes were the non-existent type `u8`, the
   reserved word `target` used as a binding, 64 bit literals with no
   representable type, and a 1024-entry SBox declared with 96 values.
3. **Failures were silent.** `GpuCracker::new` wrapped each pipeline build in
   `if let Ok(p)` and dropped the error. A user with `--gpu` got a CPU run and no
   message. The same function also wrote a 24-byte `HashResult` per candidate into
   a buffer sized 4 bytes per candidate.

The memory size was also fabricated: `vram_mb()` returned 8192, 512 or 128
depending on `DeviceType`, none of which was read from the hardware.

## What changed

### Dependency and build

- `wgpu` is now `26.0.1`, the newest release whose `rust-version` (1.84) this
  toolchain satisfies. `wgpu` 27 needs 1.88. `naga` and `naga_oil` were unused by
  the source and were removed as runtime dependencies; `naga` 26 is a build and
  dev dependency.
- `build.rs` parses and validates every top-level `src/shaders/*.wgsl` with naga
  26 at compile time and requires a compute entry point named `main`. A shader
  that does not parse now fails `cargo build`.
- `tests/shaders.rs` repeats the check with `naga` and then creates a shader
  module for every file on the real wgpu device. Both tests pass.

### One bind layout

All supported kernels use the layout documented in `docs/GPU_SHADERS.md` and at
the top of `md5.wgsl`:

| Binding | Contents |
|---------|----------|
| 0 | `array<Candidate>`, 68 bytes: 16 little endian message words plus the byte length |
| 1 | `array<u32>`, one match flag per candidate |
| 2 | `array<u32, 16>`, target digest bytes zero padded to 64 |
| 3 | `u32` candidate count |

The plan proposed bindings 0 to 4 with a lookup table binding. No supported
kernel needs a lookup table, so the layout uses four bindings and the results
buffer is 4 bytes per candidate. The deviation is recorded here rather than
hidden.

### Kernels

Seven WGSL files implement eight hash types. NTLM is MD4 over UTF-16LE, so
`pack_candidate` encodes the candidate and the MD4 pipeline is registered for
both names.

| Hash | File | Padding result |
|------|------|----------------|
| MD5 | `md5.wgsl` | Correct |
| MD4 | `md4.wgsl` | Correct |
| NTLM | `md4.wgsl` | Correct, UTF-16LE input |
| SHA-1 | `sha1.wgsl` | Correct |
| SHA-256 | `sha256.wgsl` | Correct |
| SHA-512 | `sha512.wgsl` | Correct, 64 bit words as `u32` pairs |
| RIPEMD-160 | `ripemd160.wgsl` | Correct |
| BLAKE2b-512 | `blake2b.wgsl` | Correct, zero padding only |

Three defects were found and fixed while verifying, all in the padding or final
mix, none of them visible without a known answer or a reference:

- MD5, MD4 and RIPEMD-160 wrote the 64 bit little endian length into word 15
  instead of word 14.
- SHA-1, SHA-256 and SHA-512 wrote the big endian length as a native word, so
  the byte order was wrong after the per word byte swap.
- BLAKE2b added an MD-style `0x80` terminator. BLAKE2 pads with zeros and carries
  the byte count in `v[12]`.

### Memory, limits and buffer reuse

- `src/hw.rs` reads `mem_info_vram_total` and `mem_info_gtt_total` from the DRM
  card whose PCI vendor and device ids match `AdapterInfo`. Missing files are
  `None`, not zero. On the development host: 512 MiB dedicated, 9687 MiB shared,
  vendor `0x1002`, device `0x164c`.
- `AdapterInfo::vram_mb` and `gtt_mb` return `Option<u64>`.
  `memory_summary()` prints "unknown" when a value is absent.
- Batch size is `max_storage_buffer_binding_size * 0.8 / 68`, clamped to
  64..1,048,576. On the development host it is 1,048,576.
- `GpuBufferPool::take` only reuses a buffer whose size is at least the request,
  and rounds allocations to a power of two. The previous `pop()` could return a
  smaller buffer.
- `dispatch_batch` maps exactly the bytes it copied, not the whole rounded buffer.
- The device is requested with no required features. The previous
  `Features::TIMESTAMP_QUERY` was unused and could make `request_device` fail on
  a software adapter.

### Unsupported shaders

26 files were moved to `src/shaders/unsupported` with a README that records why
each one fails. They are not built, validated or dispatched. The files are:
argon2i_core, bcrypt, bcrypt_init, blake3, double_md5, gost94, hmac_sha1,
hmac_sha256, lm_hash, md2, md5_opt, ntlm, pbkdf2_sha256, pbkdf2_sha512,
ripemd128, ripemd160_opt, salted_sha256, sha1_opt, sha256_opt, sha3_256, sha384,
sha512_224, sha512_opt, streebog256, tiger192 and whirlpool.

This is a scope reduction against the plan's "all 31 shaders". It is recorded as
not done in `docs/plan.md`; the alternative was to keep invalid files that no
code path compiles.

## Verification

Command:

```
cargo test -p engine-gpu --target-dir .build
```

Result: 10 tests passed.

- 5 tests in `src/hw.rs` for the sysfs reader: matching card, unknown adapter,
  missing file, missing tree, PCI id parsing.
- 3 tests in `tests/kernels.rs` on the real adapter:
  - published vectors for all 8 hash types, including
    `md5("abc") = 900150983cd24fb0d6963f7d28e17f72` and
    `blake2b("abc") = ba80a53f...b92386edd4009923`;
  - 1,000 deterministic candidates per hash type, lengths 0, 1, 55, 56, 63 and
    64 included, compared against RustCrypto, with exactly one match;
  - rejection of a wrong length target and a partial candidate record.
- 2 tests in `tests/shaders.rs`: naga parse and validation, then compilation of
  every shader on the GPU.

## Measured throughput

Command:

```
cargo run --release -p engine-gpu --example throughput --target-dir .build
```

Host: AMD Ryzen 7 5700U (Zen 2, 16 threads), Radeon Lucienne iGPU,
`AMD Radeon Graphics (RADV RENOIR)`, Vulkan 1.4.309, Mesa 25.0.7.

Method: 1,000,000 candidates of 11 lowercase letters, packed before the timer,
median of three dispatches of the whole batch. The CPU column is RustCrypto on
one thread, not the AVX2 multi-buffer engine, so the ratio is against a scalar
core.

| Hash | GPU M hash/s | CPU M hash/s | Ratio |
|------|--------------|--------------|-------|
| MD5 | 50.973 | 3.944 | 12.92x |
| MD4 | 55.963 | 5.791 | 9.66x |
| NTLM | 55.138 | 2.610 | 21.12x |
| SHA-1 | 17.814 | 7.471 | 2.38x |
| SHA-256 | 35.896 | 7.560 | 4.75x |
| SHA-512 | 8.517 | 1.724 | 4.94x |
| RIPEMD-160 | 44.593 | 1.915 | 23.28x |
| BLAKE2b | 38.879 | 2.931 | 13.27x |

These are kernel dispatch numbers. They exclude wordlist reading, rule
mangling, target parsing and result reporting, which is why they are higher than
the end-to-end numbers in `docs/PHASE4_STATUS.md`.

## What is still not done

- The GPU engine is not wired into the attack loop. `--gpu` creates the device,
  logs its name and memory, and drops it; attacks still use the CPU. The CLI help
  text still says "Enable GPU acceleration" and that is not true yet.
- P5.3.03 (a three-buffer staging ring) is not implemented. `dispatch_batch`
  uploads, submits, waits and reads back one batch at a time.
- P5.3.04 (device loss reporting through `EngineInfo`) is only a fallback:
  `dispatch_batch` returns `GpuError::Timeout` when the map callback does not
  fire, and `verify_many` falls back to the CPU for that batch. There is no
  device-lost callback and no `EngineInfo` field.
- The 26 unsupported shaders are not implemented. bcrypt, argon2i and the two
  PBKDF2 kernels would also need a per-candidate salt or key, which the 68-byte
  `Candidate` record does not carry.

## Files

- `engines/engine-gpu/Cargo.toml`, `build.rs`
- `engines/engine-gpu/src/device.rs`, `lib.rs`, `hw.rs`, `buffer.rs`,
  `cracker.rs`, `pipeline.rs`, `scheduler.rs`
- `engines/engine-gpu/src/shaders/{md5,md4,sha1,sha256,sha512,ripemd160,blake2b}.wgsl`
- `engines/engine-gpu/src/shaders/unsupported/` (26 files and a README)
- `engines/engine-gpu/tests/kernels.rs`, `tests/shaders.rs`
- `engines/engine-gpu/examples/throughput.rs`
- `docs/GPU_SHADERS.md`
