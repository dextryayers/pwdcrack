# Phase 7 Status: OpenCL, Metal, Vulkan, SYCL

Scope: `docs/plan.md` section 11, tasks P7.1 through P7.4.

## Summary

One of the four sub-phases is finished and verified on real hardware. Two are
written and verified as far as this machine allows. One was deleted, which is what
the plan recommended.

| Sub-phase | State | Verified how |
|-----------|-------|---------------|
| P7.1 OpenCL | Kernel written and verified | clang OpenCL front end, host execution, 201 digest checks, 133 kernel checks |
| P7.2 Metal | Fabricated hardware removed | The host is not macOS; the device list and the `/tmp` placeholder are gone |
| P7.3 Vulkan | **Finished, run on a real GPU** | 201 host checks, SPIR-V emitted and inspected, **121 candidates hashed on an AMD Radeon** |
| P7.4 SYCL | Deleted | Plan recommendation: the WGSL and CUDA paths cover the same hardware with less maintenance |

Nothing in this document claims a performance figure. One is measured, by
`cargo run --release -p engine-vulkan --features vulkan --bin measure`, and is
reported with its batch size and device name because a speedup number without
those is not a claim, it is a rumour.

## Hardware and runtime availability

| Resource | State |
|----------|-------|
| OpenCL ICD loader | `libOpenCL.so.1` present |
| OpenCL vendor ICDs | **none**. `/etc/OpenCL/vendors` does not exist, so there are zero OpenCL platforms |
| OpenCL compiler | `clang` 19.1.7 compiles OpenCL C without a device |
| Metal | Apple platform API, not present on Linux at all |
| Vulkan loader and ICDs | present: `radeon` (Mesa 25.0.7), `lvp`, `nouveau`, `intel`, `virtio` |
| Vulkan device used | AMD Radeon Graphics (RADV RENOIR), integrated, API 1.4 |

## P7.3 Vulkan: finished and run

### P7.3.01 and P7.3.02: the shader path exists

`shader.rs` previously had:

```rust
pub fn compile_glsl_to_spirv(src: &str, stage: &str) -> Result<Vec<u32>, VulkanError> {
    Err(VulkanError::ShaderCompile("glslc not available at runtime".into()))
}
```

It named GLSL when the shaders are WGSL, and it always failed. There was no shader
compilation in the engine. Alongside it, `spirv_from_bytes` converted with
`from_ne_bytes`, which is correct only because this host is little endian.

Now:

- `engines/engine-vulkan/shaders/md5.wgsl` is a real compute kernel
- `wgsl_to_spirv` compiles it with naga, in process, no external tool
- `spirv_from_bytes` is an explicit little endian conversion, per the SPIR-V spec
- `validate_spirv` checks the magic word and names byte swapping as such

Measured output: **3561 SPIR-V words, magic `0x07230203`, SPIR-V 1.0**.

### P7.3.04: limits are queried, not assumed

`VulkanDeviceLimits` carries `max_compute_work_group_invocations`,
`max_compute_work_group_count[0]`, `max_storage_buffer_range` and
`max_compute_shared_memory_size`, all read from `VkPhysicalDeviceProperties`. No
field has a fallback constant, because a fallback would be indistinguishable from
a measurement and would produce wrong batch sizes on a card whose limits differ.

### The device path

`kernel.rs` implements the full compute sequence: instance, physical device,
compute queue family, device, buffers, memory allocation, descriptor set layout,
shader module, pipeline layout, compute pipeline, descriptor pool and set,
command buffer, dispatch, submit, fence wait, readback.

`device.rs` was also broken and is rewritten:

- it called `ash::Entry::linked()`, which does not exist in ash 0.38, so the
  `vulkan` feature did not compile at all
- it dropped the `ash::Entry` and `ash::Instance` immediately after enumerating
  devices. Every later Vulkan call needs the instance, so even had it compiled it
  could not have dispatched anything. Both are now owned by the engine.

### Verification

`scripts/verify-vulkan-kernels.sh` runs three stages:

```
201 WGSL table checks, 0 failure(s)
SPIR-V: 3561 words, magic 0x07230203, version 1.0
device: AMD Radeon Graphics (RADV RENOIR) (integrated GPU)
candidates: 121
checks: 121
all digests matched python hashlib
```

Stage 1 checks the tables and the arithmetic against python hashlib for every
message length from 0 to 200. Stage 2 compiles and inspects the SPIR-V. Stage 3
runs the real module on the real device and compares every digest.

This is the only GPU path in the repository that has produced a correct digest on
real hardware.

### Defects found while building it

| Defect | Effect | Caught by |
|--------|--------|-----------|
| `padded_len` returned `total + 4` for an 8 byte length field | Padded length was not a multiple of 64, so every message of 56 bytes or more was compressed over a partial final block. Lengths 0 to 55 were correct, 56 and up were wrong | 145 of 201 host checks failed, and the failures started at exactly 56 |
| Length field written as 4 bytes | Same root cause | same |
| Output buffer had no `TRANSFER_SRC` usage bit | The staging copy was invalid, the staging buffer stayed all zeros, and every digest read back as zero. Indistinguishable from a kernel that did nothing | 121 checks all returned zero on the device |
| Over-length test candidate used the batch size, not the stride | A 16384 byte candidate against a 128 byte buffer; the run was rejected before reaching the GPU | The device check reported the reason |
| `spirv_from_bytes` used `from_ne_bytes` | Correct only by host endianness | Rewritten as explicit little endian |
| `allocate_descriptor_sets`, `cmd_bind_descriptor_sets`, `DescriptorPoolSize`, `map_memory` all called with the wrong arity for ash 0.38 | The feature did not compile | Compiler |

## P7.1 OpenCL: written and verified as far as possible here

### The kernel

`engines/engine-opencl/src/kernels/md5.cl` was rewritten. Its previous state:

| Defect | Effect |
|--------|--------|
| Four hand-picked round constants out of 64, one per quarter, plus `0x5A827999` added every step | Wrong digest for every input |
| Rotation 7 for all 64 steps | Wrong |
| Round 2 word order from `(5i+1) mod 16` | Right for the first step, wrong for 15 |
| Words read through a `(__global const uint*)` cast of a `uchar*` | Needs 4 byte alignment that packed buffers do not give |
| No padding | Wrong |
| Candidates read until the first zero byte | Any candidate containing a zero byte, or shorter than 64, hashed as a truncated string |
| `w[16]` left uninitialised for short candidates | Result depended on whatever the driver left on the stack |
| Candidate stride hardcoded to 68 | The host packing had to match a literal in the shader |

### One copy of the algorithm, not two

The hash core now lives once, in `engines/kernel-common/hash_core_shared.h`, used
by both the CUDA and the OpenCL engines. OpenCL C has no portable preprocessor
include, so `scripts/gen-opencl-core.py` projects the header into
`engines/kernel-common/hash_core.cl` at build time, and `engine-opencl/build.rs`
concatenates that with the kernel body.

Two copies of verified crypto drifting apart is a maintenance hazard that shows up
as a silent wrong digest, which is what both previous kernels were.

### Verification

```
core.cl accepted by the OpenCL front end
md5.cl accepted by the OpenCL front end
133 checks, 0 failure(s)
201 core checks, 0 failure(s)
```

- clang in OpenCL mode accepts both the core and the assembled kernel, so they are
  valid OpenCL C
- 201 digests from the generated core against python hashlib
- 133 kernel body checks through a host shim: every candidate length from 0 to
  127, an over-length candidate, a candidate containing a zero byte, and three
  known vectors

The kernel body shim caught two more bugs during development: a reference that
computed a digest for lengths above the kernel's ceiling instead of expecting
zero, and a harness that passed a 128 byte buffer for messages up to 200 bytes so
`pw_pad_md` returned 0 and nothing was hashed.

### What is not verified

The launch path is not written, and `crack_md5` returns a diagnosis rather than an
error string. `OpenclError` was a single `NotEnabled` covering three distinct
problems; it now separates no platform, no device, no such kernel in this build,
and the launch path not being implemented.

**No performance claim.** There are zero OpenCL devices on this machine.

## P7.2 Metal: fabricated hardware removed

`device.rs` constructed two devices behind `#[cfg(target_os = "macos")]`:

```rust
name: "Apple GPU", vendor: "Apple", compute_units: 64, gpu_family: "Apple9"
name: "Intel GPU", vendor: "Intel", compute_units: 48, max_threads_per_group: 512
```

Those numbers were invented. No query was made, so a MacBook Air and a Mac Pro
would have reported identical compute units and an identical GPU family. On
non-macOS it read `/tmp/metal_devices.txt`, which nothing in this repository
writes, so the path was always empty.

Both are removed. `detect_all` returns empty off macOS, and the macOS arm is the
place `MTLCreateSystemDefaultDevice()` belongs. Four tests prevent regression,
including one that asserts the specific fabricated values never reappear and one
that asserts no file is read.

**Nothing is claimed about Metal performance.** The platform is not available
here, so no Metal code was written.

## P7.4 SYCL: deleted

`engines/engine-sycl` was 65 lines, `device.rs` returned `None` with a log
message, and no root crate code referenced it. The plan recommends deletion:
sycl-rs is a large surface to maintain, and the Vulkan and CUDA paths reach the
same hardware.

Removed: the crate, the workspace member, the feature, the optional dependency,
and the `ARCHITECTURE.md` row. `docs/plan.md` still records the decision, which
is appropriate for a master plan.

## Toolchain constraints

Recorded in `rust-toolchain.toml`:

- naga 30 and 31 require rustc 1.87; the local toolchain is 1.85.1
- naga 28 compiles here and is used
- naga 26 also compiles but maps **every** `var<storage>` to read only, so a
  compute kernel that writes results cannot be expressed in it. Validation
  rejects any store with `InvalidStorePointer`. The shader parses cleanly and is
  unusable, which is why `shader.rs` has a test asserting the output binding is
  declared `read_write`

The WGSL is written to the naga 28 dialect: no `u8` type, so byte buffers are
`array<u32, 128>` with values held in 0..255, and no pointer parameters, so
per-invocation scratch is passed by value and returned rather than living in a
module-scope `var<private>` that a helper captured.

## Commands

```text
scripts/verify-vulkan-kernels.sh                              # all three stages
scripts/verify-opencl-kernels.sh                              # syntax, core, kernel body
cargo test -p engine-vulkan --features vulkan --target-dir .build
cargo test -p engine-vulkan                                   # without the feature
cargo run --release -p engine-vulkan --features vulkan --target-dir .build --bin measure
```

## Next steps

Ordered by value, not by difficulty.

1. **SHA-1, SHA-256, NTLM and MD4 WGSL kernels for Vulkan.** The MD5 kernel
   establishes the whole pipeline and the verification harness; the other three
   are the same work against compression functions that are already verified in
   `hash_core_shared.h`. This is where a GPU actually pays off, since NTLM and
   MD4 are common cracking targets and MD5 alone is not.
2. **An actual cracking entry point.** `kernel.rs` computes digests; nothing
   consumes them. A kernel that computes a digest into a buffer and a host loop
   that compares it is the difference between a benchmark and a cracker.
3. **Batched dispatch.** One dispatch per candidate list rebuilds every buffer.
   Reusing buffers across dispatches and raising the batch size is what turns the
   current number into a useful one.
4. **OpenCL launch path**, on a machine that has a vendor ICD.
5. **Metal**, on macOS.
6. **The CUDA device differential test**, P6.2.08, on a machine with a toolkit.

## Test counts

| Crate | Tests |
|-------|-------|
| pwdcrack (root) | 105 |
| engine-vulkan with `vulkan` | 12 |
| engine-vulkan without | 7 |
| engine-simd | 29 |
| engine-opencl | 7 |
| engine-metal | 4 |
| engine-cuda | 3 |