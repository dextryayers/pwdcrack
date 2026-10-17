# Phase 6 Status: CUDA and PTX

Scope: `docs/plan.md` section 10, tasks P6.1 through P6.3.

## Summary

The engine previously contained a 37 line MD5 kernel with six independent
correctness defects and a build that embedded C++ source where PTX was expected.
Both are fixed. The compression arithmetic and the MD5 kernel body are now
verified on the host against independent implementations.

**No CUDA toolkit and no CUDA device exist on this machine.** There is no
`nvcc`, no `CUDA_PATH`, and no NVIDIA hardware. The gate in P6.3.04, which
requires measured GPU MD5 throughput at least 20x the 8 core CPU baseline on a
real device, cannot be evaluated here and is not claimed. Nothing in this
document states a throughput figure.

What follows is exactly what was verified, and what was not.

## Hardware available on the build machine

| Resource | State |
|----------|-------|
| `nvcc` | absent |
| `CUDA_PATH`, `CUDACXX` | unset |
| `/usr/local/cuda*` | absent |
| NVIDIA device nodes | none |
| PCI display adapters | one AMD Radeon (Lucienne, integrated) |
| CPU | AMD Ryzen 7 5700U, 16 threads |

## What is verified

### Kernel arithmetic, P6.2

`engines/engine-cuda/src/kernels/hash_core.h` holds the compression functions.
It is plain C with no CUDA intrinsic, so the system C compiler builds it and the
same source the GPU would run can be executed and checked.

`scripts/verify-kernels.sh` produces:

```
220 checks, 0 failure(s)      # compression functions
132 checks, 0 failure(s)      # MD5 kernel body through a host shim
```

The 220 cover:

- RFC 1321 appendix A.5 vectors for MD5 and SHA-1
- FIPS 180-4 vectors for SHA-256 and SHA-512
- RFC 1320 vectors for MD4, cross checked against `openssl dgst -md4`
- Every MD5 message length from 0 through 200, with expected values from python
  hashlib

The 132 cover the MD5 kernel entry point executed as a kernel:

- One launch with 128 threads, thread *i* carrying a candidate of length *i*, so
  any lane reading the wrong slot shows up as a mismatch at exactly one length
- A candidate longer than the kernel limit, which must produce no digest rather
  than a digest for a truncated string
- The known vectors `"abc"`, `"hello"` and the empty string through the kernel

### Defects found and fixed in the kernel

The original `md5.cu` had six problems. Each produced a digest that did not
correspond to the input while still looking like a hash.

| Defect | Effect |
|--------|--------|
| Round constant `0x5A827999` used for all 64 steps | That is a SHA-1 constant. MD5 needs the full `K[64]` table |
| Rotation 7 used for all 64 steps | MD5 needs the per step rotation table |
| Round 2 word order computed as `(5i+1) mod 16` | Correct for the first step, wrong for the other 15 |
| `__shared__ w[16]` written by every thread | All threads in a block raced on the same 16 words |
| Words read through a `(unsigned int*)` cast of `unsigned char*` | Requires 4 byte alignment that packed candidate buffers do not provide |
| No padding at all | No `0x80` marker, no length field |

### Defects found and fixed while verifying the new kernel

Writing the replacement produced five more, all caught by the harness rather
than by inspection.

| Defect | How it was caught |
|--------|-------------------|
| MD4 rounds 2 and 3 indexed words as `w[i]` | Differentials against openssl; the correct orders are `0,4,8,12,1,5,...` and `0,8,4,12,2,10,...` |
| MD4 round 3 order derived as `(i%4)*2 + i//4` | Right for the first four steps, wrong after. Replaced with literal tables |
| SHA-1 step written as `ROTL(a + f + W + K, 5)` | SHA-1 is `ROTL(a,5) + f + e + W + K`. Rotation is linear over XOR but not over addition modulo 2^32 |
| SHA-1 and SHA-256 loaded words little endian | Both read the message as a big endian stream. MD4 and MD5 are little endian |
| SHA-256 used `ROTL` where `ROTR` is specified | Sigma and capital functions in SHA-256 are right rotations |
| SHA-1 and SHA-256 digests stored little endian | Both emit big endian words |
| The new MD5 kernel declared its pad buffer `__shared__` | Written that way by mistake during the rewrite; the same class of race the original had |
| Candidate stride hardcoded to the maximum length | The harness packed at a different stride and every lane hashed the wrong bytes. The stride is now a parameter |

A note on method. Twice during this work a Python reference and the C code agreed
with each other and were both wrong, because both came from the same
misremembering of the algorithm. Agreement between two implementations is only
evidence when they have independent origins. Every value used here is checked
against python hashlib, `openssl`, or the RustCrypto crates.

### Build pipeline, P6.1

`engines/engine-cuda/build.rs`:

- Locates `nvcc` through `CUDACXX`, then `CUDA_PATH/bin/nvcc`, then `PATH`
- Compiles each kernel with `-arch=compute_60 --ptx -O3` and embeds the PTX with
  `include_bytes!`
- Surfaces nvcc's own stdout and stderr on failure instead of a bare exit code
- Fails the build with installation instructions when `nvcc` is absent, unless
  `PW_CUDA_ALLOW_NO_NVCC=1` is set, in which case it warns and sets
  `cfg(pw_cuda_no_ptx)`

Compute capability 6.0 is the floor, covering Maxwell and everything the driver
can JIT upward from there.

Verified by running both paths: without the escape hatch the build stops with the
instructions above; with it, the crate builds and reports
`CudaEngine::kernels_embedded()` as false.

### PTX loading, P6.1.04

`src/kernel.rs` previously did `include_str!("kernels/md5.cu")` and passed the
result to `ptx::compile_ptx`, which expects PTX assembly. It was embedding C++
source. The file now embeds the PTX the build script produced, and a test asserts
the embedded bytes begin with a `.version` directive, which is the check that
would have caught the original mistake.

A build without a toolkit reports `kernels_embedded() == false` separately from
device availability, because those are different problems with different fixes.

## What is not verified

| Task | State | Reason |
|------|-------|--------|
| P6.3.04 GPU throughput gate | Not evaluated | No CUDA device. No rate is claimed anywhere in this repository |
| P6.3.01 real launch through cudarc | Written against the cudarc API, never executed | Cannot run without a device |
| P6.3.02 scheduler, streams per SM partition | Not started | Depends on a device to tune anything meaningful |
| P6.3.03 CPU and GPU overlap | Not started | Depends on a device to measure whether it helps |
| P6.2.02 SHA-1 kernel | Compression verified, `.cu` entry point not written | Same pattern as MD5, no blocker |
| P6.2.03 SHA-256 kernel | Compression verified, `.cu` entry point not written | Message schedule is more work than MD5 |
| P6.2.04 SHA-512 kernel | Compression verified, `.cu` entry point not written | 128 byte blocks, needs its own pad capacity |
| P6.2.05 NTLM kernel | MD4 compression verified, `.cu` entry point not written | UTF-16LE conversion has to happen host side |
| P6.2.06 bcrypt | Not started | EksBlowfish setup is substantial and cannot be checked without a device |
| P6.2.08 differential test on device | Host only | 10,000 random candidates per type on real hardware is the stated gate and has not been run |

### Why the host harness is not a substitute

Running the kernel bodies on the host executes the same C the GPU would execute
and checks the digest, the padding, the thread mapping and the bounds check. It
cannot observe:

- real parallel execution, so there is no concurrency, occupancy or latency
  behaviour to measure
- global memory coalescing, which is often the deciding factor in GPU hashing
  throughput
- register pressure or local memory spilling, both of which change performance
  without changing results
- anything nvcc would reject at compile time

A kernel that passes this harness and produces correct digests on a device could
still be slower than the CPU path. That is a real possibility and the reason the
P6.3.04 gate exists.

## Commands

```text
scripts/verify-gpu-kernels.sh                          # both stages, no toolkit needed
PW_CUDA_ALLOW_NO_NVCC=1 cargo test -p engine-cuda       # crate tests
cargo build -p engine-cuda                             # requires nvcc, fails loudly without it
```

## Next step for anyone with a device

1. Install the toolkit, build with `cargo build -p engine-cuda`, confirm nvcc
   produced `generated/md5.ptx` and that it starts with `.version`.
2. Write the device side differential test: 10,000 random candidates per hash
   type through the kernel, compared against the Rust reference. This is P6.2.08
   and it is the gate that has never been run.
3. Only then measure throughput, and only then compare against the CPU baseline.