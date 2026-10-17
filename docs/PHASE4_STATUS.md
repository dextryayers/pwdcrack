# Phase 4 Status: SIMD Engine

Scope: `docs/plan.md` section 8, tasks P4.1 through P4.4.
Last updated after the AVX2 MD5 kernel was brought to a correct state.

## Summary

The crate previously shipped 8-line stubs under `x86/` and `arm/` that each
called the scalar implementation while the module names and comments claimed
vectorised work. One real kernel now exists and is verified against the
reference implementation. The remaining tasks are listed honestly below with the
reason each one has not been done.

## Completed

### P4.1.01: 8 lane AVX2 MD5 kernel

`engines/engine-simd/src/x86/avx2_md5.rs`, 8 lanes of 32 bits, one message per
lane, 64 steps fully unrolled with literal shift immediates.

Four defects were found and fixed. All four were silent: the kernel returned a
full 16 byte digest that simply was not the digest of the input, and three of
the four left every single block message correct, which is why a short test did
not catch them.

| Defect | Symptom | Fix |
|--------|---------|-----|
| Word order for rounds 2, 3 and 4 computed as a formula instead of read from RFC 1321 appendix A.3 | Wrong digest for every input | Explicit per step word index, checked against the specification table |
| Blend mask polarity inverted | The compressed result was discarded and the pre-block state kept | Mask is now built per lane and `_mm256_blendv_epi8` is called with the carried state first |
| Feed forward added the initial vector on every block | Correct for one block, wrong for every later one | Adds the state the block started from, which is what MD5 chaining specifies |
| Word gather offset added `blk * 64` to an index that was already relative to block `blk` | Out of bounds panic for every message over 64 bytes | Offset is `w * 4` within the block |

A fifth defect was found by a test written after the above four were fixed: a
lane whose message finished at an earlier block had its own state added to
itself, doubling it. The feed forward addend is masked per lane now.

Round functions were checked against RFC 1321 and corrected once. `F(X,Y,Z)` is
`XY v not(X) Z`, where the complement applies to the first argument, which is
`b` in the `FF(a,b,c,d,...)` macro, not to the target register `a`. The first
version of this file complemented `a`.

### Padding

`pad_message` produces the fixed 64 byte blocks the kernel consumes, up to two
blocks or 119 bytes. A test asserts the `0x80` marker position, the zero fill
and the little endian bit length for every length from 0 to 119.

An earlier version searched for a block with room for the marker and skipped it
entirely when the message length was a multiple of 64, so every 64 byte
message produced a wrong digest.

### Differential tests

15 tests in `avx2_md5.rs`, 11 in `dispatch.rs`. Coverage includes:

- RFC 1321 appendix A.5 test suite for the scalar reference
- Padding for every length 0 through 119
- Batch equality against the scalar digest for every length 0 through 119
- Two block lengths specifically, since that is where the chaining defects hid
- A group where lanes finish at different blocks
- A group of eight two block messages
- Empty batches, ragged batches, mixed long and short batches, the fallback path
  for messages over 119 bytes

### Measured throughput

`cargo bench -p engine-simd --bench md5 --target-dir .build`, on the development
host, corpus of 16 byte passwords, 65536 hashes per measurement:

| Batch | scalar /s | avx2-multi8 /s | speedup |
|-------|-----------|----------------|---------|
| 8 | 4,151,824 | 9,406,469 | 2.27x |
| 64 | 4,171,504 | 9,759,685 | 2.34x |
| 512 | 4,199,506 | 9,854,919 | 2.35x |
| 4096 | 4,200,151 | 9,791,372 | 2.33x |
| 16384 | 4,195,574 | 9,463,241 | 2.26x |

The speedup is well below the 8x the lane count suggests. MD5 is 64 dependent
steps, and the round functions are two dependent operations each, so the
critical path is roughly 10 cycles per round. Eight lanes raise throughput to
about 2.3x rather than 8x because the gather and store overhead per block is
serial with the compression.

`md5_verify`, the single candidate entry point, still routes to scalar on
purpose. Handing a multi-buffer kernel one message fills one lane and costs
gather and store work for no benefit.

## Correctness fixes outside the kernel

### NTLM password encoding

`scalar_ntlm_verify` in `dispatch.rs` mapped each input **byte** to a `u16` to
build the UTF-16LE buffer NTLM requires. That agrees with UTF-16LE only while
every byte is ASCII, because an ASCII byte is its own code point. For a
multi-byte UTF-8 sequence it produced the wrong number of code units, so no
NTLM hash of a non-ASCII password could ever match. The password is now decoded
from UTF-8 and encoded with `str::encode_utf16`.

A test covers `é`, `café`, `naïve`, `日本語`, `🔑pass` and `Ωmega`, and another
test asserts that the old byte-to-`u16` mapping really does produce a different
digest for `é`, so the fix cannot silently regress.

Invalid UTF-8 now returns `false` rather than hashing a substituted
replacement character, which would produce a digest that looks valid and
matches nothing.

## Not done, and why

| Task | State | Reason |
|------|-------|--------|
| P4.1.02 AVX2 SHA-1 | Not started | Same structure as MD5, no blocker |
| P4.1.03 AVX2 NTLM | Not started | MD4 is structurally the easiest of the four, no blocker |
| P4.1.04 AVX2 SHA-256 | Not started | Message schedule is more work than MD5, no blocker |
| P4.1.05 AVX-512 16 lane | Not started | No blocker |
| P4.1.06 SSE2 SHA-1 | Not started | Four lanes, no blocker |
| P4.2 SHA-NI | Not implemented, documented as such | `x86/shani.rs` is now an honest pass through |
| P4.3 NEON and SVE | Not implemented, documented as such | `arm/neon64.rs` is now an honest pass through |
| P4.4.01 dispatch by `(HashType, CpuFeatures)` | Partial | `md5_batch_verify` reaches the AVX2 kernel; the other three still dispatch by hash name |
| P4.4.02 cached feature detection | Done | `detect.rs` runs once in `init()` and stores an `AtomicU8` |
| P4.4.03 log the selected kernel | Not started | Blocked on P2.3 logging |

### Why the SHA-NI and NEON files are not implemented

Both files previously carried this claim:

> `target_feature(enable = "sha")` tells the compiler to emit SHA-NI instructions
> for the scalar hash body.

That is false. The attribute declares that the caller guarantees the feature is
present, which is what allows intrinsics like `_mm_sha256rnds2_epu32` to
compile. It does not vectorise scalar code and does not introduce instructions
the source never mentions. A function that only calls into a digest library
keeps calling into that library whatever features are enabled.

Both files now state this, expose an `*_available()` predicate, and contain only
documented pass-throughs. The dispatch level check is kept so that adding real
kernels later needs no change at the call site.

## Verification commands

```text
cargo test -p engine-simd
cargo bench -p engine-simd --bench md5 --target-dir .build
```

The root crate suite is 97 tests and the SIMD crate is 26, all passing.

Note that `target/release` on this machine is root owned and not writable, so
release and bench builds need `--target-dir .build`.