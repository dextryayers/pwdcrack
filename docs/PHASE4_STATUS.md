# Phase 4 Status: SIMD Engine

Scope: `docs/plan.md` section 8, tasks P4.1 through P4.4.
Last updated after the AVX2 MD4/NTLM kernel and the attack loop integration.

## Summary

Two multi-buffer kernels now exist and the attack engine calls them:

| Kernel | File | State |
|--------|------|-------|
| MD5, 8 lanes | `engines/engine-simd/src/x86/avx2_md5.rs` | Verified against `md-5` for every length 0 through 200, measured 2.1x to 2.3x |
| MD4 and NTLM, 8 lanes | `engines/engine-simd/src/x86/avx2_md4.rs` | Verified against RFC 1320 and `md4` for every length 0 through 200, measured 1.76x to 1.82x |
| Padding, shared | `engines/engine-simd/src/x86/md_pad.rs` | Both kernels pad through this one module |

Before this round, the MD5 kernel existed but nothing in the attack path called
it: `engine-simd` was not in the default feature set, `HashCracker::verify_batch`
had no override anywhere, and the dictionary loop called `verify` once per
candidate. The kernel was correct and unreachable. That is now fixed:

- `engine-simd` is part of `tier-auto`, which is the default feature set.
- `Md5Hash`, `Md4Hash` and `NtlmHash` override `verify_batch` through
  `src/hash/simd.rs`, which returns `None` (and therefore the plain loop) when the
  host has no AVX2 or the hash type has no kernel.
- `src/attack/dictionary.rs` hands the cracker groups of 512 candidates in both
  the mmap path and the streaming path, for the raw candidates and for the
  rule-mangled ones.
- `--verbose` now names the kernels the host can run, and a debug line appears
  once per kernel when the batch route is first taken, so acceleration can be
  confirmed from outside the binary.

Measured end to end with release builds of the same source, the default build
against `--no-default-features`, on 2,000,000 candidates:

| Workload | Per candidate loop | Batch kernel | Ratio |
|----------|--------------------|--------------|-------|
| 1 MD5 target, 2M words (median of 3) | 0.69 s | 0.62 s | 1.11x |
| 1 NTLM target, 2M words (median of 3) | 0.77 s | 0.67 s | 1.15x |
| 64 MD5 targets, 2M words (median of 3) | 4.82 s | 3.06 s | 1.58x |
| 64 NTLM targets, 2M words (median of 3) | 7.60 s | 4.17 s | 1.82x |

The single target rows are close to 1x because a dictionary run over one hash is
bound by reading and decoding the wordlist, not by hashing. The 64 target rows are
where the hash work dominates, and there the kernel's contribution is visible.
The full numbers, including the spread between runs, are in "Measured
throughput" below.

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

### P4.1.03: 8 lane AVX2 MD4 kernel, which is also NTLM

`engines/engine-simd/src/x86/avx2_md4.rs`. MD4 is three rounds of sixteen steps,
and its round functions are a select, a three way majority and a three way XOR,
so the kernel serves MD4 and NTLM from one compression function. NTLM is MD4 over
the password encoded as UTF-16LE: `ntlm_encode` produces that byte string and the
same kernel hashes it.

The step macro writes to the register named at the call site and the F argument
order is spelled out per line, so each of the 48 lines can be read against RFC
1320 section 3.4 directly. The three round constants and the word orders live in
the source with the specification's values, not in a table computed at run time.

Details that are easy to get wrong and are covered by tests:

- Round 2 reads word columns 0, 1, 2, 3 with a stride of four; round 3 reads
  0 8 4 12, then 2 10 6 14, then 1 9 5 13, then 3 11 7 15. Round 3 swaps its
  middle two offsets relative to round 2.
- MD4 uses the same initial vector and padding as MD5, which is why `md_pad.rs` is
  shared, but its output is four little endian words, so a straight word store is
  the wire format.
- UTF-8 input is decoded and re-encoded with `str::encode_utf16`. Mapping input
  bytes to code units agrees with UTF-16LE only while every byte is ASCII.
- Input that is not valid UTF-8 is reported as a mismatch instead of being hashed
  with replacement characters, which would produce a digest that looks valid and
  matches nothing. An invalid candidate in the middle of a batch keeps its
  position, so the lanes after it do not shift.
- UTF-16LE doubles the byte length, so a candidate of 60 bytes or more falls
  outside the two block window and is hashed scalar. That is documented rather
  than silently approximated.

Two NTLM defects were found by measurement, not by inspection. The first version
allocated one `Vec<u8>` per candidate for the encoding and one `String` per lane
for the hex comparison. It ran at 0.65x the scalar path: slower than doing
nothing. Encoding into a single arena and comparing into a stack buffer fixed
that to 1.17x to 1.36x. The second version then measured 0.96x when the caller
handed it one group of 16384 candidates, because the encode arena no longer fit
in L2; chunking at 512 candidates and reusing the arena fixed that, and the
figure is 1.39x to 1.47x at every total input size measured. Both regressions
were invisible without running the benchmark, which is why the benchmark exists.

### P4.1.07: Shared padding

`engines/engine-simd/src/x86/md_pad.rs` holds `block_count` and `pad_message`,
used by both kernels. Padding is where the recorded MD5 defects lived: a skipped
terminator when the length was an exact multiple of 64, a bit length written to
the wrong block, and a message accepted past the two block window. A second copy
for MD4 would be a second chance at each of those.

Tests cover the 55/56 and 119/120 length boundaries, the terminator position for a
64 byte message, the little endian bit length for a 60 byte message (480 bits),
and the refusal of a 120 byte message.

### P4.1.08: 10,000 random inputs

`x86::tests::ten_thousand_random_messages_agree_with_the_scalar_reference` in
`engines/engine-simd/src/x86/mod.rs`. A fixed seed xorshift generator produces
10,000 messages of length 0 through 200 with arbitrary bytes, including NUL and
high bytes, and every lane of both kernels is compared against the digest crate.
Lengths above 119 take the scalar fallback by design, so those cases pin the
boundary rather than the vector path.

### Differential and boundary tests

55 tests in `engine-simd`. Coverage includes:

- RFC 1321 appendix A.5 and RFC 1320 appendix A.5 test suites for the scalar
  references
- RFC 1320 A.5 through the vector kernel
- Every length 0 through 200 for both kernels against the digest crates
- Two block lengths specifically, since that is where the chaining defects hid
- A group where lanes finish at different blocks
- A group of eight two block messages
- Empty batches, ragged batches, mixed long and short batches, the fallback path
  for messages over 119 bytes
- A direct call to `md4_multi8` and `md5_multi8` that fails if the kernel returns
  a wrong digest, so the differential tests cannot pass vacuously by falling back
  to scalar on a host that reports AVX2
- NTLM: multi-byte UTF-8, invalid UTF-8 in the middle of a batch, every candidate
  length from 1 to 60 against the scalar verifier, uppercase hex targets, and the
  single target entry points against the paired ones

## Attack loop integration

`src/attack/dictionary.rs` now verifies candidates in groups:

- `VERIFY_GROUP` is 512, the size at which the NTLM kernel was measured at its
  best (1.39x) and at which the fixed cost of a batched call is amortised.
- The mmap path keeps zero copy line slices and hands `&[&[u8]]` groups to
  `WordBatch::verify_lines`, which decodes them and batches per target.
- The streaming path reads `STREAM_BLOCK` (8192) lines, then splits the block into
  groups and processes them in parallel. It previously used `par_bridge` straight
  from the line iterator, which hands one line to one worker, so there was no
  group to give a batch verifier at all.
- Rules: every rule's output for the whole group is collected and verified as one
  batch per target. The candidate strings are the same strings the per candidate
  loop would have produced.
- Progress accounting is preserved: the bar advances by
  `words * (1 + rule_count)`, the line counter by `words`, and the rate line now
  prints when the count crosses a multiple of 10000 instead of testing for an
  exact multiple, which grouping would have skipped entirely.
- Matched results are pushed with the same `CrackResult` shape and order within a
  group. `cracked_count` is still incremented for raw matches only, as before.

### Two silent defects found while integrating

1. Routing the batch path through the detected level made it depend on
   `engine_simd::init()` having run. The dashboard, the C ABI, the language
   bindings and the tests never call `init()`, so every one of them would have
   silently received the scalar path while the code looked accelerated. The gate
   is now the runtime feature check, which needs no setup.
2. The default build did not compile at all. `cluster_only` and
   `run_cluster_and_report` exist only with `engine-distributed`, but the
   `if cluster_only` block in `src/main.rs` was not gated by that feature, so a
   plain `cargo build` failed with three `E0425` errors. The block is now behind
   `#[cfg(feature = "engine-distributed")]`.

## Measured throughput

Host: AMD Ryzen 7 5700U (Zen 2, Lucienne), 16 hardware threads, rustc 1.85.1.
Corpus for the kernel benchmarks: 16 byte passwords, 65536 hashes per
measurement, `cargo bench --target-dir .build` (the release directory is root
owned on this machine).

### Kernel level, `--bench md5`

| Batch | scalar /s | avx2-multi8 /s | speedup |
|-------|-----------|----------------|---------|
| 8 | 4,125,237 | 9,237,341 | 2.24x |
| 64 | 4,168,483 | 8,791,481 | 2.11x |
| 512 | 4,159,893 | 9,575,884 | 2.30x |
| 4096 | 4,161,497 | 9,025,917 | 2.17x |
| 16384 | 4,191,807 | 9,183,891 | 2.19x |

### Kernel level, `--bench md4`

| Kernel | Batch | scalar /s | vector /s | speedup |
|--------|-------|-----------|-----------|---------|
| md4 | 8 | 5,651,094 | 10,134,031 | 1.79x |
| md4 | 64 | 5,790,157 | 10,165,184 | 1.76x |
| md4 | 512 | 5,828,540 | 10,607,785 | 1.82x |
| md4 | 4096 | 5,810,418 | 10,481,381 | 1.80x |
| md4 | 16384 | 5,944,022 | 9,260,180 | 1.56x |
| ntlm | 8 | 4,016,291 | 3,645,046 | 0.91x |
| ntlm | 64 | 4,029,854 | 5,279,038 | 1.31x |
| ntlm | 512 | 4,012,592 | 5,579,494 | 1.39x |
| ntlm | 4096 | 4,095,980 | 5,811,916 | 1.42x |
| ntlm | 16384 | 4,072,595 | 5,986,325 | 1.47x |

The NTLM row at a batch of eight is below 1x and stays that way: 8 candidates is
one kernel group, and the arena setup and the digest vector are not paid for by
one group. This is why `VERIFY_GROUP` is 512 and not 8.

The speedup is well below the 8x the lane count suggests. MD5 is 64 dependent
steps and MD4 is 48, the round functions are dependent operations themselves, so
the critical path per step is several cycles. Eight lanes raise throughput to
about 2.2x for MD5 and 1.8x for MD4 rather than 8x because the gather, the state
feed forward and the store per block are serial with the compression.

`md5_verify`, `md4_verify` and `ntlm_verify`, the single candidate entry points,
still route to scalar on purpose. Handing a multi-buffer kernel one message fills
one lane and costs gather and store work for no benefit.

### End to end

Two release binaries of the same source:

- `pwdcrack-simd`: default features, which now include `engine-simd`.
- `pwdcrack-plain`: `--no-default-features`, which is the same code with the
  batch route compiled out.

Corpus: 2,000,000 words of 11 bytes (`word0000000` through `word1999999`,
24 MB). Neither target appears in the wordlist, so both builds verify every
candidate against every target. Three runs per row, medians reported.

| Workload | plain | simd | ratio |
|----------|-------|------|-------|
| 1 MD5 target | 0.68, 0.69, 0.69 (median 0.69) | 0.58, 0.62, 0.65 (median 0.62) | 1.11x |
| 1 NTLM target | 0.76, 0.77, 0.82 (median 0.77) | 0.63, 0.67, 0.69 (median 0.67) | 1.15x |
| 64 MD5 targets | 4.62, 4.82, 5.84 (median 4.82) | 2.94, 3.06, 3.44 (median 3.06) | 1.58x |
| 64 NTLM targets | 7.52, 7.60, 8.51 (median 7.60) | 3.91, 4.17, 6.21 (median 4.17) | 1.82x |

An earlier measurement round of the 64 target rows, before the debug line was
added and on an otherwise idle machine, gave 5.83 s to 2.86 s for MD5 (2.04x) and
7.20 s to 3.86 s for NTLM (1.87x). The spread across runs is real, so the honest
statement is 1.6x to 2.0x for MD5 and about 1.8x for NTLM at 64 targets, not the
best single number.

### Correctness at that scale

The same binaries were run against 201 targets: 200 absent from the wordlist plus
one whose plaintext is the last word. Both builds, for both MD5 and NTLM,
recovered exactly one target:

```text
3253d20888c4a8b08eb3302d157f7957  ->  word1999999  [Md5Hash]
597a881b482067c490ba4682f60db08e  ->  word1999999  [NTLM]
```

Both digests were confirmed independently with
`openssl dgst -md5` and `openssl dgst -md4 -provider legacy` over the UTF-16LE
encoding.

### What the numbers do not say

- A dictionary run against one target is bound by reading and decoding the
  wordlist, measured at about 3 million lines per second in the streaming path.
  The kernel cannot fix that: the streaming path allocates one `String` per line
  (`BufRead::lines`) and another for the block copy. Fixing that is an I/O change,
  not a kernel change, and it is not done.
- The kernel gains do not appear for hash types without a kernel. SHA-1, SHA-256,
  SHA-512, bcrypt, the Unix crypt family and the rest still verify one candidate
  at a time.

## Not done, and why

| Task | State | Reason |
|------|-------|--------|
| P4.1.02 AVX2 SHA-1 | Not started | No blocker; a real kernel needs the 80 step schedule unrolled, not a wrapper |
| P4.1.04 AVX2 SHA-256 | Not started | No blocker; the message schedule is more work than MD5 |
| P4.1.05 AVX-512 16 lane | Not started | No blocker; this host has no AVX-512, so it could not be executed, only compiled |
| P4.1.06 SSE2 SHA-1 | Not started | No blocker |
| P4.2.01 to P4.2.04 SHA-NI | Not implemented, documented as such | `x86/shani.rs` is an honest pass through |
| P4.3.01 to P4.3.04 NEON and SVE | Not implemented, documented as such | `arm/neon64.rs` is an honest pass through; no aarch64 hardware here |
| P4.4.01 dispatch keyed by `(HashType, CpuFeatures)` | Partial | `src/hash/simd.rs` maps a hash type to a kernel; the feature half is a capability check in the same function, not a table |

### Why the SHA-NI and NEON files are not implemented

Both files previously carried this claim:

> `target_feature(enable = "sha")` tells the compiler to emit SHA-NI instructions
> for the scalar hash body.

That is false. The attribute declares that the caller guarantees the feature is
present, which is what allows intrinsics like `_mm_sha256rnds2_epu32` to compile.
It does not vectorise scalar code and does not introduce instructions the source
never mentions. A function that only calls into a digest library keeps calling
into that library whatever features are enabled.

Both files now state this, expose an `*_available()` predicate, and contain only
documented pass-throughs. The dispatch level check is kept so that adding real
kernels later needs no change at the call site.

## Verification commands

```text
cargo test -p engine-simd
cargo test
cargo bench -p engine-simd --bench md5 --target-dir .build
cargo bench -p engine-simd --bench md4 --target-dir .build
```

The root crate suite is 111 tests and the SIMD crate is 55, all passing.

The end to end comparison in this document was produced with:

```text
cargo build --release --target-dir .build
cp .build/release/pwdcrack /tmp/opencode/simdbench/pwdcrack-simd
cargo build --release --no-default-features --target-dir .build
cp .build/release/pwdcrack /tmp/opencode/simdbench/pwdcrack-plain
/usr/bin/time -f "%e" ./pwdcrack-simd dictionary many64.md5 words.txt
```

Note that `target/release` on this machine is root owned and not writable, so
release and bench builds need `--target-dir .build`.
