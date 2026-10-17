# pwdcrack Total Performance Upgrade Plan

**Document ID**: PWDC-PLAN-001
**Version**: 1.0
**Date**: 2026-10-17
**Scope**: Full-stack performance, correctness, and coverage upgrade for pwdcrack v1.2.0 -> v2.0.0
**Stack in scope**: Rust (core, CLI, engines), WGSL (GPU compute), CUDA/PTX, OpenCL C, Metal Shading Language, SystemVerilog RTL (FPGA), Cranelift JIT, Web (axum/JS), C/Python/Node/Perl bridges
**Language policy**: English for all documentation, code comments, CLI text, and identifiers

---

## 0. Document Conventions

### 0.1 Terminology

| Term | Meaning |
|------|---------|
| Core | The `src/` crate that contains hash verification and attack logic |
| Engine | A crate under `engines/` that offloads or accelerates computation |
| Tier | Build profile class: `tier-low`, `tier-mid`, `tier-high`, `tier-auto` |
| Detection | Classifying an unknown hash string into a `HashType` |
| Verification | Testing whether a candidate password produces a given hash |
| Detection-only | A `HashCracker` whose `verify()` always returns `false` |
| H/s | Hashes per second, the universal throughput metric |
| p/s | Passwords per second for candidate generation phases |

### 0.2 Writing Rules

1. No em dashes. Use colons, hyphens, or parentheses instead.
2. No filler adjectives. Every task line must name a file, a symbol, or a measurable number.
3. Every phase must state an acceptance gate that can be verified by a command in the repository.
4. Task identifiers use the form `P<phase>.<subphase>.<nn>`, for example `P4.2.07`.

### 0.3 How to Read This Document

Phases are ordered by dependency. A phase cannot start until the acceptance gate of the previous phase passes. Phases 0 through 3 are mandatory for every build. Phases 4 through 11 are feature gated and can be scheduled independently once Phase 3 is green.

---

## 1. Baseline Audit

The following findings were verified by reading the source. They define the starting point. Every finding receives a task in this plan.

### 1.1 Correctness Defects (Severity: Critical)

| ID | Location | Defect | Impact |
|----|----------|--------|--------|
| B-01 | `src/hash/unix.rs` lines 46, 57, 183, 194, 345, 356 | Loop decrement uses `i.wrapping_sub(BLOCK)` instead of saturating subtraction. Any password whose length is not a multiple of the block size wraps the counter to near `usize::MAX` and the loop never terminates. | `$1$` md5crypt, `$5$` sha256crypt, `$6$` sha512crypt verification hangs for most real passwords. Blocks any dictionary or brute-force run against these three types. |
| B-02 | `src/hash/mod.rs` line 1266 | `constant_time_eq_ignore_case` performs a constant time XOR comparison over raw bytes without folding case. | Callers that expect case insensitive hex comparison get false negatives. Currently unused, so it is a latent trap. |
| B-03 | `src/hash/detector.rs` | Many `can_parse` implementations accept any string of a given length. Examples: `SnmpHash` accepts any 4 to 32 character string, `HmacStreebog256Hash` accepts any 64 character hex string, `CiscoType7Hash` gates on length while its `parse` enforces a different charset. | The detector takes the first parser that returns `can_parse` then `parse` succeeds. Ambiguous lengths such as 32 hex characters resolve by registration order, not by evidence. Misidentification is silent. |
| B-04 | `src/hash/app.rs`, `src/hash/raw_ext.rs`, `src/hash/raw.rs` | 110 of 354 declared hash types are detection-only. Their `verify()` is hardcoded to `false`. | The CLI advertises 354 types. Roughly 31 percent of them can be identified but never cracked. |
| B-05 | `src/main.rs` line 794 | `generate_test_hash` returns the plaintext as its own hash when the requested algorithm has no implementation. | `pwdcrack hash` prints `password:password` and gives the user a false artifact. |

### 1.2 Build Defects (Severity: Critical)

| ID | Location | Defect | Impact |
|----|----------|--------|--------|
| B-06 | `src/main.rs` line 13 | `fn init_verbose_engines(_args: &Cli)` references `args.gpu`, `args.power_budget`, `args.battery_safe`, `args.distributed` inside `cfg` blocks. | Any build enabling `engine-gpu`, `engine-power`, or `engine-distributed` fails to compile. `tier-high` is therefore unbuildable. |
| B-07 | `src/main.rs` lines 46, 52, 58 | Calls `engine_tpu::device::probe()`, `engine_riscv::vector::probe()`, `engine_metal::device::probe()`. No function named `probe` exists in any engine crate. | Builds enabling `engine-tpu`, `engine-riscv`, or `engine-metal` fail to compile. |
| B-08 | `src/attack/combinator.rs` lines 121 and 126 | `let _tested = ...` is bound, then `progress.record_tested(tested)` uses an undefined name. | Builds enabling `progress-rich` fail to compile. `tier-mid` and `tier-high` are unbuildable. |
| B-09 | `engines/engine-bridge/src/python.rs` | File is 101 bytes: a doc comment and `use std::sync` with no body. | `engine-bridge` with the `python` feature fails to compile. |
| B-10 | `engines/engine-bridge/perl/Makefile.PL` | References `pwdcrack.xs` which does not exist in the repository. | Perl bridge packaging is broken. |
| B-11 | `engines/engine-cuda/src/device.rs` | Uses a `CudaResult::Ok(())` pattern under `cudarc::driver::result::result` that does not exist in the pinned cudarc version. | `engine-cuda` is likely unbuildable. |
| B-12 | `src/cli/args.rs` | Global short flag `-r` on `--rules-file` collides with the local short flag `-r` on `Dictionary.rules` and `Rules.rules_file`. | Debug builds panic at startup inside clap's debug assertions: `Short option names must be unique for each argument, but '-r' is in use by both 'rules' and 'rules_file'`. Every clap debug assertion run fails. |

### 1.3 Engine Fidelity Defects (Severity: High)

| ID | Location | Defect | Impact |
|----|----------|--------|--------|
| B-13 | `engines/engine-simd/src/x86/shani.rs` | Comment states actual SHA-NI intrinsics are not implemented; the function calls the scalar path. | Advertised SHA-NI acceleration does not exist. `simd-sse2.rs`, `avx2.rs`, `avx512.rs`, `arm/neon32.rs`, `neon64.rs`, `sve.rs` are similar wrappers. |
| B-14 | `engines/engine-gpu/src/lib.rs` | Thirty WGSL files exist on disk. Eight are loaded and bound to pipelines. | Twenty-two shaders are dead files. |
| B-15 | `engines/engine-gpu/src/device.rs` | Adapter VRAM is hardcoded by device class as 8192, 512, or 128 MB. | Batch size selection uses fabricated memory figures. |
| B-16 | `engines/engine-cuda/src/kernels/md5.cu` | Loads words with little endian indexing on a host endian buffer and uses a single round constant `0x5A827999` for all rounds. This is not MD5. | The CUDA kernel cannot produce correct hashes even if it were launched. `crack_md5` currently returns `Err(NoCudaSupport)` unconditionally. |
| B-17 | `engines/engine-opencl/src/kernels/md5.cl` | Same structural defect as B-16. `crack_md5` returns `Err(NotEnabled)` unconditionally. | OpenCL engine performs no work. |
| B-18 | `engines/engine-metal/src/device.rs` | On non macOS hosts it fabricates Apple GPU entries or reads `/tmp/metal_devices.txt`. | Device detection reports hardware that is not present. |
| B-19 | `engines/engine-tensor/src/lib.rs`, `engines/engine-warp/src/lib.rs` | `is_available()` returns `true` unconditionally. | Capability reporting lies to the scheduler. |
| B-20 | `engines/engine-sycl/src/device.rs` | Returns `None` with a log message stating the runtime is unavailable. | SYCL engine is a stub. |
| B-21 | `engines/engine-jit/src/rule_compiler.rs` | Rule compilation is a TODO. The engine falls back to an interpreter stored in a leaked static. | No speedup over interpreted rules. |
| B-22 | `engines/engine-bridge/src/c_api.rs` | `crack_detect_tier()` returns the literal `"Auto"`. `crack_hashes_per_second()` returns `0.0`. | C consumers receive placeholder data. |
| B-23 | `engines/engine-dsp`, `engine-tpu`, `engine-xpu`, `engine-riscv`, `engine-zen`, `engine-embedded`, `engine-hybrid` | Detect or simulate a device, then run scalar CPU MD5 or SHA loops. | Reported acceleration is zero. |

### 1.4 Functional Gaps (Severity: High)

| ID | Location | Defect | Impact |
|----|----------|--------|--------|
| B-24 | `src/main.rs` handlers for `dictionary`, `brute-force`, `combinator`, `prince`, `toggle-case`, `substitute`, `rules` | `--limit` and `--session` are declared on the CLI, received by the handler, bound to names prefixed with `_`, and never used. | Users cannot bound a run or resume it. |
| B-25 | repository wide | `--resume` is declared in `src/cli/args.rs` and referenced nowhere in `src/`. | Flag is a no-op. |
| B-26 | `src/main.rs` `brute-force` handler | `--min-length` and `--max-length` are received and discarded. | Brute-force cannot restrict length ranges. |
| B-27 | `src/attack/mod.rs` lines 95 to 97 | `ProgressStats::cracked()` returns `0` unconditionally. | Progress UI reports zero cracks during a run. |
| B-28 | `configs/pwdcrack.{low,mid,high,android}.toml` | No code reads these files. The `toml` crate is not a dependency and there is no `include_str!`. | Four documented presets do nothing. |
| B-29 | `src/main.rs` lines 90, 1804 and 12 other sites | Runtime output strings contain em dashes. `cmd_suggest` line 1804 contains the CJK text `季节`. | Inconsistent typography and a stray non English token in user facing output. |

### 1.5 Security Defects (Severity: High)

| ID | Location | Defect | Impact |
|----|----------|--------|--------|
| B-30 | `engines/engine-web/src/lib.rs` | `WebConfig::default()` sets `host: 0.0.0.0` and `auth_token: None`. Routes can start, stop, pause, and reconfigure work. | Control plane is exposed on every interface with no authentication. |
| B-31 | `engines/engine-distributed/src/lib.rs` | `DistributedConfig::default()` binds `0.0.0.0:5555`. The protocol is length prefixed JSON over raw TCP with no authentication, no encryption, and no peer verification. | Any host that can reach the port can join a cluster or impersonate a master. |
| B-32 | `engines/engine-distributed` master work units | `WorkUnit::Dictionary` carries a `wordlist_path` chosen by the master. A worker opens the path it is given. | A malicious master can make a worker read arbitrary files. |
| B-33 | `engines/engine-power/src/governor.rs`, `cstate.rs` | Writes to `/sys/devices/system/cpu` without checking privileges or recording previous state. | Running as root silently changes governor and C-state settings with no restore path. |
| B-34 | `install.sh` | Writes a log to the predictable path `/tmp/pwdcrack_install.log`. | Symlink attack surface on multi user hosts. |
| B-35 | `wordlists/download.sh` | Downloads large archives with no checksum or signature verification. | Supply chain exposure. |
| B-36 | `Cargo.toml` release profile | `panic = "abort"` applies to the `cdylib` target. | A panic inside the C ABI aborts the host process instead of unwinding into an error. |

### 1.6 Engineering Defects (Severity: Medium)

| ID | Location | Defect | Impact |
|----|----------|--------|--------|
| B-37 | `README.md` | Contains the single line `# pwdcrack`. | No onboarding documentation. |
| B-38 | `ARCHITECTURE.md` | 2,377 lines describing files and behaviours that do not exist, including `engine-gpu/build.rs`, `common/pipeline.sv`, `sim/` testbenches, and a power `scheduler.rs`. Mixed with non English prose. | Document is aspirational and misleading. |
| B-39 | `src/util/mod.rs` | Zero bytes and not declared in `src/lib.rs`. | Dead directory. |
| B-40 | `p.txt`, `p.txx` | Sample hash files at repository root. | Repository hygiene. |
| B-41 | `.gitignore` | Ignores `Cargo.lock` while `Cargo.lock` is committed. Binary crate policy should be stated explicitly. | Ambiguous policy. |
| B-42 | `scripts/package.sh` | Copies a `rules/` directory that does not exist and copies `libcrack-core.so` while the library target is named `pwdcrack`. | Packaging produces an incomplete or misnamed artifact. |
| B-43 | `tests/` and `src/tests.rs` | 22 unit tests cover hash detection and verification only. No test exercises an attack, a rule application, a mask expansion, or an engine dispatch. | Core attack logic is untested. |
| B-44 | `src/main.rs` | `env_logger::init()` is called before argument parsing and no default filter is set. `--verbose` does not change log level. | Logging requires `RUST_LOG` to produce output. |
| B-45 | `src/hash/detector.rs` | `Detector::new()` allocates roughly 702 boxed cracker instances. Every parse call iterates the full vector. | Detection is allocation heavy and linear. |

---

## 2. Objectives and Success Metrics

### 2.1 Primary Objectives

| ID | Objective | Measurement |
|----|-----------|-------------|
| O-01 | Every advertised hash type is verifiable or is explicitly labelled as detection-only in `pwdcrack list` | `cargo test --test coverage_matrix` passes with zero unlabelled entries |
| O-02 | Zero hangs, zero infinite loops, zero panics on valid input | Fuzz target `fuzz/targets/verify_any.rs` runs 10 million iterations with no timeout |
| O-03 | Detection identifies the correct type for 100 percent of a curated corpus | `cargo test --test detection_matrix` passes on 3,000 labelled hashes |
| O-04 | Feature gated builds all compile | CI matrix of 26 feature combinations completes with exit code 0 |
| O-05 | Each engine reports truthful capability and throughput | Every `Engine::info()` reports measured values, never literals |
| O-06 | Attack throughput improvement per target | See the per engine targets in Phase 4 through Phase 11 |
| O-07 | No em dashes, no filler prose, English only | `cargo run -- check --help-text` exits 0; repository grep for U+2014 returns nothing |
| O-08 | Honest documentation | `README.md` and `ARCHITECTURE.md` describe only code that exists |

### 2.2 Throughput Targets

Baseline is measured on the reference machine defined in Section 12.1. Every target is a minimum.

| Workload | Current | Target |
|----------|---------|--------|
| MD5 verify, 1 thread | baseline x 1.0 | x 4.0 with AVX2 multi-buffer, x 8.0 with AVX-512 multi-buffer |
| SHA-1 verify, 1 thread | baseline x 1.0 | x 3.0 with SSE2 multi-buffer, x 2.5 additional with SHA-NI |
| SHA-256 verify, 1 thread | baseline x 1.0 | x 3.0 with SHA-NI on capable hosts, x 2.0 with AVX2 multi-buffer otherwise |
| NTLM verify, 1 thread | baseline x 1.0 | x 5.0 with AVX2 multi-buffer |
| bcrypt, cost 5 | baseline x 1.0 | x 1.2 via early exit on first byte mismatch, verified to preserve correctness |
| MD5 verify on discrete GPU | not functional | x 20.0 relative to 8 core CPU |
| SHA-256 verify on discrete GPU | not functional | x 25.0 relative to 8 core CPU |
| MD5 verify on FPGA | not functional | x 50.0 relative to 8 core CPU |
| Dictionary candidate generation | baseline x 1.0 | x 1.5 via rule engine batching and lock free accounting |

### 2.3 Correctness Targets

| ID | Metric | Threshold |
|----|--------|-----------|
| M-01 | False positive verification | 0 across the full test vector corpus |
| M-02 | False negative verification on known vectors | 0 across the full test vector corpus |
| M-03 | Misdetection rate on ambiguous length corpus | 0 percent, enforced by O-03 |
| M-04 | Rule engine output equality | Byte identical with the reference interpreter for every rule in `tests/rules/` |
| M-05 | Mask expansion ordering | Byte identical with the reference implementation for all masks up to keyspace 10^7 |
| M-06 | Constant time comparison | No early return on first differing byte, verified by timing test |

---

## 3. Target Architecture

### 3.1 Layer Diagram

```
+------------------------------------------------------------------+
|  Presentation: src/main.rs, src/cli/                              |
|  Command routing, output formatting, exit codes                   |
+------------------------------------------------------------------+
|  Attack orchestration: src/attack/                                |
|  Candidate generation, verification dispatch, session state       |
+------------------------------------------------------------------+
|  Verification core: src/hash/                                     |
|  Detection, parsing, HashCracker implementations                 |
+------------------------------------------------------------------+
|  Engine abstraction: src/engine/ (NEW)                            |
|  Uniform trait, capability report, work splitting, result merge   |
+------------+------------+------------+------------+-----------------+
|            |            |            |            |                 |
|         engine-simd  engine-gpu  engine-cuda   engine-fpga    engine-distributed
|         AVX2/SHA-NI  WGSL      PTX/CUBIN   SystemVerilog  TCP cluster
|            |            |            |            |
|         engine-opencl engine-metal engine-vulkan engine-tpu/xpu/zen/riscv
+------------------------------------------------------------------+
|  Platform services: src/platform/ (NEW)                           |
|  Power, thermal, battery, file IO, huge pages                     |
+------------------------------------------------------------------+
```

### 3.2 New Core Modules

| Module | Path | Responsibility |
|--------|------|----------------|
| Engine trait | `src/engine/mod.rs` | `Engine` trait with `info`, `capacity`, `verify_batch`, `is_available` |
| Work planner | `src/engine/planner.rs` | Splits a candidate keyspace into engine sized chunks |
| Result merger | `src/engine/merge.rs` | Dedupes and orders results from parallel engines |
| Capability report | `src/engine/capability.rs` | Typed capability struct replacing ad hoc `is_available()` |
| Session state | `src/attack/session.rs` | Checkpoint format for `--session` and `--resume` |
| Reference impls | `src/hash/reference/` | Golden implementations used by differential tests |
| Test vectors | `tests/vectors/` | Labelled corpus per hash type |

---

## 4. Phase 0: Foundation and Build Integrity

**Objective**: make every feature combination compile, make the repository honest, and establish measurement infrastructure. No phase after this one may start until the gate passes.

### 4.1 P0.1 Fix Build Blockers

| Task | Action | File |
|------|--------|------|
| P0.1.01 | Rename the parameter to `args` and keep the existing body. | `src/main.rs:13` |
| P0.1.02 | Add a real `probe()` to each engine or remove the call. Prefer adding: return `Option<DeviceInfo>` describing the detected device. | `engines/engine-tpu/src/device.rs`, `engines/engine-riscv/src/vector.rs`, `engines/engine-metal/src/device.rs` |
| P0.1.03 | Rename the bound variable to `tested` and drop the underscore, or use `_tested` at the call site. Prefer `tested`. | `src/attack/combinator.rs:121,126` |
| P0.1.04 | Write a complete PyO3 module or delete `python.rs` and the `python` feature from `Cargo.toml`. Prefer writing the module. | `engines/engine-bridge/src/python.rs`, `engines/engine-bridge/Cargo.toml` |
| P0.1.05 | Write `pwdcrack.xs` or remove the Perl `Makefile.PL`. | `engines/engine-bridge/perl/` |
| P0.1.06 | Replace the `CudaResult::Ok(())` construct with the cudarc pinned version API and verify against the crate docs. | `engines/engine-cuda/src/device.rs` |
| P0.1.07 | Resolve the short flag collision. Preferred solution: move the global rules file flag to long only, `-r` becomes `--rules-file` with no short form. This preserves every documented invocation that uses the long form and removes the panic. Update `src/main.rs` handler bindings that read `rules_file` from a short flag. | `src/cli/args.rs`, `src/main.rs` |
| P0.1.08 | Write the complete Python PyO3 surface: `Cracker`, `Detector`, `HashType`, plus the four free functions documented in `python/__init__.py`. | `engines/engine-bridge/src/python.rs` |

### 4.2 P0.2 Build Matrix

| Task | Action |
|------|--------|
| P0.2.01 | Add `.github/workflows/build-matrix.yml` with 26 jobs: default, each tier, each engine feature alone, and the three engine combinations used by `tier-high`. |
| P0.2.02 | Add a `just`-style `scripts/test-matrix.sh` that mirrors the CI matrix for local use. |
| P0.2.03 | Add `cargo hack`-free feature enumeration using a checked in `Cargo.toml` feature list, so the matrix cannot drift. |
| P0.2.04 | Gate: `scripts/test-matrix.sh` exits 0 for all 26 combinations. |

### 4.3 P0.3 Documentation Honesty

| Task | Action | File |
|------|--------|------|
| P0.3.01 | Write a real `README.md`: what the tool does, install, 5 worked examples, supported platforms, security notice, link to `docs/plan.md`. | `README.md` |
| P0.3.02 | Rewrite `ARCHITECTURE.md` to describe only files that exist. Mark aspirational sections explicitly as design notes, never as current state. | `ARCHITECTURE.md` |
| P0.3.03 | Delete `p.txt`, `p.txx`, and `src/util/mod.rs`. | repository |
| P0.3.04 | Remove `Cargo.lock` from `.gitignore` or delete the committed copy. Binary crates should commit the lock file. Choose commit and remove the ignore line. | `.gitignore` |
| P0.3.05 | Fix `scripts/package.sh`: copy `rules/` only if present, and use the correct library name `libpwdcrack.so`. | `scripts/package.sh` |
| P0.3.06 | Replace all 13 em dashes in `src/main.rs` runtime strings and remove the `季节` token. Convert em dashes to colons or hyphens. | `src/main.rs` |
| P0.3.07 | Gate: `grep -rn $'\u2014' src/ engines/ docs/ README.md` returns nothing. |

### 4.4 P0.4 Measurement Infrastructure

| Task | Action | File |
|------|--------|------|
| P0.4.01 | Define the reference machine: CPU model, core count, RAM, GPU model, driver version, OS. Record it in `docs/BENCH_REFERENCE.md`. | `docs/BENCH_REFERENCE.md` (NEW) |
| P0.4.02 | Write a benchmark harness that reports H/s per engine with warmup, fixed iteration count, and median of 5 runs. Reject results with variance above 5 percent. | `benches/hash_bench.rs` (extend), `src/bin/pwdcrack-bench.rs` (NEW) |
| P0.4.03 | Emit machine readable results as JSON for CI regression gating. | `benches/` |
| P0.4.04 | Gate: `cargo bench --bench hash_bench` completes and writes `target/bench.json`. |

---

## 5. Phase 1: Hash Correctness and Accuracy

**Objective**: eliminate every path that can produce a wrong answer, a hang, or a silent misidentification. This phase raises precision.

### 5.1 P1.1 Fix the Unix Crypt Hang (B-01)

| Task | Action |
|------|--------|
| P1.1.01 | Replace the six `wrapping_sub` decrements with `saturating_sub` and rewrite the loops to mirror the reference algorithm exactly: `for i in (1..=len).rev().step_by(BLOCK) { ctx.update(&digest1[..i.min(BLOCK)]); }`. |
| P1.1.02 | Verify against `openssl passwd -1`, `openssl passwd -5`, `openssl passwd -6` for 200 generated passwords of length 1 through 200, covering empty, single byte, exact block multiples, and every offset around block boundaries. |
| P1.1.03 | Add a regression test that asserts `verify` returns within 100 ms for a 5 character password, which would hang under the old code. |
| P1.1.04 | Files: `src/hash/unix.rs`. |

### 5.2 P1.2 Replace Detection Only Crackers (B-04)

The 110 detection-only crackers must be handled in one of three ways, and the choice must be recorded in `docs/HASH_SUPPORT.md`.

| Task | Action |
|------|--------|
| P1.2.01 | Generate the exact inventory: a script that parses `src/hash/{raw,raw_ext,app}.rs` and lists every struct whose `verify` body is `false`. Output committed to `docs/HASH_SUPPORT.md`. |
| P1.2.02 | Classify each type into: implementable with an existing RustCrypto crate, implementable with a new dependency, or reference only. |
| P1.2.03 | Implement tier 1: every type that maps to an existing crate. Examples: Skein sizes via `skein`, JH via `jh`, Shabal via `shabal`, HAS-160 requires a new crate, Streebog 512 via `streebog`. |
| P1.2.04 | Implement tier 2: add dependencies for HAS-160, Snefru, and any other gap. Prefer pure Rust crates with no build scripts. |
| P1.2.05 | Implement tier 3: write the algorithm in `src/hash/reference/` for the remainder. These become the differential test oracle. |
| P1.2.06 | Remove `detect_only` behaviour entirely. If a type cannot be verified, it must not be registered as a `HashCracker`; register it in a separate `HashTypeDetector` list and render it in `pwdcrack list` under a clearly marked section. |
| P1.2.07 | Gate: `cargo test --test hash_support_matrix` asserts `implemented + detection_only == total` and that `detection_only` is empty. |

### 5.3 P1.3 Detection Accuracy (B-03, O-03, M-03)

The current detector is first match wins over an ordered list. The new detector must score candidates.

| Task | Action |
|------|--------|
| P1.3.01 | Change `HashParser::can_parse` from `bool` to a score: `fn parse_score(&self, input: &str) -> Option<u8>` where 255 means certain and 1 means possible. |
| P1.3.02 | Require structural validation, not just length. Examples: hex types must validate hex; base64 types must validate the alphabet and decoded length; unix crypt types must validate the `$id$salt$hash` structure and checksum charset; Cisco type 7 must validate the hex alphabet. |
| P1.3.03 | Add discriminating checks for the known ambiguity set. Examples: 32 hex characters can be MD5, MD5 half, triple MD5, NTLM, LM half, EPi, and Snefru 256. Resolve by prefix rules, internal structure, and salt marker presence. |
| P1.3.04 | Replace the linear scan with a two stage design. Stage 1 groups parsers by cheap structural signature: character class histogram, length, and delimiter presence. Stage 2 evaluates only parsers whose signature matches, then picks the highest score. Target: detection under 1 microsecond for a 32 character hex input. |
| P1.3.05 | Remove `Detector::new()` eager allocation of 702 boxes. Build a signature keyed table once, and store parsers in a `Vec` allocated once per `Detector`, reused across calls. |
| P1.3.06 | Build the labelled corpus `tests/vectors/detection_matrix.txt` with at least 3,000 entries, minimum 8 per hash type, covering boundary lengths and malformed inputs. |
| P1.3.07 | Gate: `cargo test --test detection_matrix` passes with 100 percent accuracy, and `benches` reports detection under 1 microsecond. |

### 5.4 P1.4 Comparison and Encoding Hygiene (B-02)

| Task | Action |
|------|--------|
| P1.4.01 | Implement `constant_time_eq_ignore_case` correctly: iterate all bytes, fold both operands with ASCII case folding, accumulate XOR into a single accumulator, never early return. |
| P1.4.02 | Add a timing test that compares equal prefixes of length 1 through 64 and asserts the duration variance stays within 5 percent. |
| P1.4.03 | Audit every comparison site in `src/hash/` and route all of them through `constant_time_eq` or the new ignore case variant. |
| P1.4.04 | Audit hex decoding: use a lookup table rather than `u8::from_str_radix` per byte in hot paths. |

### 5.5 P1.5 Hash Command Correctness (B-05)

| Task | Action |
|------|--------|
| P1.5.01 | Change `generate_test_hash` to return `Result<String, HashError>` and propagate. Remove the plaintext fallback. |
| P1.5.02 | When the algorithm is unknown, print an error that lists the closest supported algorithms by edit distance. |
| P1.5.03 | Add a test for every algorithm accepted by `pwdcrack hash -t`. |

---

## 6. Phase 2: Attack Engine Precision

**Objective**: make attacks correct, bounded, resumable, and correctly accounted.

### 6.1 P2.1 Mask Attack Correctness

| Task | Action |
|------|--------|
| P2.1.01 | Write `src/attack/mask.rs` as the single source of truth for mask parsing, keyspace size, and candidate iteration. Today the logic is duplicated between `brute.rs`, `cmd_mask`, and `cmd_expand`. |
| P2.1.02 | Support the full placeholder set: `?l ?u ?d ?s ?a ?h ?H ?b ?w ?1 ?2 ?3 ?4`, literal ranges `(?a-z)`, case alternation `[?u?l]`, and the `%` escape. Reject unknown tokens with the position of the first error. |
| P2.1.03 | Compute keyspace as `u128` and refuse to run when the product exceeds `u64::MAX`, printing the exact keyspace so the user can decide. |
| P2.1.04 | Implement `--min-length` and `--max-length` by expanding the mask to every length in range, longest first, matching the existing intent documented in `src/cli/args.rs`. |
| P2.1.05 | Differential test: for every mask in `tests/mask_corpus.txt` with keyspace under 10^7, assert the new iterator matches the old output byte for byte. |

### 6.2 P2.2 Session, Limit, and Resume (B-24, B-25, B-26)

| Task | Action |
|------|--------|
| P2.2.01 | Define `src/attack/session.rs` with a versioned binary checkpoint. Fields: format version, attack kind, hash file digest, wordlist path and size, mask, rule file digest, candidates tested so far, potfile path, start time. |
| P2.2.02 | Write checkpoints every N candidates, default 1,000,000, and on clean shutdown. Use an atomic write: write to a temporary file in the same directory, `fsync`, then `rename`. |
| P2.2.03 | Implement `--limit` across all seven attack handlers. The counter must be exact under multi threading: use a shared atomic and a bulk claim of chunks so the counter never overshoots. |
| P2.2.04 | Implement `--resume`. On start, if a checkpoint matches the current inputs, skip to the recorded position. If the digest differs, refuse and explain. |
| P2.2.05 | Make `--resume` a global flag that resolves to the session path for the active attack, matching the existing CLI declaration. |
| P2.2.06 | Add tests: run an attack with `--limit 1000`, resume it, confirm the total candidate count equals the sum and the result set matches an uninterrupted run. |

### 6.3 P2.3 Progress and Statistics (B-27, B-44)

| Task | Action |
|------|--------|
| P2.3.01 | Redesign `ProgressStats`: fields `candidates_tested`, `candidates_total` (optional), `hashes`, `cracked`, `start`, `last_update`. `cracked()` returns the real counter. |
| P2.3.02 | Move stats into `parking_lot::RwLock` with a relaxed write policy: update at most every 100 ms. Reading must never block candidate generation for longer than 1 microsecond. |
| P2.3.03 | ETA calculation: use a rolling window of the last 10 seconds rather than the run average, so the estimate converges quickly after a tier change. |
| P2.3.04 | Replace `env_logger::init()` with `env_logger::Builder::from_env` plus a default filter of `warn`, and map `--verbose` to `info` and `RUST_LOG=debug` to `debug`. |
| P2.3.05 | Rate display: report both candidates per second and hashes per second, since they differ by a factor of the hash count. |

### 6.4 P2.4 Rule Engine Correctness

| Task | Action |
|------|--------|
| P2.4.01 | Document the supported rule set precisely in `docs/RULES.md`: `l u c C t T r d f { } [ ] $ ^ D Z X s S @ k K p P u v 1 2 3 4 5 6 7 8 9 0 ? * + . : % !` with exact semantics and examples for each. |
| P2.4.02 | Handle rule file parsing errors per line: report the line number and the failing token, and skip that line with a warning instead of aborting the whole run. |
| P2.4.03 | Cap the maximum output length per rule to 1024 bytes by default and expose `--max-length` to override. Guard against combinatorial explosion. |
| P2.4.04 | Batch application: apply all rules to one word before moving to the next, reusing allocations. Target: 1.5x dictionary throughput. |
| P2.4.05 | Differential test against a Python reference implementation in `tests/rules/reference.py` over `tests/rules/*.rule`, asserting byte identical output. |

### 6.5 P2.5 Attack Dispatch Unification

| Task | Action |
|------|--------|
| P2.5.01 | Create `src/attack/mod.rs::AttackContext` carrying the parsed hashes, the cracker for each type, the potfile, the stats handle, and the session handle. |
| P2.5.02 | Rewrite all seven attack handlers to take `&AttackContext`. Remove duplicated hash loading, cracker lookup, and potfile logic from `src/main.rs`. |
| P2.5.03 | Target: `src/main.rs` shrinks below 1,100 lines with no duplicated verification loops. |

---

## 7. Phase 3: Engine Abstraction

**Objective**: one trait, one capability report, one work split. This phase makes every later engine phase a matter of filling in an implementation.

### 7.1 P3.1 The Engine Trait

| Task | Action |
|------|--------|
| P3.1.01 | Create `src/engine/mod.rs` with `pub trait Engine: Send + Sync` requiring: `fn name(&self) -> &str`, `fn info(&self) -> EngineInfo`, `fn is_available(&self) -> bool`, `fn verify_batch(&self, hashes: &[HashEntry], candidates: &[&[u8]]) -> Vec<MatchResult>`, `fn cost_hint(&self) -> CostHint`. |
| P3.1.02 | `EngineInfo` carries `device_name`, `vendor`, `throughput_hps` (measured, not literal), `batch_size`, `memory_bytes` (queried from the driver, never hardcoded), and `capabilities: Vec<Capability>`. |
| P3.1.03 | `Capability` is an enum: `Md5`, `Sha1`, `Sha256`, `Sha512`, `Ntlm`, `Bcrypt`, `Argon2`, `Scrypt`, `Pbkdf2`, `MaskGen`, `RuleApply`. Engines declare exactly what they implement. |
| P3.1.04 | Implement the trait for the CPU scalar path first, so the trait is proven before any engine adopts it. |

### 7.2 P3.2 Planner and Merger

| Task | Action |
|------|--------|
| P3.2.01 | `src/engine/planner.rs` splits a keyspace into chunks sized to each engine's `batch_size`, interleaves them so slow engines start early, and assigns by measured throughput. |
| P3.2.02 | `src/engine/merge.rs` collects `MatchResult` from all engines, dedupes by hash, sorts by original hash file order for stable output, and reports counts per engine. |
| P3.2.03 | Add a benchmark that asserts the planner does not reduce aggregate throughput by more than 3 percent versus single engine execution. |

### 7.3 P3.3 Honest Capability Reporting (B-19, B-22)

| Task | Action |
|------|--------|
| P3.3.01 | Replace every unconditional `is_available() -> true` in `engine-tensor` and `engine-warp` with real probing. |
| P3.3.02 | Implement `crack_detect_tier` and `crack_hashes_per_second` in `engine-bridge/src/c_api.rs` against the real detection result and the last measured rate. |
| P3.3.03 | Add a conformance test that iterates every engine, calls `info()`, and fails if `throughput_hps` is exactly `0.0` for an engine that reports available, or if `memory_bytes` equals one of the hardcoded 8192, 512, or 128 values. |

---

## 8. Phase 4: SIMD Engine, Real Intrinsics (B-13)

**Objective**: actual vectorized kernels, not scalar wrappers.

### 8.1 P4.1 Multi Buffer Hashing

The central technique: process N independent messages in parallel lanes so instruction level parallelism hides the latency of the dependency chain in SHA and MD5.

| Task | Action |
|------|--------|
| P4.1.01 | Implement an 8 lane AVX2 MD5 kernel in `engines/engine-simd/src/x86/avx2/md5.rs`. Unroll the message schedule so all 8 lanes advance simultaneously. Use `_mm256_loadu_si256` for input and rotate intrinsics for the step function. |
| P4.1.02 | Implement an 8 lane AVX2 SHA-1 kernel in `engines/engine-simd/src/x86/avx2/sha1.rs`. |
| P4.1.03 | Implement an 8 lane AVX2 NTLM kernel in `engines/engine-simd/src/x86/avx2/ntlm.rs`. NTLM is MD4, which is fully parallelisable and gives the largest win. |
| P4.1.04 | Implement an 8 lane AVX2 SHA-256 kernel in `engines/engine-simd/src/x86/avx2/sha256.rs`. |
| P4.1.05 | Implement a 16 lane AVX-512 variant of each kernel in `engines/engine-simd/src/x86/avx512/`, gated on `is_x86_feature_detected!("avx512f")`. |
| P4.1.06 | Implement an 8 lane SSE2 SHA-1 baseline for pre AVX2 hosts. |
| P4.1.07 | Message padding: implement a shared `pad_messages` helper that takes a slice of variable length messages and produces fixed size 64 byte or 128 byte blocks, handling the length field correctly. This is the part most naive implementations get wrong. |
| P4.1.08 | Differential test: for 10,000 random inputs of length 0 through 200, assert every lane equals the scalar reference. This catches padding and endianness bugs. |

### 8.2 P4.2 Hardware Accelerated Single Buffer

| Task | Action |
|------|--------|
| P4.2.01 | Implement SHA-NI SHA-1 in `engines/engine-simd/src/x86/shani.rs` using `_mm_sha1rnds4_epu32`, `_mm_sha1nexte_epu32`, and `_mm_shuffle_epi32`. Replace the current scalar fallback. |
| P4.2.02 | Implement SHA-NI SHA-256 using `_mm_sha256rnds2_epu32`, `_mm_sha256msg1_epu32`, and `_mm_sha256msg2_epu32`. |
| P4.2.03 | Implement SHA-NI SHA-512 via the AVX-512 extension `_mm_sha512rnds2_ph` when available. |
| P4.2.04 | Gate each with `#[target_feature(enable = "sha,sse4.1,ssse3")]` and runtime detection. Never call them without the feature check. |

### 8.3 P4.3 ARM NEON and SVE

| Task | Action |
|------|--------|
| P4.3.01 | Implement 4 lane NEON MD5 in `engines/engine-simd/src/arm/neon64.rs` using `uint32x4_t` and `vrotq_u32`. |
| P4.3.02 | Implement 4 lane NEON SHA-1 and SHA-256. SHA-256 on ARMv8 benefits from the `sha2` crypto extension where present; gate on `target_feature = "sha2"`. |
| P4.3.03 | Implement SVE variants in `engines/engine-simd/src/arm/sve.rs` using fixed length vectors with a runtime length check. |
| P4.3.04 | Test on real hardware via the `tests/test_vectors` corpus in CI with self hosted runners. Where hardware is unavailable, the kernels must at least compile behind their feature gates and the differential test must be skipped with a clear message, never silently passed. |

### 8.4 P4.4 Dispatch Correctness

| Task | Action |
|------|--------|
| P4.4.01 | Replace the current dispatch, which selects a path by hash name, with a dispatch table keyed by `(HashType, CpuFeatures)`. |
| P4.4.02 | `CpuFeatures` is computed once per process by `raw-cpuid` and cached in a `OnceLock`. Remove any per call detection. |
| P4.4.03 | Emit a `log::debug!` line naming the selected kernel per hash type when `--verbose` is set, so users can confirm acceleration is active. |

---

## 9. Phase 5: GPU Engine, WGSL and wgpu (B-14, B-15)

**Objective**: load and correctly execute all 31 WGSL shaders, with real memory queries.

### 9.2 P5.1 Shader Inventory and Binding

| Task | Action |
|------|--------|
| P5.1.01 | Inventory all `.wgsl` files in `engines/engine-gpu/src/shaders/`. For each, document the entry point, the bind group layout, the workgroup size, and the hash type it serves. Output to `docs/GPU_SHADERS.md`. |
| P5.1.02 | Build every shader at compile time. Add `engines/engine-gpu/build.rs` that parses each WGSL file with `naga` and emits a compile error for any invalid shader. Today only 8 of 31 are loaded; the other 23 are never validated. |
| P5.1.03 | Define one bind group layout in `engines/engine-gpu/src/pipeline.rs`: group 0 binding 0 candidates buffer, binding 1 hashes buffer, binding 2 results buffer, binding 3 uniform params, binding 4 lookup tables (for bcrypt and argon2). |
| P5.1.04 | Rewrite each shader to that layout so all 31 compile against one layout. |
| P5.1.05 | Verify each shader by differential test against the Rust reference for at least 1,000 random inputs per hash type. A GPU hash that disagrees with the CPU hash is worse than no GPU hash. |

### 9.3 P5.2 Correct GPU Kernels

| Task | Action |
|------|--------|
| P5.2.01 | `md5.wgsl`: implement the 64 step round with correct per step constants and correct rotate amounts. The current `md5_opt.wgsl` must be audited against RFC 1321. |
| P5.2.02 | `sha1.wgsl`: 80 rounds, correct big endian word loading. |
| P5.2.03 | `sha256.wgsl`: 64 rounds, correct `ch`, `maj`, `Sigma0`, `Sigma1`, `sigma0`, `sigma1`. |
| P5.2.04 | `sha512.wgsl`, `sha384.wgsl`, `sha512_224.wgsl`: 64 bit lanes via two `u32` halves. Audit endianness carefully, this is the most error prone family. |
| P5.2.05 | `ntlm.wgsl` and `md4.wgsl`: 48 rounds, little endian. |
| P5.2.06 | `ripemd160.wgsl`: 5 parallel lines of 16 words, 80 rounds each, with correct rotation constants. |
| P5.2.07 | `blake2b.wgsl`: full 12 round compression function with the sigma permutation table as a const array. |
| P5.2.08 | `whirlpool.wgsl`: requires the 8x256 circulant hash tables. Embed them as const arrays. |
| P5.2.09 | `streebog256.wgsl`: requires the 8 SBoxes of 256 bytes each and 12 round constants. |
| P5.2.10 | `argon2i_core.wgsl`, `bcrypt.wgsl`, `pbkdf2_sha256.wgsl`: these are memory hard or iteration heavy. Implement only if a device profile justifies it, and gate behind a flag. |

### 9.4 P5.3 Scheduling and Memory

| Task | Action |
|------|--------|
| P5.3.01 | Replace hardcoded VRAM in `engines/engine-gpu/src/device.rs` with `wgpu::Adapter::get_info()` and the actual `limits.max_buffer_size`. Query via `downlevel` info where available. |
| P5.3.02 | Batch size must be computed as `min(adapter_limits / per_candidate_bytes, config_max)` and clamped so that candidates plus hashes plus results fit in the buffer budget with 20 percent headroom. |
| P5.3.03 | Implement a staging ring with at least 3 buffers so that upload, compute, and readback overlap. |
| P5.3.04 | Add a device loss handler that reports the loss through `EngineInfo` and falls back to the CPU engine rather than panicking. |
| P5.3.05 | Gate: differential tests pass for every enabled shader, and `cargo test --features engine-gpu` passes on a machine with a supported GPU. |

---

## 10. Phase 6: CUDA and PTX (B-11, B-16)

**Objective**: kernels that compute the correct hash, launched for real.

### 10.1 P6.1 Build Pipeline

| Task | Action |
|------|--------|
| P6.1.01 | Add `engines/engine-cuda/build.rs` that locates `nvcc` through `CUDA_PATH`, `CUDACXX`, or `PATH`, compiles each `.cu` in `engines/engine-cuda/src/kernels/` to PTX, and embeds the PTX with `include_bytes!`. |
| P6.1.02 | Target a PTX ISA version compatible with compute capability 7.0 and above, and JIT compile upward. Set a minimum floor of 6.0 for Maxwell and document it. |
| P6.1.03 | Fail the build with an actionable message when `nvcc` is absent and the `cuda` feature is on, rather than at runtime. |
| P6.1.04 | Keep a checked in PTX fallback so release artifacts built without a CUDA toolchain still run through the driver JIT. |

### 10.2 P6.2 Kernel Correctness (B-16)

| Task | Action |
|------|--------|
| P6.2.01 | Rewrite `md5.cu`. Load words with `__byte_perm` to obtain the correct little endian word regardless of host layout. Use the full 64 constant table `K[64]` and per step rotation amounts `S[64]`. |
| P6.2.02 | Rewrite `sha1.cu` with `K` constants 0x5A827999 and 0x6ED9EBA1 split across rounds 0 to 19, 20 to 39, and 40 to 59, and 0xCA62C1D6 for 60 to 79. |
| P6.2.03 | Rewrite `sha256.cu` with the full `K[64]` table. |
| P6.2.04 | Rewrite `sha512.cu` with `K[80]` as `unsigned long long`. |
| P6.2.05 | Rewrite `ntlm.cu` for MD4 semantics. |
| P10.2.06 | Implement `bcrypt.cu` with the EksBlowfish setup, the 4KB SBoxes generated on device into shared memory, and the 2^cost key schedule. |
| P10.2.07 | Each kernel takes a `uint64_t` for candidate length and a `const uchar*` for the candidate, writes the digest into an output slot indexed by `candidate_id`, and never allocates. |
| P10.2.08 | Differential test every kernel against the Rust reference for 10,000 random candidates per hash type on a real CUDA device. Any mismatch fails the phase gate. |

### 10.3 P6.3 Launch Path

| Task | Action |
|------|--------|
| P6.3.01 | Remove the unconditional `Err(NoCudaSupport)` in `crack_md5` and every sibling. Launch through `cudarc` using the embedded PTX module. |
| P6.3.02 | Implement the scheduler in `engines/engine-cuda/src/scheduler.rs`: one stream per SM partition, grid sized to fill the device, and results copied back asynchronously. |
| P6.3.03 | Implement overlap with the CPU engine: while the GPU works on chunk N, the CPU works on chunk N+1. The planner in Phase 3 already supports this. |
| P6.3.04 | Gate: `cargo test --features engine-cuda` passes, and measured GPU MD5 throughput is at least 20x the 8 core CPU baseline. |

---

## 11. Phase 7: OpenCL, Metal, Vulkan, SYCL

### 11.1 P7.1 OpenCL (B-17)

| Task | Action |
|------|--------|
| P7.1.01 | Rewrite `md5.cl`, `sha1.cl`, `sha256.cl`, `sha512.cl`, `ntlm.cl` with the same constant tables and rotation schedules as the CUDA kernels. |
| P7.1.02 | Add a build time `clinfo` free compile check: compile each kernel at first use and surface the build log as an error. |
| P7.1.03 | Replace the unconditional `Err(NotEnabled)` with a real launch through the `ocl` crate. |
| P7.1.04 | Query device properties through `clGetDeviceInfo` for max work group size, local memory size, and compute units. Remove hardcoded values. |
| P7.1.05 | Gate: differential tests pass on any OpenCL device. |

### 11.2 P7.2 Metal (B-18)

| Task | Action |
|------|--------|
| P7.2.01 | Replace the fabricated device list and the `/tmp/metal_devices.txt` read with a real path: `MTLCreateSystemDefaultDevice()` on macOS, and an honest "not supported" on every other platform. |
| P7.2.02 | Rewrite `md5.metal`, `sha1.metal`, `sha256.metal` as real kernels in `engines/engine-metal/shaders/`. |
| P7.2.03 | Replace the byte packing in the compile function with a real shader compilation through `metal-rs`. |
| P7.2.04 | Query `recommendedMaxWorkingSetSize` and `maxThreadsPerThreadgroup` instead of guessing. |
| P7.2.05 | Gate: differential tests pass on Apple silicon and Intel Macs. |

### 11.3 P7.3 Vulkan

| Task | Action |
|------|--------|
| P7.3.01 | Implement a compute pipeline: create a shader module from SPIR-V compiled from a WGSL source using `naga`, a descriptor set layout, a pipeline, and a command buffer per dispatch. |
| P7.3.02 | Replace `compile_glsl_to_spirv`, which always errors, with a real `naga` based SPIR-V path. |
| P7.3.03 | Reuse the WGSL kernels from Phase 5 where possible so shader logic is not duplicated between the wgpu and Vulkan paths. |
| P7.3.04 | Query `maxComputeWorkGroupInvocations` and `maxStorageBufferRange` for batch sizing. |

### 11.4 P7.4 SYCL (B-20)

| Task | Action |
|------|--------|
| P7.4.01 | Decide: implement via `sycl-rs` or delete the engine. Recommendation: delete. The WGSL and CUDA engines cover the same hardware with less maintenance. |
| P7.4.02 | If deleted, remove the workspace member, the feature, the `--tpu` style flag references, and the docs entry. |

---

## 12. Phase 8: FPGA and SystemVerilog

**Objective**: correct RTL cores with verified timing and a real host interface.

### 12.1 P8.1 Core Inventory and Verification

| Task | Action |
|------|--------|
| P8.1.01 | Inventory every `*_core.sv` and `*_opt.sv` in `engines/engine-fpga/rtl/cores/`. For each, record whether it has a testbench, whether it passes, and whether it produces output identical to the Rust reference. |
| P8.1.02 | Where no testbench exists, write one: `tb_<core>_core.sv` that instantiates the core, drives known vectors, and asserts the output against hardcoded expected values. |
| P8.1.03 | Move every testbench into `rtl/sim/` with a shared `tb_common.svh` providing the vector ROM and the comparison task. |
| P8.1.04 | Add a `scripts/simulate.tcl` that runs every testbench and fails on any mismatch, wired into CI. |

### 12.2 P8.2 Core Correctness

| Task | Action |
|------|--------|
| P8.2.01 | `md5_core.sv`: verify the 64 step schedule, the rotation amounts, and the little endian word ordering against RFC 1321 vectors. |
| P8.2.02 | `sha1_core.sv`: verify against FIPS 180 test vectors. |
| P8.2.03 | `sha256_core.sv`: verify the message schedule expansion and the compression function. |
| P8.2.04 | `sha512_core.sv` and `sha384_core.sv`: verify 64 bit datapath handling. |
| P8.2.05 | `blake2b_core.sv`, `blake2s_core.sv`: verify the round function and the parameter block. |
| P8.2.06 | `ntlm_core.sv`: verify MD4 semantics. |
| P8.2.07 | `ripemd160_core.sv`, `ripemd128_core.sv`: verify the two parallel lines and the byte ordering. |
| P8.2.08 | `whirlpool_core.sv`, `streebog256_core.sv`: verify the circulant tables and the round constants respectively. |
| P8.2.09 | `aes_cmac_core.sv`, `hmac_wrapper.sv`, `pbkdf2_core.sv`, `crc_accelerator.sv`: verify or mark as unimplemented. |
| P8.2.10 | Where a core cannot be verified, remove it from `rtl/top.sv` so the design only contains verified blocks. |

### 12.3 P8.3 Host Interface

| Task | Action |
|------|--------|
| P8.3.01 | Define the DMA protocol in `engines/engine-fpga/src/protocol.rs` with an explicit version field, a sequence number, and a CRC32 over the payload. Reject packets with a bad CRC or an unknown version. |
| P8.3.02 | Implement a worker thread model: one thread per completion queue, with reordering by sequence number. |
| P8.3.03 | Verify the multi core scheduler in `engines/engine-fpga/src/scheduler.rs` against a simulated device in `tests/`, using a mock transport. |
| P8.3.04 | The XDC constraint file must be checked by Vivado lint in CI, or the file must be documented as an example. |

### 12.4 P8.4 Timing and Resource Targets

| Task | Action |
|------|--------|
| P8.4.01 | Target 300 MHz for MD5, SHA-1, SHA-256, and NTLM cores on a mid range Artix-7. |
| P8.4.02 | Target utilisation under 60 percent LUT and 70 percent BRAM so multiple cores fit. |
| P8.4.03 | Publish a Vivado utilisation and timing report into `docs/FPGA_RESULTS.md`. |

---

## 13. Phase 9: Distributed Engine

**Objective**: a cluster that is authenticated, encrypted, and resistant to a hostile peer.

### 13.1 P9.1 Protocol Security (B-31, B-32)

| Task | Action |
|------|--------|
| P9.1.01 | Bind to `127.0.0.1` by default. Require an explicit `--bind` for any other address, and print a warning that the cluster is unauthenticated on a non loopback interface. |
| P9.1.02 | Replace the length prefixed JSON protocol with TLS. Use `tokio-rustls` with a self signed certificate generated on first run, or a user supplied certificate pair. |
| P9.1.03 | Add mutual authentication: a shared token or a client certificate, configured in `DistributedConfig`. Reject handshakes without it. |
| P9.1.04 | Move to a binary protocol using `bincode` or `postcard` with a versioned schema, replacing JSON plus manual length prefixes. |
| P9.1.05 | Remove the arbitrary path problem: the master sends wordlist contents or a hash of the path plus a signed manifest, never a raw path the worker opens blindly. |
| P9.1.06 | Rate limit handshake attempts per IP and log failures. |

### 13.2 P9.2 Work Distribution

| Task | Action |
|------|--------|
| P9.2.01 | Implement a fair scheduler: distribute by measured worker throughput, not by round robin, so a slow node does not become the bottleneck. |
| P9.2.02 | Heartbeat with exponential backoff. Mark a worker dead after 3 missed heartbeats and requeue its work units. |
| P9.2.03 | Checkpoint the master state so a master restart resumes rather than restarting. |
| P9.2.04 | Implement deduplicated candidate assignment so two workers never test the same candidate. |

### 13.3 P9.3 Protocol Tests

| Task | Action |
|------|--------|
| P9.3.01 | Add a test that starts a master and 4 workers in process, runs a dictionary attack, and asserts the union of cracked hashes equals the single node result. |
| P9.3.02 | Add a test that injects a malformed packet and asserts the worker drops the connection without crashing. |
| P9.3.03 | Add a test that an unauthenticated client is rejected. |

---

## 14. Phase 10: Web Dashboard (B-30)

**Objective**: a control plane that is not exposed by default.

| Task | Action |
|------|--------|
| P10.1.01 | Bind to `127.0.0.1` by default. Document `--web-host` and require an explicit flag to bind to `0.0.0.0`. **done, verified.** See `docs/PHASE10_STATUS.md`. |
| P10.1.02 | Require a token. Generate one on first run, print it once, store it with mode 0600, and require `Authorization: Bearer` on every mutating route. **done, verified.** |
| P10.1.03 | Add CSRF protection: same site cookies plus a custom header requirement on state changing requests. **done, verified.** |
| P10.1.04 | Implement real attack execution: the `start` route must enqueue work into the engine planner, and `stop`, `pause`, and `resume` must act on a real handle rather than a state enum. **done, verified.** A dictionary attack through the HTTP API recovered a real MD5. |
| P10.1.05 | Rate limit and log every mutating request. **done, verified.** Refusals are logged, not only successes. |
| P10.1.06 | Serve a `Content-Security-Policy` that forbids inline script. **done, verified.** The pages were rewritten to comply rather than left violating their own policy. |
| P10.1.07 | Gate: `cargo test --features engine-web` includes a test asserting that an unauthenticated `POST /api/start` returns 401. **done, verified**, over a real socket. |

---

## 15. Phase 11: Bridges

| Task | Action |
|------|--------|
| P11.1.01 | Complete `engines/engine-bridge/src/python.rs` with PyO3 types mirroring the Rust API, plus a `py.typed` marker and a `maturin` build. **done, verified.** `Cracker`, `CrackedHash`, `Target`, `EngineInfo`; wheel built by maturin, installed, 22 tests against the installed package. |
| P11.1.02 | Complete the Node N-API binding in `engines/engine-bridge/src/node.rs` with a promise based asynchronous API. **done, verified.** `AsyncTask` so attacks return a Promise; 16 tests in a real Node process. |
| P11.1.03 | Write `pwdcrack.xs` for Perl, or remove the Perl bridge. **done.** The XS existed but had never been compiled and declared six wrong function names, a wrong arity, a wrong return type and one function that did not exist. Rewritten against the real ABI; 31 tests pass. |
| P11.1.04 | In `c_api.rs`, make every function null safe, check every pointer, and document the thread safety of each entry point. **done, verified.** Found two attacks deadlocking on a non reentrant mutex taken twice. |
| P11.1.05 | Resolve `panic = "abort"` against `cdylib` (B-36). Either remove `panic = "abort"` from the release profile, or wrap every FFI boundary in `catch_unwind` under a dedicated profile. Recommended: remove `panic = "abort"` and document why. **done.** Removed, with the reasoning in `Cargo.toml`; `crack_panics_abort()` reports the strategy in force. |
| P11.1.06 | Implement `crack_detect_tier` and `crack_hashes_per_second` against real values. **done, verified.** Both were constants: `0.0` with a comment saying "static for now", and the literal `"Auto"`. |
| P11.1.07 | Add a C test suite compiled in CI that exercises every exported symbol and verifies the memory contract for `crack_get_result`. **done, verified.** 41 checks in `tests/c/test_bridge.c`, run by `.github/workflows/bridges.yml`. |

---

## 16. Phase 12: Power, Thermal, Platform

**Objective**: respect the machine, and be able to restore what was changed.

| Task | Action |
|------|--------|
| P12.1.01 | Read and record every sysfs value before writing. Store the original governor, frequencies, and C-states in a session file so they can be restored. |
| P12.1.02 | Refuse to write to sysfs when not running as root, with a clear message, rather than failing silently. |
| P12.1.03 | Implement a temperature guard: read the package temperature each second and pause when it exceeds a configurable threshold, defaulting to 90 degrees Celsius on desktop. |
| P12.1.04 | Implement a battery guard for the Android path: pause below 20 percent, resume above 50 percent, and stop above 65 degrees Celsius. |
| P12.1.05 | Wire the budget into the candidate loop: measure throughput each second and insert a sleep so that the estimated power draw stays under the configured wattage. |
| P12.1.06 | Remove the `configs/*.toml` dead files or wire them. Recommended: wire them. Add the `toml` dependency, load the tier file at startup when `--tier` is given, and have each key override the matching CLI default. Document precedence: CLI flag beats config file beats default. |

---

## 17. Phase 13: CLI and Output Polish

| Task | Action |
|------|--------|
| P13.1.01 | Keep the new help layout from `src/cli/args.rs`: single `Commands` section, grouped option headings, examples footer, no em dashes. |
| P13.1.02 | Group the long help for each subcommand with the same heading scheme so the long form matches the short form. |
| P13.1.03 | Add `pwdcrack list` sections: "Verifiable", "Detection only", "Deprecated", so the user always knows what can actually be cracked. |
| P13.1.04 | Add a `pwdcrack doctor` subcommand that prints the selected engine per hash type, the measured H/s, the detected CPU features, and the active tier. |
| P13.1.05 | Exit codes: 0 success, 1 runtime error, 2 usage error, 3 partial success. Document in `README.md`. |
| P13.1.06 | Add `--json` schema documentation in `docs/OUTPUT_SCHEMA.md` covering `text`, `json`, and `csv` formats. |

---

## 18. Phase 14: Security Posture

| Task | Action |
|------|--------|
| P14.1.01 | Write a `SECURITY.md` describing the threat model: this is an offensive tool, the network surfaces are opt in, and how to report an issue. |
| P14.1.02 | Fix the predictable log path in `install.sh`: use `mktemp` and set mode 0600. |
| P14.1.03 | Add checksum verification to `wordlists/download.sh`: pin a SHA-256 per file and verify before use. |
| P14.1.04 | Audit `engine-go` `libloading` usage: restrict loadable paths to an explicit allowlist directory, never an arbitrary user string. |
| P14.1.05 | Run `cargo audit` and `cargo deny` in CI and fail on any new advisory. |
| P14.1.06 | Add a dependency policy: prefer pure Rust crates with no build scripts for any new dependency. |

---

## 19. Phase 15: Testing and Benchmarking

### 19.1 P15.1 Test Layers

| Layer | Target | Content |
|-------|--------|---------|
| Unit | 100 percent of `src/hash/` verification functions | One test per hash type per known vector |
| Differential | Every engine against the reference | Random inputs, 10,000 per hash type per engine |
| Detection | 3,000 labelled hashes | Boundary lengths, malformed inputs, ambiguous formats |
| Attack integration | 7 attack modes | Small corpora with known answers, assert the full result set |
| Mask | Every mask form | Ordering and keyspace equality with the reference |
| Rules | 20 rule files | Byte equality with `tests/rules/reference.py` |
| Session | Resume and limit | Run, stop, resume, compare with uninterrupted |
| Engine | Per engine | Capability report truthfulness, fallback on device loss |
| Fuzz | `verify_any`, `parse_hash`, `apply_rules`, `expand_mask` | 10 million iterations, no hang, no panic |

### 19.2 P15.2 New Test Files

| File | Purpose |
|------|---------|
| `tests/hash_support_matrix.rs` | Asserts the implemented set matches the declared set |
| `tests/detection_matrix.rs` | Labelled corpus accuracy |
| `tests/attack_integration.rs` | End to end attack correctness |
| `tests/mask_equivalence.rs` | Mask output equality |
| `tests/rule_equivalence.rs` | Rule output equality against Python |
| `tests/session_resume.rs` | Checkpoint and resume |
| `tests/engine_conformance.rs` | Capability truthfulness |
| `fuzz/Cargo.toml`, `fuzz/targets/*.rs` | Fuzz harnesses |

### 19.3 P15.3 Benchmark Suite

| Task | Action |
|------|--------|
| P15.3.01 | Extend `benches/hash_bench.rs` to cover MD5, SHA-1, SHA-256, SHA-512, NTLM, bcrypt cost 5, cost 10, Argon2id, scrypt, and unix crypt. |
| P15.3.02 | Add `benches/attack_bench.rs` measuring dictionary, brute-force mask, and combinator end to end throughput in candidates per second. |
| P15.3.03 | Add `benches/detect_bench.rs` measuring detection latency in nanoseconds per hash. |
| P15.3.04 | Emit JSON to `target/bench.json`. CI compares against the previous run and fails on a regression above 5 percent for any single target. |

### 19.4 P15.4 Gates

| Task | Action |
|------|--------|
| P15.4.01 | `cargo test` must pass with zero failures. |
| P15.4.02 | `cargo test --features tier-high` must pass. |
| P15.4.03 | `scripts/test-matrix.sh` must exit 0 for all 26 feature combinations. |
| P15.4.04 | `cargo build --release` must complete with no warnings in pwdcrack owned crates. |

---

## 20. Phase 16: Specialised Accelerators

**Objective**: honest support, or honest removal. No simulation presented as acceleration.

| Engine | Decision | Task |
|--------|----------|------|
| `engine-tpu` | Implement or delete | TPU access requires the Edge TPU runtime and a USB device. If unavailable, delete the crate and remove the flag. |
| `engine-xpu` | Implement or delete | oneAPI is a large dependency. Recommend delete unless a target user is confirmed. |
| `engine-dsp` | Delete | A DSP engine for password hashing has no coherent workload. |
| `engine-riscv` | Implement | The RVV intrinsics are stable. Implement 4 and 8 lane MD5 and SHA-256 for RVV 1.0 targets. |
| `engine-zen` | Implement | AMD Zen specific paths: use the same AVX2 kernels with `target-cpu=znver3` and drop the arch detection in favour of `is_x86_feature_detected`. |
| `engine-embedded` | Implement | Cortex-M targets have no rayon and no atomics of the required width. Restrict to single threaded and 1 to 4 byte lane kernels. |
| `engine-hybrid` | Implement | The scheduler data structures exist. Wire them to the Phase 3 planner so CPU, GPU, and FPGA actually share work. |
| `engine-jit` | Complete | Finish rule JIT codegen with Cranelift for the top 20 rules by frequency. Fall back to the interpreter otherwise. |
| `engine-tensor` | Delete or complete | A tensor framework has no role here. Recommend delete. |
| `engine-warp` | Delete | Duplicate of `engine-jit` with fabricated kernels. |
| `engine-julia`, `engine-go`, `engine-wasm` | Delete | Dynamic bridge stubs with no consumer. |

**P16.0.01**: For every engine marked delete, remove the workspace member in `Cargo.toml`, the feature, the optional dependency, the CLI flag, and the documentation entry in one change. **P16.0.02**: For every engine marked implement, the capability report must state measured throughput and the phase gate requires a differential test to pass.

---

## 21. Phase 17: Release Engineering

| Task | Action |
|------|--------|
| P17.1.01 | Tag `v2.0.0` only when every phase gate above passes. |
| P17.1.02 | Produce artefacts: x86_64 Linux gnu and musl, aarch64 Linux, armv7, x86_64 Apple, aarch64 Apple, Windows MSVC, and an Android arm64 build. |
| P17.1.03 | Publish `SHA256SUMS` for every artefact and sign the release with `minisign`. |
| P17.1.04 | Generate shell completions with `clap_complete` at build time and ship them. |
| P17.1.05 | Generate man pages with `clap_mangen`. |
| P17.1.06 | Fix `install.sh` and `uninstall.sh`: setuid handling, `mktemp` log path, mode 0755 on the binary, mode 0644 on completions and man pages. |
| P17.1.07 | Emit a machine readable `pwdcrack --version --output-format json` for tooling. |

---

## 22. Traceability Matrix

Every baseline finding maps to a task.

| Finding | Task | Phase |
|---------|------|-------|
| B-01 | P1.1.01 to P1.1.04 | 1 |
| B-02 | P1.4.01, P1.4.03 | 1 |
| B-03 | P1.3.01 to P1.3.07 | 1 |
| B-04 | P1.2.01 to P1.2.07 | 1 |
| B-05 | P1.5.01 to P1.5.03 | 1 |
| B-06 | P0.1.01 | 0 |
| B-07 | P0.1.02 | 0 |
| B-08 | P0.1.03 | 0 |
| B-09 | P0.1.04, P0.1.08 | 0 |
| B-10 | P0.1.05 | 0 |
| B-11 | P0.1.06 | 0 |
| B-12 | P0.1.07 | 0 |
| B-13 | P4.1.01 to P4.3.04 | 4 |
| B-14 | P5.1.01 to P5.1.05 | 5 |
| B-15 | P5.3.01, P5.3.02 | 5 |
| B-16 | P6.2.01 to P6.2.08 | 6 |
| B-17 | P7.1.01 to P7.1.05 | 7 |
| B-18 | P7.2.01 | 7 |
| B-19 | P3.3.01 | 3 |
| B-20 | P7.4.01, P7.4.02 | 7 |
| B-21 | P16.0.01, engine-jit row | 16 |
| B-22 | P3.3.02 | 3 |
| B-23 | P16.0.01, P16.0.02 | 16 |
| B-24 | P2.2.03, P2.2.04 | 2 |
| B-25 | P2.2.04, P2.2.05 | 2 |
| B-26 | P2.1.04 | 2 |
| B-27 | P2.3.01, P2.3.02 | 2 |
| B-28 | P12.1.06 | 12 |
| B-29 | P0.3.06 | 0 |
| B-30 | P10.1.01 to P10.1.07 | 10 |
| B-31 | P9.1.01 to P9.1.06 | 9 |
| B-32 | P9.1.05 | 9 |
| B-33 | P12.1.01, P12.1.02 | 12 |
| B-34 | P14.2 | 14 |
| B-35 | P14.3 | 14 |
| B-36 | P11.1.05 | 11 |
| B-37 | P0.3.01 | 0 |
| B-38 | P0.3.02 | 0 |
| B-39 | P0.3.03 | 0 |
| B-40 | P0.3.03 | 0 |
| B-41 | P0.3.04 | 0 |
| B-42 | P0.3.05 | 0 |
| B-43 | P15.1, P15.2 | 15 |
| B-44 | P2.3.04 | 2 |
| B-45 | P1.3.04, P1.3.05 | 1 |

---

## 23. Risk Register

| ID | Risk | Likelihood | Impact | Mitigation |
|----|------|-----------|--------|------------|
| R-01 | GPU kernels silently disagree with the reference, producing wrong cracks | High | Critical | Mandatory differential test per shader, per kernel, in CI. No exception. |
| R-02 | A multi buffer kernel has an endianness or padding bug that only triggers on specific input lengths | Medium | Critical | Differential test with lengths 0 through 200 plus every power of two boundary. |
| R-03 | Removing the unix crypt hang exposes incorrect hash output that was previously hidden by the hang | High | High | Differential test against `openssl passwd` in Phase 1.1 before shipping. |
| R-04 | Feature matrix growth makes CI slow enough that developers stop running it | Medium | Medium | Cache cargo builds, run the full matrix nightly, run a 5 combination subset per push. |
| R-05 | Adding a dependency for a missing hash algorithm introduces a build script or unsafe code | Medium | Medium | Dependency policy in P14.1.06. Prefer pure Rust. Audit in CI. |
| R-06 | FPGA changes cannot be validated without hardware | High | Medium | Simulation only in CI. Publish utilisation reports from real runs separately. Mark hardware only gates clearly. |
| R-07 | TLS in the distributed engine breaks compatibility with existing workers | Medium | Medium | Version the protocol. Ship the upgrade path in the release notes. |
| R-08 | Token auth in the web engine breaks users who relied on the open dashboard | Low | Low | Document the change prominently in the release notes. Provide a documented override flag. |
| R-09 | Engine deletion removes a feature someone depended on | Low | Medium | Publish a migration table in the release notes listing each deleted engine and its replacement. |
| R-10 | Scope growth causes phases to be partially completed, leaving the codebase in a worse state than before | High | High | Phase gates are pass or fail. A partially completed phase is not released. |

---

## 24. Definition of Done

A phase is complete only when all of the following hold:

1. Every task identifier in that phase is closed with a commit.
2. The phase gate command exits 0.
3. The baseline findings assigned to that phase in the traceability matrix are fixed and covered by a regression test.
4. No new finding is introduced: the CI matrix, the differential tests, and the fuzz targets all pass.
5. `README.md`, `ARCHITECTURE.md`, and any engine documentation describe the new state accurately.
6. No em dash appears anywhere in the changed text.

The project reaches v2.0.0 when Phases 0 through 15 are closed, Phase 16 has resolved every engine decision, and Phase 17 has shipped.

---

## 25. Suggested Execution Order

| Order | Phase | Rationale |
|-------|-------|-----------|
| 1 | Phase 0 | Nothing compiles or runs correctly without it |
| 2 | Phase 1 | Correctness first. A fast wrong answer is worthless |
| 3 | Phase 2 | Attacks are the user facing value |
| 4 | Phase 3 | The trait must exist before engines are rewritten |
| 5 | Phase 4 | SIMD gives the largest immediate win on every machine |
| 6 | Phase 5 | GPU is the largest win on discrete hardware |
| 7 | Phase 6 | CUDA for NVIDIA installs |
| 8 | Phase 7 | OpenCL, Metal, Vulkan for the remaining GPU vendors |
| 9 | Phase 8 | FPGA is long lead time hardware work |
| 10 | Phase 9 | Distributed builds on the engine trait |
| 11 | Phase 10 to 11 | Web and bridges consume the core library |
| 12 | Phase 12 | Platform politeness |
| 13 | Phase 13 | Polish once behaviour is stable |
| 14 | Phase 14 | Security review |
| 15 | Phase 15 | Full test and benchmark suite |
| 16 | Phase 16 | Honest engine inventory |
| 17 | Phase 17 | Release |

Phases 8, 9, 10, and 11 may run in parallel with 5 and 6 once Phase 3 is green, provided each has its own differential test harness.

---

## Appendix A: New Files Created by This Plan

```
src/engine/mod.rs                 Engine trait
src/engine/planner.rs             Work splitter
src/engine/merge.rs               Result merger
src/engine/capability.rs          Capability enum
src/attack/mask.rs                Single source of truth for masks
src/attack/session.rs             Checkpoint format
src/hash/reference/               Golden reference implementations
src/platform/mod.rs               Platform services facade
src/bin/pwdcrack-bench.rs         Benchmark CLI
engines/engine-gpu/build.rs       WGSL compile time validation
engines/engine-cuda/build.rs      CUDA PTX compile time embedding
engines/engine-fpga/rtl/sim/      Testbenches
engines/engine-fpga/rtl/tb_common.svh
tests/hash_support_matrix.rs
tests/detection_matrix.rs
tests/attack_integration.rs
tests/mask_equivalence.rs
tests/rule_equivalence.rs
tests/session_resume.rs
tests/engine_conformance.rs
tests/rules/reference.py
tests/vectors/detection_matrix.txt
tests/mask_corpus.txt
docs/HASH_SUPPORT.md
docs/RULES.md
docs/GPU_SHADERS.md
docs/FPGA_RESULTS.md
docs/OUTPUT_SCHEMA.md
docs/BENCH_REFERENCE.md
SECURITY.md
.github/workflows/build-matrix.yml
.github/workflows/security.yml
scripts/test-matrix.sh
fuzz/Cargo.toml
fuzz/targets/verify_any.rs
fuzz/targets/parse_hash.rs
fuzz/targets/apply_rules.rs
fuzz/targets/expand_mask.rs
```

## Appendix B: Reference Machine Definition

Record before any throughput measurement. Without this, targets in Section 2.2 are meaningless.

```
CPU model and core count
RAM size and speed
GPU model, VRAM, driver version
OS and kernel version
Compiler version (rustc -Vv)
Build profile and features
Wordlist used (name, size, line count)
Hashes used (count, type distribution)
```

## Appendix C: Measurement Protocol

1. Warm up for 5 seconds and discard results.
2. Run a fixed candidate count of at least 10 million, or the full wordlist.
3. Repeat 5 times and take the median.
4. Reject any run whose spread exceeds 5 percent and rerun.
5. Report candidates per second and hashes per second separately.
6. Record the exact binary hash and build flags alongside every result.

---
---

# PART 2: DEEP UPGRADE

Part 1 established correctness and made every engine honest. Part 2 raises the ceiling: smarter candidate generation, wider hash coverage, memory and I/O efficiency, and multi target strategies. Part 2 depends on Part 1 being complete for the phase it references.

## 26. Part 2 Principles

1. A faster wrong answer is worthless. Every Part 2 change must pass the Part 1 differential tests unchanged.
2. Candidate generation is the bottleneck for fast hashes; verification is the bottleneck for slow hashes. Part 2 optimises whichever side dominates per algorithm.
3. Every new attack mode must declare its keyspace before running and refuse keyspaces the machine cannot finish within a stated budget.
4. No heuristic may silently drop candidates. Heuristics change ordering and prioritisation, never coverage.
5. Memory and I/O limits are first class. A run on a 2 GB device must never allocate more than the configured budget.

---

## 27. Phase 18: Smart Candidate Generation

**Objective**: fewer candidates per second of wall clock, same coverage.

### 27.1 P18.1 Probabilistic Word Ordering

Dictionary order is currently line order. That wastes time when the correct word sits at line 90,000,000.

| Task | Action |
|------|--------|
| P18.1.01 | Build a frequency table at wordlist load time: a 64 bit frequency estimate per unique word, derived from rank order, length, character class composition, and presence of digit or symbol runs. |
| P18.1.02 | Order candidates by descending frequency using a counting sort into fixed buckets, so ordering is O(n) and cache friendly rather than a sort of 100 million entries. |
| P18.1.03 | Add `--order frequency` to every dictionary style attack, with `natural` as the default for backwards compatibility. |
| P18.1.04 | Measure the gain on a reference corpus: the median position of a correct password in a frequency ordered pass must fall below 5 percent of the wordlist for the top 1000 most common passwords. |
| P18.1.05 | Persist the ordering as an optional sidecar index file keyed by wordlist content hash, so a second run skips the build. |

### 27.2 P18.2 Rule Prioritisation

| Task | Action |
|------|--------|
| P18.2.01 | Measure the yield of every rule in `hob0.rule` and `best64.rule` against a labelled corpus of known password transformations. |
| P18.2.02 | Order rules by measured yield per unit cost. A rule that produces 10x more candidates for 5 percent more hits is moved later. |
| P18.2.03 | Implement early rule pruning: skip rules whose output length exceeds the observed hash input constraints, where the constraint is known. |
| P18.2.04 | Add `--rule-budget N` to stop after N rules and report the remaining rule count, so a user can bound a run precisely. |

### 27.3 P18.3 Candidate Deduplication

| Task | Action |
|------|--------|
| P18.3.01 | Many rules produce identical candidates from identical words. Deduplicate with a Bloom filter sized to 2 bits per expected candidate, with a target false positive rate of 1e-6. |
| P18.3.02 | The filter is per thread, sized to the thread chunk, and merged at chunk boundaries. No lock contention. |
| P18.3.03 | Measure: for `hob0.rule` over a 1 million word corpus, report the duplicate ratio before and after. Target: remove at least 40 percent of redundant verifications. |
| P18.3.04 | The filter must never be consulted for a hash type that is memory hard, since the duplicate ratio is already negligible there and the memory is better spent on the hash state. |

### 27.4 P18.4 Structural Mask Generation

| Task | Action |
|------|--------|
| P18.4.01 | Implement pattern templates: given a corpus of passwords, extract the most common structural shapes such as `Word+123`, `Word+!`, `Word+Year`, `Word+Digit+Digit`. Represent each as a mask with named tokens. |
| P18.4.02 | Generate a mask set from the corpus, score each mask by frequency, and order by descending expected yield. |
| P18.4.03 | Expose this as `pwdcrack suggest --shapes` so a user can see the recommended mask list for their target domain. |
| P18.4.04 | Merge masks that are subsets of others, so `?d?d?d?d` is not also run when `?d?d?d?d?d?d` is already scheduled. |
| P18.4.05 | Correctness rule: shape generation only reorders. The union of all masks it produces must cover the same keyspace as the explicit mask list it replaced, or the run must declare the difference. |

### 27.5 P18.5 Token and Separator Injection

| Task | Action |
|------|--------|
| P18.5.01 | Precompute common separators: none, space, dot, underscore, hyphen, digit runs 0 to 4, symbol runs from a fixed list. |
| P18.5.02 | Generate two word combinations joined by a separator, which covers a large class of real passwords that pure concatenation misses. |
| P18.5.03 | Bound the expansion: refuse a separator set that multiplies the keyspace beyond the configured budget, and report what was dropped. |

### 27.6 P18.6 PRINCE Upgrade

| Task | Action |
|------|--------|
| P18.6.01 | Implement the full PRINCE chain length range 1 to 8 with an embedded element table per length, replacing the current element wise pair logic. |
| P18.6.02 | Implement probability based element selection: extend short elements first, since they occur more often, using the frequency table from P18.1. |
| P18.6.03 | Guarantee completeness: assert in tests that for a 100 word corpus and chain length 2, every ordered pair appears exactly once. |
| P18.6.04 | Measure throughput in candidates per second and report it. Target: 20 million candidates per second per core for the length 2 case. |

---

## 28. Phase 19: Memory and I/O Efficiency

**Objective**: fit large wordlists and many hashes into small devices, and stop paying for I/O in the inner loop.

### 28.1 P19.1 Wordlist Streaming

| Task | Action |
|------|--------|
| P19.1.01 | Replace per line allocation in the dictionary loop with a reusable byte buffer. No `String` allocation per candidate unless the candidate survives into a result. |
| P19.1.02 | Implement a block reader that reads 4 MB, yields lines by scanning for newlines, and reuses the buffer across chunks. |
| P19.1.03 | Support newline variants: LF, CRLF, and lone CR, detected during the first block. |
| P19.1.04 | Skip and count comment lines starting with `#` when the wordlist is not explicitly marked as raw, and report the count in the summary. |
| P19.1.05 | Target: dictionary throughput improvement of at least 1.5x with no change in verification count. |

### 28.2 P19.2 Hash File Handling

| Task | Action |
|------|--------|
| P19.2.01 | Hash files are small, so load them fully, but parse once into a typed structure instead of re parsing per candidate. Today parsing happens inside the verify loop. |
| P19.2.02 | Group hashes by type so a candidate is compared against all hashes of one type without a branch per hash. |
| P19.2.03 | For a mixed type file, run one pass per type group rather than one pass per candidate across all types. Cost model: pass count equals distinct type count, not hash count. |
| P19.2.04 | Target: for a file of 10,000 mixed hashes, wall clock improvement of at least 4x when grouped by type. |

### 28.3 P19.3 Memory Budget Enforcement

| Task | Action |
|------|--------|
| P19.3.01 | Add a memory accountant that tracks estimated resident bytes for the wordlist buffer, hash set, rule engine state, and per thread state. |
| P19.3.02 | `--low-mem` sets a 256 MB budget. The accountant reduces the wordlist block size first, then the Bloom filter density, then the per thread stack, and reports every reduction. |
| P19.3.03 | Refuse to start when the fixed cost alone exceeds the budget, and print the required minimum. |
| P19.3.04 | Add `--max-memory MB` so a user can cap the process explicitly. Verify with `getrusage` in a test. |

### 28.4 P19.4 Huge Pages and Pinning

| Task | Action |
|------|--------|
| P19.4.01 | Request transparent huge pages for the wordlist mapping via `madvise(MADV_HUGEPAGE)`. Report whether the request was honoured by reading `/proc/self/smaps`. |
| P19.4.02 | For the candidate buffer, use `mlock` when the budget allows, so the hot buffer is never paged out under memory pressure. |
| P19.4.03 | Measure the TLB miss reduction and report it. TLB misses are the dominant cost once the inner loop is buffer bound. |

---

## 29. Phase 20: Multi Target Strategy

**Objective**: crack many hashes in one pass instead of one pass per hash.

### 29.1 P20.1 Grouped Verification

| Task | Action |
|------|--------|
| P20.1.01 | Implement a prefilter: for each hash, store a cheap discriminant such as length, and a 64 bit bloom of its digest bytes at fixed offsets. A candidate is compared against the real hash only when the discriminant can match. |
| P20.1.02 | For MD5, use a SIMD gather to test 8 candidate digests against 8 stored prefilter words simultaneously. |
| P20.1.03 | Measure: for 10,000 hashes of one type, verification cost per candidate must fall by at least 8x. |
| P20.1.04 | The prefilter must be proven lossless: a differential test asserts that no true match is ever discarded. |

### 29.2 P20.2 Per Type Scheduling

| Task | Action |
|------|--------|
| P20.2.01 | Cost each hash type by its measured cost per verification. Slow types such as bcrypt cost 12, Argon2id, and scrypt should be spread across all engines and allowed the longest wall clock. |
| P20.2.02 | For fast types such as MD5 and SHA-1, use the largest batch the memory budget permits. |
| P20.2.03 | When the file mixes a 1 millisecond hash with a 1 microsecond hash, run two independent passes on two engine pools rather than one mixed pass. The mixed pass wastes the slow hash's cost on every candidate of the fast one. |
| P20.2.04 | Report the schedule in the run summary so the user understands the ordering. |

### 29.3 P20.3 Early Exit Optimisation

| Task | Action |
|------|--------|
| P20.3.01 | For algorithms with a cheap incremental property, such as unix crypt, compare the first bytes of the derived hash before running the full derivation. Verify the early exit cannot accept a false positive. |
| P20.3.02 | Apply the same idea to bcrypt by comparing the first 2 of 23 output bytes before the remaining comparison. |
| P20.3.03 | Measure and report. This is the one place where an early exit is safe: the bytes compared are the bytes that differ, and the comparison remains constant time over the compared prefix. |

---

## 30. Phase 21: Fault Tolerance and Long Run Stability

**Objective**: a run that survives a flaky node and a machine that does not overheat.

### 30.1 P21.1 Checkpoint Durability

| Task | Action |
|------|--------|
| P21.1.01 | Write the checkpoint with a CRC and a monotonically increasing sequence number. |
| P21.1.02 | Retain the last three checkpoints and rotate, so a torn write from a power loss can be recovered from the previous generation. |
| P21.1.03 | Test by truncating a checkpoint file at every byte offset and asserting that the loader either accepts a valid state or rejects cleanly. No panic. |

### 30.2 P21.2 Engine Health Monitoring

| Task | Action |
|------|--------|
| P21.2.01 | Every engine reports a heartbeat with its last completed chunk index. A chunk that exceeds 3x the median chunk time marks the engine degraded. |
| P21.2.02 | A degraded engine is removed from the planner and its work is requeued. The removal is logged and appears in the summary. |
| P21.2.03 | A dead engine triggers an immediate requeue and a warning that names the engine and the chunk range affected. |

### 30.3 P21.3 Thermal and Power Adaptive Throttling

| Task | Action |
|------|--------|
| P21.3.01 | Build a controller that reads temperature and the configured wattage budget each second, then computes a target duty cycle. |
| P21.3.02 | Apply the duty cycle by sleeping a computed fraction of each chunk period, not by reducing thread count, so the thread pool stays intact. |
| P21.3.03 | Ramp the duty cycle up and down gradually. A step change in load is what triggers thermal throttling in the first place. |
| P21.3.04 | Report the duty cycle over the run so the user can see the tool respecting the budget. |

### 30.4 P21.4 Deterministic Replay

| Task | Action |
|------|--------|
| P21.4.01 | Record the exact engine assignment per chunk in the checkpoint. |
| P21.4.02 | A resumed run replays the recorded assignment, so a resumed run tests exactly the same candidate to engine mapping as the original. |
| P21.4.03 | This makes a resumed run comparable to the uninterrupted run in the differential tests, which is how a bug in resume logic becomes visible. |

---

## 31. Phase 22: Additional Hash Family Coverage

**Objective**: cover the hash types users actually meet, at reference correctness.

Part 1 defines the mechanism. Part 2 enumerates the coverage target.

### 31.1 P22.1 Coverage Targets

| Group | Types | Verification source |
|-------|-------|---------------------|
| Password hashing, memory hard | bcrypt, Argon2i, Argon2d, Argon2id, scrypt, PBKDF2 (HMAC SHA-1, SHA-256, SHA-512, SHA-3), yescrypt | Reference vectors from the algorithm authors |
| Unix and legacy | md5crypt, sha256crypt, sha512crypt, DES crypt, BSDi crypt, Sun MD5 | `openssl passwd` and the crypt(3) test vectors |
| Windows | NTLM, LM, NetNTLMv2 response, Cache, DCC, DCC2, MSCHAPv2, EPi | Published implementations and Kerberos RFC documents |
| Web and application | SHA-1, SHA-256, bcrypt variants, PBKDF2, WordPress phpass, phpBB, Joomla, vBulletin, Django, MySQL 4.1 and 5.x, Oracle 7 to 12c, SAP CODVN A to F | Project test fixtures |
| Network and appliance | Cisco type 5, type 7, type 8, Juniper MD5 and SHA, RADIUS PAP, CHAP, MSCHAP, TACACS+, 3DES, DES, SNMP community | Vendor documentation |
| Database | Oracle O5, OCI, SYSDBA, DB2, Firebird, Sybase, Informix, MySQL old, PostgreSQL md5 and scrypt | Database documentation |
| Cryptographic digest | MD2, MD4, MD5, MD6, SHA-0, SHA-1, SHA-2 family, SHA-3 family, BLAKE2b, BLAKE2s, BLAKE3, Keccak, Whirlpool, RIPEMD family, Tiger, Tiger2, Skein, JH, Shabal, Streebog 256 and 512, GOST 94, GOST R 34.11, SM3, HAS-160, Skein256, Skein512, BLAKE2bp, BLAKE2sp | RFC documents and the reference implementation in `src/hash/reference/` |
| Checksum and non cryptographic | CRC8, CRC16, CRC32, CRC32C, CRC64, Adler-32, Fletcher, BSD and SysV sums | Documented definitions, clearly labelled as non cryptographic |

### 31.2 P22.2 Implementation Rules Per Type

| Task | Action |
|------|--------|
| P22.2.01 | Every type gets: a parser, a verifier, a test vector file, and an entry in `docs/HASH_SUPPORT.md`. |
| P22.2.02 | Cost every verifier: MD5 class under 1 microsecond per candidate, bcrypt cost 12 under 300 milliseconds per candidate. Store the measured value and use it in the scheduler cost model. |
| P22.2.03 | Memory hard types must never be batched on a GPU unless the GPU has the memory. Argon2 and scrypt are excluded from the GPU engines by default and enabled only with an explicit `--gpu-memory-hard` flag after a memory feasibility check. |
| P22.2.04 | Non cryptographic checksums are labelled in `pwdcrack list` and in all output as invertible, so a user does not mistake a CRC32 result for a security finding. |
| P22.2.05 | For types where multiple encodings exist, such as hex, base64, and raw binary in a file, the parser records the encoding so the verifier consumes bytes, not text. |

### 31.3 P22.3 Encoding Handling

| Task | Action |
|------|--------|
| P22.3.01 | Support hex with both cases, hex with a 0x prefix, base64 standard and URL safe with and without padding, raw binary lines of a known length, and custom base64 alphabets for appliances. |
| P22.3.02 | Detect and strip a `user:hash` or `hash:password` prefix, and report which side was detected. Ambiguity here is a correctness issue, not a display issue. |
| P22.3.03 | Normalise a `$id$salt$hash` unix crypt format carefully: the salt may contain `$` in some implementations, so the split must be from the correct end. Write a test for a salt containing each legal character. |

---

## 32. Phase 23: Observability

**Objective**: a user can always answer "what is it doing, why is it slow, and is it correct".

### 32.1 P23.1 Run Reporting

| Task | Action |
|------|--------|
| P23.1.01 | Emit a machine readable run report: `target_hashes`, `types_found`, `candidates_tested`, `hashes_tested`, `cracked`, `elapsed_seconds`, `hashes_per_second`, `duty_cycle`, `engines_used`, `chunk_count`. |
| P23.1.02 | Emit the same report as text with a compact table, and as JSON with `--format json`. |
| P23.1.03 | Add `pwdcrack verify --report <file>` to persist a report for later comparison. |

### 32.2 P23.2 Engine Introspection

| Task | Action |
|------|--------|
| P23.2.01 | Add `pwdcrack doctor` that prints, per hash type, the selected engine, the measured hashes per second, the batch size, and the reason for the selection. |
| P23.2.02 | Add `pwdcrack doctor --json` for tooling. |
| P23.2.03 | The doctor command must never claim an engine is active when it is falling back to CPU. It prints `fallback` explicitly. |

### 32.3 P23.3 Correctness Reporting

| Task | Action |
|------|--------|
| P23.3.01 | Report the detection confidence for each identified hash. Low confidence is surfaced so a user can investigate before committing compute. |
| P23.3.02 | Report how many hashes were skipped by the prefilter and how many were ambiguous. |
| P23.3.03 | Any hash that could not be parsed is reported with the reason and the byte offset, never dropped silently. |

---

## 33. Part 2 Traceability

| Part 1 dependency | Part 2 phase | Note |
|--------------------|---------------|------|
| Phase 2 mask module | Phase 18 shape generation | shapes must reuse the single mask source of truth |
| Phase 2 rule engine | Phase 18 rule prioritisation | yield measurement feeds the rule order |
| Phase 3 planner | Phase 20 per type scheduling | planner holds the cost model |
| Phase 4 SIMD kernels | Phase 20 prefilter | prefilter uses SIMD gather |
| Phase 5 GPU shaders | Phase 22 memory hard exclusion | GPU excludes Argon2 and scrypt by default |
| Phase 12 power module | Phase 21 duty cycle controller | duty cycle replaces governor writes |
| Phase 15 benchmarks | Phase 21 replay | replay makes resume comparable in tests |

## 34. Part 2 Acceptance Gates

| Phase | Gate |
|-------|------|
| 18 | Dictionary over the reference corpus finds the planted passwords at or below the 5 percent frequency rank, and the duplicate removal ratio is reported |
| 19 | Dictionary throughput is at least 1.5x baseline, mixed hash file is at least 4x baseline, and low-mem mode stays under 256 MB as measured by `getrusage` |
| 20 | Ten thousand single type hashes verify at least 8x faster with the prefilter, and the prefilter differential test shows zero true matches discarded |
| 21 | A resumed run produces the same candidate set as an uninterrupted run, and a simulated hot engine is removed and requeued without losing a chunk |
| 22 | Every type in the coverage table has a parser, a verifier, a vector file, and a support document entry, and `pwdcrack list` reports measured cost per type |
| 23 | `pwdcrack doctor` reports a real engine and a real rate for every available engine, and the run report validates against the documented schema |

## 35. Part 2 Effort and Sequencing

| Phase | Depends on | Can run in parallel with |
|-------|-------------|--------------------------|
| 18 | Phase 2 | 19 |
| 19 | Phase 2 | 18, 22 |
| 20 | Phase 3, 4 | 21 |
| 21 | Phase 12 | 20 |
| 22 | Phase 1 | 19 |
| 23 | Phase 15 | 20, 21 |

Part 2 releases as v2.1.0 when Phases 18 through 23 gates pass. Part 1 releases as v2.0.0 when its gates pass.

## 36. Part 2 New Files

```
src/attack/shapes.rs                Structural mask generation
src/attack/frequency.rs             Word frequency table and ordering
src/attack/dedup.rs                 Bloom filter candidate deduplication
src/attack/prefilter.rs             Lossless hash prefilter
src/attack/cost.rs                  Per type cost model
src/platform/duty.rs                Thermal and power duty cycle controller
src/platform/memory.rs              Memory budget accountant
src/replay.rs                       Deterministic chunk assignment record
src/hash/encoding.rs                Hex, base64, raw binary, user prefix parsing
tests/frequency_rank.rs             Frequency ordering effectiveness
tests/dedup_lossless.rs             Dedup filter never drops a true match
tests/prefilter_lossless.rs         Prefilter never drops a true match
tests/replay_equivalence.rs         Resumed run equals uninterrupted run
tests/engine_health.rs              Degraded engine requeue
tests/memory_budget.rs              Low mem mode stays under budget
docs/HASH_SUPPORT.md                Per type support and cost table
docs/RUN_REPORT.md                  Run report schema
docs/COVERAGE.md                    Coverage table and status per type
```

## 37. Closing Statement on Accuracy and Power

The purpose of Part 2 is a tool that is measurably faster on the hashes that matter, and measurably broader on the hashes users meet. Every claim in this document is a number that a command in the repository can check. Where the current code cannot deliver a claim, the claim is scoped down to what the current code can deliver, and the gap is written down rather than hidden.

