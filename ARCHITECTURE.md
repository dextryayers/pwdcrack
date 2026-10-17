# pwdcrack Architecture

This document describes the code that exists in this repository today. Intended
structure and future work live in `docs/plan.md`; nothing here is aspirational.

Every path and symbol below was checked against the source. Where a component is
incomplete, that is stated plainly rather than implied.

---

## 1. Workspace Layout

`Cargo.toml` declares a Cargo workspace with the root crate plus 26 member
crates under `engines/`. The root crate builds two artefacts:

```toml
[lib]
crate-type = ["lib", "cdylib"]
name = "pwdcrack"
```

- `libpwdcrack.rlib` for Rust consumers
- `libpwdcrack.so` / `.dylib` / `.dll` for the C ABI in `engines/engine-bridge`

The CLI binary `pwdcrack` is built from `src/main.rs`, which declares its own
`mod cli` rather than using the library's CLI module. The library therefore
exposes `hash`, `attack`, and `potfile` only.

### Root Crate Modules

| Path | Responsibility |
|------|----------------|
| `src/main.rs` | Entry point. Argument routing, the 18 command handlers, output formatting, exit codes. |
| `src/cli/args.rs` | clap derive definitions: `Cli` struct, global options, the `Commands` enum. |
| `src/cli/mod.rs` | Re-exports `Cli` and `Tier`. |
| `src/hash/mod.rs` | `HashType` enum (354 variants), `HashEntry`, the `HashCracker` and `HashParser` traits, helpers. |
| `src/hash/audit.rs` | Tests that enforce the detection versus verification distinction. See `docs/HASH_TYPES.md`. |
| `src/hash/detector.rs` | `Detector`: the registry of cracker instances plus `detect`, `identify`, `cracker_for_type`. |
| `src/hash/raw.rs` | Raw digest verifiers: MD5, SHA-1, SHA-2, NTLM, and similar. |
| `src/hash/raw_ext.rs` | Extended digest verifiers: BLAKE2, BLAKE3, RIPEMD, Whirlpool, Streebog, Tiger, Skein, JH, Shabal, GOST, SM3, Groestl. |
| `src/hash/app.rs` | Application format verifiers: PBKDF2, HMAC variants, NTLMv1, SAP CODVN, and others. |
| `src/hash/unix.rs` | `$1$`, `$5$`, `$6$` crypt implementations. |
| `src/hash/bcrypt_.rs` | bcrypt verification. |
| `src/hash/argon2_scrypt.rs` | Argon2 and scrypt verification. |
| `src/attack/mod.rs` | `CrackResult`, `ProgressStats`. |
| `src/attack/dictionary.rs` | Wordlist pass with optional rule application. |
| `src/attack/brute.rs` | Mask parsing, keyspace iteration, brute force. |
| `src/attack/combinator.rs` | Two-wordlist concatenation. |
| `src/attack/prince.rs` | PRINCE candidate generation. |
| `src/attack/toggle.rs` | Case toggle candidates. |
| `src/attack/substitute.rs` | Leet and symbol substitution. |
| `src/attack/rules/engine.rs` | John and Hashcat style rule parsing and application. |
| `src/potfile.rs` | Potfile load, save, and lookup. |
| `src/tests.rs` | Unit tests for detection and verification. |

---

## 2. Verification Flow

```
hash line
   |
   v
Detector::detect(line)
   |  iterates registered parsers, returns the first that parses
   v
(Box<dyn HashCracker>, HashEntry)
   |
   v
cracker.verify(candidate, &entry)
   |
   v
true  -> CrackResult { original, hash_type, password }
```

`Detector::new()` builds the registry once. `Detector::detect` is then a linear
scan over that registry, first match wins. This is a known weakness: several
parsers accept any input of a given length, so ambiguous lengths resolve by
registration order rather than by evidence. See `docs/plan.md` Phase 1 for the
replacement design.

### Detected Versus Verified

Not every detected type has a real verifier. A number of types are registered so
they can be identified and reported, but their `verify` returns `false`. Running
`pwdcrack list` shows which entries exist; `docs/plan.md` tracks the work to
implement the remainder.

---

## 3. Attack Flow

All attack modules share this shape:

1. `load_hashes` reads the hash file and produces `(cracker, HashEntry)` pairs.
2. The attack module iterates candidates, usually with `rayon` for parallelism.
3. Each candidate is tested against every loaded hash.
4. Matches become `CrackResult` values.
5. `emit_results` writes to the potfile and to stdout or `--output`.

Common signature shape:

```rust
pub fn run_dictionary(
    hashes: &[HashEntry],
    cracker: &dyn HashCracker,
    wordlist_path: &str,
    rules_path: Option<&str>,
    _threads: usize,
    quiet: bool,
    low_mem: bool,
) -> Vec<CrackResult>
```

Note that the attack modules take a single `&dyn HashCracker` together with the
hashes it owns, rather than per-hash crackers. Grouping a mixed type file by
type therefore happens in the caller. See `group_by_cracker` in
`engines/engine-bridge/src/python.rs` for the reference implementation of that
grouping.

### Mask Syntax

`brute.rs` supports `?l`, `?u`, `?d`, `?s`, `?a`, `?h`, `?H`, `?b`, and the custom
placeholders `?1` through `?4`. Placeholder parsing is duplicated between
`brute.rs` and the `mask` and `expand` commands; consolidating it is planned work.

---

## 4. Feature Tiers

Defined in the root `Cargo.toml`:

| Feature | Enables |
|---------|---------|
| `default` | `tier-auto` |
| `tier-low` | `simd-scalar`, `io-stream`, `progress-simple` |
| `tier-mid` | `simd-detect`, `mmap`, `progress-rich` |
| `tier-high` | `tier-mid` plus `huge-pages`, `engine-gpu`, `engine-power` |

Each `engine-*` feature maps to an optional path dependency on the matching crate
under `engines/`. Enabling an engine adds it as a dependency; it does not by
itself make the engine functional.

---

## 5. Engine Crates

Twenty five crates live under `engines/`. Their real state:

| Crate | State |
|-------|-------|
| `engine-simd` | CPU feature detection via `raw-cpuid`. The x86 and ARM kernels wrap scalar code; SHA-NI and AVX2 intrinsics are not implemented. |
| `engine-gpu` | wgpu backend with WGSL compute shaders. Some shaders load and dispatch; most of the 31 shader files are unused. Adapter memory is hardcoded rather than queried. |
| `engine-jit` | Cranelift mask compiler produces real machine code. The rule compiler is a placeholder that falls back to an interpreter. |
| `engine-power` | Reads Intel RAPL, AMD hwmon, GPU power, cpufreq governor, battery, and C-states from sysfs. Writes sysfs values, which needs root. |
| `engine-fpga` | PCIe DMA transport to `/dev/fpga0`, a packet protocol with CRC32, and SystemVerilog cores with testbenches. RTL is unverified against a reference. |
| `engine-distributed` | tokio TCP master and worker with a JSON protocol, heartbeats, and work requeue. No authentication, binds all interfaces by default. |
| `engine-web` | axum dashboard with REST routes and a WebSocket ticker. Attack control routes change state only; they do not start work. No authentication, binds all interfaces by default. |
| `engine-android` | Termux detection, battery, thermal, storage access framework, notifications. |
| `engine-bridge` | C ABI is complete and null checked. Python bindings use PyO3 0.23. Perl XS and Node N-API modules are present. |
| `engine-cuda` | Device enumeration is implemented against the cudarc driver API. Kernels exist but the MD5 kernel does not compute a correct MD5 and is not launched. |
| `engine-opencl` | Device enumeration works. `crack_md5` returns `NotEnabled` unconditionally and the kernels have the same MD5 defect as CUDA. |
| `engine-vulkan` | Instance and device enumeration only. No compute pipeline. |
| `engine-metal` | On non-Apple hosts it reports devices read from a file in `/tmp`. |
| `engine-sycl` | Returns `None` with a log message. |
| `engine-tpu`, `engine-xpu`, `engine-dsp`, `engine-tensor`, `engine-warp` | Detect or simulate a device, then run scalar CPU loops. Availability reporting is not trustworthy. |
| `engine-riscv`, `engine-zen`, `engine-embedded` | Architecture detection followed by scalar CPU loops. |
| `engine-go`, `engine-julia`, `engine-wasm` | Dynamic loading stubs with no consumer. |
| `engine-hybrid` | Scheduler data structures with no execution path. |

`docs/plan.md` Phase 16 lists the intended decision for each of these.

---

## 6. Build and Release

| Script | Purpose |
|--------|---------|
| `scripts/build-all.sh` | Cross-compiles the five supported targets. |
| `scripts/build-android.sh` | Android builds with the NDK linker set up. |
| `scripts/cross-compile/android-ndk.sh` | Downloads the NDK and writes linker config. |
| `scripts/package.sh` | Stages and tars a release tree. |
| `scripts/test-all.sh` | Runs tests across the default and tier feature sets. |
| `scripts/test-matrix.sh` | Full feature combination matrix. |
| `install.sh`, `uninstall.sh` | Install to `${PREFIX:-/usr/local}`. |
| `docker/Dockerfile.{low,mid,high,android}` | Container build recipes per tier. |

Release profile settings:

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = "symbols"
panic = "abort"
```

`panic = "abort"` applies to the `cdylib` as well, which means a panic inside the
C ABI terminates the host process. Changing this is tracked in `docs/plan.md`.

---

## 7. Data Files

| Path | Contents |
|------|----------|
| `configs/pwdcrack.{low,mid,high,android}.toml` | Tier presets. No code reads these files; they are documentation only. |
| `tests/test_vectors/*.txt` | Labelled `hash:password` vectors for md5, sha1, sha256, ntlm, and bcrypt. |
| `tests/test_vectors_gen.py` | Python generator for the vector files. |
| `wordlists/download.sh` | Fetches rockyou and SecLists. Performs no checksum verification. |

---

## 8. Known Architectural Gaps

Consolidated here so a reader does not have to diff the source:

1. `Detector` resolves ambiguity by registration order rather than by evidence.
2. Mask parsing is duplicated across three call sites.
3. Flag parsing, hash loading, and result emission are duplicated across the 18
   command handlers in `src/main.rs`.
4. Attack modules take one cracker rather than a per-hash cracker.
5. No engine implements the same interface, so the scheduler cannot treat them
   uniformly.
6. Several engines report capability without measuring it.

`docs/plan.md` addresses each of these with a phased plan and acceptance gates.
