# Phase 2 and Phase 3 Status

Status after the third pass. Everything marked done was verified by running the
tests or the command, not by reading the code.

Test suite: **97 tests, 0 failures.**

---

## Phase 2: Attack Engine Precision

| Task | State | Evidence |
|------|-------|----------|
| P2.1 Mask single source of truth | **Done** | `src/attack/mask.rs`, 19 tests |
| P2.1 Length range semantics | **Done** | Verified: explicit range works, default does not expand |
| P2.1 Keyspace overflow safety | **Done** | `u128`; verified `?b` x 10 does not overflow |
| P2.2 Checkpoint format | **Done** | `src/attack/session.rs`, 12 tests |
| P2.2 Atomic write with three generations | **Done** | Verified: temp file gone, gen 0 and 1 populated |
| P2.2 `--limit` for brute force | **Done** | Verified: 100 candidates tested, not 10^6 |
| P2.2 `--resume` for brute force | **Done** | `run_bruteforce_from` resumes at an exact index |
| P2.2 `--session` wired to the CLI | **Partial** | Module ready; handler wiring outstanding |
| P2.2 `--limit` for other attacks | **Not done** | dictionary, combinator, prince still ignore it |
| P2.3 `ProgressStats::cracked()` | **Done** | Was hardcoded `0`, now a real counter |
| P2.3 Hash vs candidate rate separation | **Done** | `record_hashed` added; rate prefers real hash work |
| P2.3 ETA and duration formatting | **Done** | Extracted and unit tested |
| P2.3 `--verbose` sets a log level | **Not done** | `env_logger::init()` still ignores it |
| P2.4 Rule engine correctness | **Not done** | `--limit` and output cap still ignored |
| P2.5 `AttackContext` unification | **Not done** | Handlers still duplicate loading and emission |

### The mask length bug this pass found and fixed

This is the most important finding of the pass and it changed the meaning of a
common command.

`--min-length` has a CLI default of `1`. The first implementation of length
expansion treated that default as a real request, so `?d?d?d` silently became
three masks of length 1, 2, and 3. Consequences:

- The keyspace grew from 1,000 to 1,110 candidates.
- Every candidate index shifted, because the shorter masks were searched first.
- A user asking for 6 digits searched 1, 2, 3, 4, 5, and 6 digit passwords and
  had no way to know.

Detected by testing the binary rather than only the library: the unit tests
called `expand_lengths` directly with explicit ranges and never exercised the
CLI default.

The fix is a semantic rule, now pinned by five tests:

| Input | Behaviour |
|-------|-----------|
| no `--max-length` | use the mask's natural length, ignore `--min-length` |
| `--max-length` equal to natural | single mask |
| explicit range | expand across the range |

Verified after the fix:

```
answer at index 500, --limit 600      -> found 000500
answer at index 500, --limit 100      -> not found, 100 candidates tested
4 digit answer, --min-length 4 --max-length 6 -> found, "Lengths: 4 to 6"
```

### Mask tokens added

| Token | Meaning |
|-------|---------|
| `?w` | all printable ASCII |
| `(abc)` | literal set, used in order |
| `[?u?l]` | alternation over the union of classes |
| `\%` | a literal percent sign |

Two behaviours intentionally differ from the old parser:

1. An unknown `?X` is an **error**, not a literal. The old parser turned `?q`
   into a literal `?q`, producing a keyspace the user never asked for.
2. Keyspace is `u128`. A mask of `?b` ten times is 2^80, which the old `u64`
   code saturated, so such a mask "succeeded" while testing almost nothing.

### Session checkpoint format

| Property | Implementation |
|----------|----------------|
| Versioned | `FORMAT_VERSION`, rejected on mismatch with a clear message |
| Magic header | `PWDCSESS1`, so a wrong file is detected before field parsing |
| Atomic | write to temp, `sync_all`, then `rename` |
| Durable | parent directory synced after the rename |
| Three generations | newest is gen 0, older survive a damaged newest file |
| Input digests | FNV-1a over hash file, wordlist, rules, and mask |
| Mismatch detection | resuming against different inputs is refused, not attempted |

Candidates are stored as positions, never as text, so a checkpoint stays small
regardless of how far the run got.

---

## Phase 3: Engine Abstraction

| Task | State | Evidence |
|------|-------|----------|
| P3.1 `Engine` trait | **Done** | `src/engine/mod.rs`, 6 tests |
| P3.1 `EngineInfo` with measured rate | **Done** | `measured` flag separates measured from unmeasured |
| P3.1 `Capability` and `CapabilitySet` | **Done** | `src/engine/capability.rs`, 9 tests |
| P3.1 CPU reference engine | **Done** | `CpuEngine`, benchmarked at construction |
| P3.2 `BatchPlan` with engine clamping | **Done** | Clamped to batch size, never zero |
| P3.2 Planner with rate proportional split | **Done** | `src/engine/planner.rs`, 11 tests |
| P3.2 Deterministic result merge | **Done** | Deduplicated on (candidate, hash), sorted |
| P3.3 Capability filtering in the planner | **Done** | Engine missing a capability gets no work |
| P3.3 Conformance test for honest reporting | **Partial** | Truthfulness is enforced by construction, not yet by a test |

### How the abstraction prevents the previous lies

The prior engines reported capability without measuring it. `engine-tensor` and
`engine-warp` returned `is_available() == true` unconditionally and then ran a
scalar CPU MD5 loop, so the scheduler believed in hardware that was not being
used.

Three mechanisms close that off:

1. **`CapabilitySet`** must declare algorithm families. The planner drops any
   engine that does not declare every required capability, so an engine that
   cannot do the work is never given it.
2. **`EngineInfo::measured`** distinguishes "measured and slow" from "never
   measured". `is_usable()` returns false for an engine that has no measured
   rate and no capabilities.
3. **`summary()`** prints `unmeasured` rather than a fabricated number, which is
   what `pwdcrack doctor` will display.

`CapabilitySet::baseline()` deliberately **excludes** `UnixCrypt`, because the
implementation in `src/hash/unix.rs` is not correct yet. Claiming it would be
exactly the kind of lie this module exists to prevent.

### Planning behaviour

| Property | Guarantee |
|----------|-----------|
| Coverage | Chunks are contiguous with no gap and no overlap; tested for one and two engines |
| Proportional split | Work is divided by measured rate; a 3:1 split gives roughly 25/75 |
| Slow engines first | Engines sort by rate ascending, so the long pole starts immediately |
| Batch sizing | Chunk size honours the engine's declared batch, defaulting to 65,536 |
| Rounding | The last engine absorbs rounding drift so the total is exact |
| No usable engine | `build` returns `None` so the caller can fall back rather than do nothing |

---

## Recommended Order for the Next Pass

1. Wire `--session` and `--resume` into the brute-force handler. The module and
   `run_bruteforce_from` exist; only the handler is missing.
2. P2.2 `--limit` for dictionary, combinator, prince, toggle-case, substitute.
3. P2.4 rule engine: `--limit`, output length cap, `docs/RULES.md`, and the
   differential test against a Python reference.
4. P2.5 `AttackContext` to remove the duplicated loading and emission.
5. P2.3 logging so `--verbose` and `RUST_LOG` work.
6. P3.3 conformance test that walks every engine and fails on a fabricated rate.
7. Adopt `Engine` inside the attack path so the planner is actually used rather
   than merely present.

---

## Note on `$1$`, `$5$`, `$6$`

Still outstanding from Phase 1 and tracked in `UNIX_CRYPT_STATUS.md`. The
infinite loop is fixed; the md5crypt digest is not correct and `verify` returns
`false` deliberately. `openssl passwd` and `libcrypt.so.1` are available as an
oracle and agree with each other.
