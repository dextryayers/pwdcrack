# Phase 2 and Phase 3 Status

Status after the second pass. Everything listed as done was verified by running
the test suite or the command, not by inspection alone.

---

## Phase 2: Attack Engine Precision

| Task | State | Evidence |
|------|-------|----------|
| P2.1 Mask single source of truth | **Done** | `src/attack/mask.rs`, 14 tests pass |
| P2.1 Length range (`--min-length` / `--max-length`) | **Done** | Verified: finds `1234` at length 4, does not at length 5 |
| P2.1 Keyspace overflow safety | **Done** | `u128` arithmetic, refused rather than wrapped |
| P2.2 `--limit` honoured | **Done** for brute force | Verified: 1000 candidates on a 10^8 keyspace stops immediately |
| P2.2 `--session` / `--resume` | **Not done** | Flags are still accepted and discarded |
| P2.3 `ProgressStats::cracked()` | **Done** | Was hardcoded `0`, now a real counter. 8 tests |
| P2.3 ETA and rate formatting | **Done** | `format_rate` and `format_duration` extracted and tested |
| P2.3 `--verbose` sets a log level | **Not done** | `env_logger::init()` still ignores it |
| P2.4 Rule engine correctness | **Not done** | `--limit` and `--max-length` still ignored for rules |
| P2.5 `AttackContext` unification | **Not done** | Handlers still duplicate loading and emission |

### What P2.1 changed for users

Before this pass, mask support was:

```
?l ?u ?d ?s ?a ?h ?H ?b ?1 ?2 ?3 ?4
```

Now it also covers:

| Token | Meaning |
|-------|---------|
| `?w` | all printable ASCII |
| `(abc)` | literal set, used in order |
| `[?u?l]` | alternation over the union of classes |
| `\%` | a literal percent sign |

Two behaviours are deliberately different from the old code:

1. **An unknown `?X` is an error, not a literal.** The old parser turned `?q`
   into a literal `?q`, which produced a keyspace the user never asked for. In a
   cracking tool a silently wrong keyspace means a silently incomplete run.
2. **Keyspace is computed in `u128`.** A mask like `?b?b?b?b?b?b?b?b` is 2^64.
   The old `u64` code saturated, so such a mask would have finished "successfully"
   after testing almost nothing.

### Tests added

`src/attack/mask.rs`, 14 tests:

- parses classes and literals
- unknown token is an error not a literal
- keyspace of common masks
- huge keyspace does not overflow
- last position varies fastest
- literals do not consume keyspace digits
- preview respects keyspace bound
- custom charsets are used
- literal range expands
- question mark inside a range is a literal byte
- alternation unions classes
- escaped percent is literal
- length expansion grows the keyspace
- preview of expanded range covers each length

`src/attack/mod.rs`, 8 tests covering the counters, ETA, and both formatters.

Full suite: 54 tests, 0 failures.

### Defects found and fixed while writing P2.1

The new mask code initially had three bugs that the tests caught, all in the
candidate ordering and range parsing. They are listed here because they show the
value of the tests rather than the code:

1. Literals were emitted in reverse order, so `pw?d` produced `wp0`.
2. The `(...)` range slice started one byte late, so `(?abc)` captured `a, c`
   and skipped `b`.
3. The `?`-prefix heuristic inside `(...)` assumed `?X` pairs and stepped two
   bytes at a time, dropping every character at an odd offset.

---

## Phase 3: Engine Abstraction

| Task | State |
|------|-------|
| P3.1 `Engine` trait | **Not done** |
| P3.1 `EngineInfo` and `Capability` | **Not done** |
| P3.2 Planner and merger | **Not done** |
| P3.3 Honest capability reporting | **Partially done in Phase 0** |

Phase 3 depends on Phase 2 being complete enough that a single engine
interface can serve every attack path. `--session`, `--resume`, and `--limit`
for the dictionary, combinator, PRINCE, toggle-case, substitution, and rules
paths are still outstanding, so Phase 3 has not been started.

---

## Recommended Order for the Next Pass

1. P2.2 session checkpoint and resume. This is the largest remaining user
   visible gap: two CLI flags are documented and do nothing.
2. P2.4 rule engine: implement `--limit`, add `docs/RULES.md`, add the
   differential test against a Python reference.
3. P2.5 `AttackContext`, which removes the duplicated loading and emission code
   from the handlers in `src/main.rs`.
4. P2.3 logging, so `--verbose` and `RUST_LOG` work.
5. Only then Phase 3, because the engine trait should be introduced once the
   attack paths have a single shape.

---

## Note on `$1$`, `$5$`, `$6$`

Still outstanding from Phase 1 and tracked in `UNIX_CRYPT_STATUS.md`. The
infinite loop is fixed; the md5crypt digest is not correct and `verify` returns
`false` deliberately. `openssl passwd` and `libcrypt.so.1` are available as an
oracle and agree with each other.
