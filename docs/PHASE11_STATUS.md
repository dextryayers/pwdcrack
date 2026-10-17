# Phase 11 status: bridges

What this file is: the state of the C, Python, Perl and Node surfaces in
`engines/engine-bridge`, with the numbers from the last run and nothing
estimated.

## Sub-phase results

| Task | State | Evidence |
|------|-------|----------|
| P11.1.01 Python with PyO3 types, `py.typed`, maturin | **done, verified** | wheel built by maturin, installed, 22 tests run against the installed package |
| P11.1.02 Node N-API with a promise API | **done, verified** | 16 tests in a real Node process, including that the event loop keeps running during an attack |
| P11.1.03 Perl `pwdcrack.xs` | **done, verified** | XS rewritten against the real ABI, compiled, 31 tests pass |
| P11.1.04 null safety, pointer checks, thread docs | **done, verified** | every export documents its locking, every pointer is checked before it is written |
| P11.1.05 `panic = "abort"` against `cdylib` (B-36) | **done** | removed from `[profile.release]`, with the reasoning written into `Cargo.toml` |
| P11.1.06 `crack_detect_tier`, `crack_hashes_per_second` | **done, verified** | both were constants, both now measure |
| P11.1.07 a C test suite in CI | **done, verified** | `tests/c/test_bridge.c`, 41 checks, run by `.github/workflows/bridges.yml` |

## The suites

```
scripts/test-c-bridge.sh        C bridge suite: 41 checks, 0 failures
                                panic strategy: unwind (catch_unwind works)
scripts/test-perl-bridge.sh     Files=1, Tests=31, Result: PASS
scripts/test-python-bridge.sh   Ran 22 tests ... OK
scripts/test-node-bridge.sh     # tests 16, # pass 16, # fail 0
cargo test -p engine-bridge     24 passed (c_api unit tests)
cargo test -p engine-bridge --features node
                               31 passed (24 c_api + 7 node)
```

Every suite runs a dictionary attack against a wordlist and checks the recovered
password against a digest the test computed itself, so two implementations of
MD5 agreeing is never the evidence. Two of them use
`8350c7ecc6d4706e12107df747eb6e71`, which is MD5 of
`pwdcrack-reference-candidate`, and each test recomputes it.

## P11.1.04 and P11.1.06: what the C API was

`c_api.rs` was 373 lines and had these defects. All are fixed; the list is here
because each one was invisible without a test that called the thing.

**Every attack deadlocked.** `attack_dictionary` and `attack_bruteforce` took the
global `ENGINE` lock at the top of the function and took it again at the bottom
to store the results, with the first guard still in scope. `std::sync::Mutex` is
not reentrant, so both completed the attack and then hung forever. The work was
done and the caller could not reach it.

This is why the integration tests run every attack on a worker thread with a
deadline. A test that simply called the function would hang the suite rather
than fail it, which is a bad way to find a deadlock.

**`crack_hashes_per_second` returned `0.0`.** The body was
`0.0 // Returned in real-time by the engine; static for now`. It now divides the
candidates the attack actually tested by the wall clock it actually took. For
brute force the numerator is the runner's own `tested` count, not an estimate
derived from keyspace arithmetic.

**`crack_detect_tier` returned the literal `"Auto"`.** That is a mode name, not a
detection: it said the same thing on a phone and on a workstation. It now reads
`available_parallelism` and `/proc/meminfo` and reports `"low"`, `"mid"` or
`"high"` by the thresholds written out in the doc comment.
`crack_detect_tier_detail` returns the numbers it decided with, so the
thresholds can be argued with.

**`crack_get_result` wrote through unchecked pointers.** `out_hash` and
`out_password` were dereferenced without a null check, and the function returned
0 even when only one of the two strings had been set. Both are checked before
either is written, and both are nulled first so a caller that ignores the return
code cannot read stale memory.

**`crack_version` leaked.** It used `CString::into_raw`, which transfers
ownership to the caller, while the doc comment said the caller must not free it.
Every call leaked. There are now two functions: `crack_version` returns a
process-lifetime pointer, `crack_version_owned` returns one the caller owns, and
each says which.

**Every `ENGINE.lock().unwrap()` could take down the host.** A poisoned mutex
means an earlier attack panicked while holding the lock; unwrapping it panics
again, and with `panic = "abort"` that aborts the caller's process. A C library
that can be permanently bricked by one failed call is not a library. The lock is
now recovered through `into_inner` and carried on.

**Thread safety was asserted, not documented.** The module header claimed a
"thread-safe API" while two functions held the lock for the length of an attack
that can run for hours. Each export now says whether it is serialised or
blocking, and says that the lock is not reentrant.

## P11.1.05: the profile

`[profile.release]` set `panic = "abort"` and this crate builds a `cdylib`. Three
consequences:

1. A panic anywhere in the library kills the host program. A cracker parses
   attacker-supplied hash strings, so a panic below is a thing that will
   eventually happen.
2. `catch_unwind` becomes inert, so the guard around each attack could not have
   caught anything. It would have looked like it worked.
3. An unwind crossing an FFI boundary is undefined behaviour, so abort is not
   the safe choice at an FFI edge. It is the one that removes the possibility of
   handling it.

Removed, and the reasoning is a comment in `Cargo.toml` next to the setting.
`crack_panics_abort()` reports the strategy actually in force so a caller can
see which guarantee it has, and the test that asserts the guard catches a panic
returns early under an aborting build rather than taking the process down.

## P11.1.03: the Perl binding

`pwdcrack.xs` existed, was 205 lines, and had never been compiled. It declared
an ABI that does not exist:

| declared | actual |
|----------|--------|
| `crack_load_hashes(u8*, int)` | `hash_load_file(const char *)` |
| `crack_hash_count()` | `crack_total_hashes()` |
| `crack_verify(u8*,int,u8*,int)` | did not exist at all |
| `crack_dictionary_attack(...)` | `attack_dictionary(const char*, const char*, int)` |
| `crack_bruteforce_attack(...)` | `attack_bruteforce(const char*, u64, u64, int)` |
| `crack_get_result(7 arguments)` | `crack_get_result(3 arguments)`, no lengths, no type |
| `crack_hashes_per_second() -> int` | returns `double` |

Six wrong names, a wrong arity, a wrong return type, and one function that was
invented. `crack_verify` has been added to the C API so the surface can offer
it; it is the same code path the CLI's `verify` subcommand uses.

`lib/pwdcrack.pm` was also out of step: `@EXPORT_OK` listed functions that did
not exist and omitted every one that did, and it referenced `$XS_VERSION`
without ever assigning it, so the module did not load at all.

## P11.1.02: the Node binding

The previous `node.rs` declared five N-API C functions by hand and implemented
`crack_verify` by reading one argument into a 256 byte buffer, discarding it, and
returning the literal string `"ok"`.

* It verified nothing, so every call succeeded.
* The returned pointer came from a `CString` that was dropped at the end of the
  function, so the caller read freed memory.
* A password over 256 bytes was silently truncated, which for a password cracker
  means answering about a different password.

Rewritten with the `napi` crate, which was already a dependency. Attacks are
`AsyncTask`, so they return a Promise and run on the libuv pool. The suite
asserts that a timer keeps firing during an attack, which is the property that
makes the Promise worth having.

## A defect both language bridges shared

The first version of both bindings took the loaded targets out of the session to
group them by cracker type, and put them back with a placeholder cracker that
answers `false` for everything. A second attack on the same session therefore
cracked nothing and reported success.

Found by the Node suite's "several attacks can be awaited concurrently" test,
which is the only place two attacks overlap. Both now group by borrowing, and
`test_a_second_attack_still_works` in the Python suite holds the line.

## Not done, stated plainly

**No Ruby bridge.** `Cargo.toml` declares a `ruby` feature and there is no
`ruby.rs`. Phase 11 does not list one, so the feature is a lie in the manifest.
It should either be implemented or removed; it is noted here rather than
silently left.

**`c_api.rs` has no generated header.** The C suite declares the prototypes by
hand, and the XS file declares them by hand again. Three hand written copies of
one ABI is how the Perl binding got six wrong names in the first place. A
`cbindgen` header, checked in and verified by the C suite, would make the third
copy checkable instead of trusted. Not done.

**The websocket is unauthenticated.** It streams status, counters and cracked
hashes to anything that connects. Consistent with the read-only HTTP routes and
with the same reasoning; see `docs/PHASE10_STATUS.md`.

**Mixed hash types use the first cracker for a dictionary attack.**
`attack_dictionary` and `attack_bruteforce` in `c_api.rs` pass
`hashes[0].0.as_ref()` as the cracker for every hash, so a load containing MD5
and SHA-256 together verifies both with the MD5 cracker. The C, Python and Node
surfaces all group by type and are correct; the C API's two attack entry points
are not. Not fixed, and it is a real wrong answer rather than a missing feature.

**Release profiles are not exercised.** The bridge suites default to the debug
profile because `target/release` is not writable here. The C suite prints which
panic strategy it linked against, and the Perl and Node suites link the same
archive, so the behaviour is known; a release build of this workspace has not
been run.

## Files

```
engines/engine-bridge/src/c_api.rs              the C ABI
engines/engine-bridge/src/python.rs              PyO3: Cracker, CrackedHash, Target, EngineInfo
engines/engine-bridge/src/node.rs                N-API with AsyncTask
engines/engine-bridge/perl/pwdcrack.xs           the XS binding
engines/engine-bridge/perl/lib/pwdcrack.pm       the Perl module
engines/engine-bridge/perl/Makefile.PL           static link through MYEXTLIB
engines/engine-bridge/perl/t/01_bridge.t         31 Perl tests
engines/engine-bridge/python/pwdcrack/           __init__.py and py.typed
engines/engine-bridge/python/tests/test_bridge.py 22 Python tests
engines/engine-bridge/node/test_bridge.js        16 Node tests
engines/engine-bridge/node/pwdcrack.d.ts         TypeScript declarations
engines/engine-bridge/tests/c/test_bridge.c      41 C checks
engines/engine-bridge/tests/ffi_roundtrip.rs     Rust side of the C ABI
.github/workflows/bridges.yml                    runs all four
```