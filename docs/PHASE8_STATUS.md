# Phase 8 status: FPGA and SystemVerilog

Scope: `docs/plan.md` section 12, tasks P8.1 through P8.4.

## Summary

Nine cores compute correct digests, verified against 177 vectors generated from
independent oracles, and eleven testbenches run green. Every core that cannot be
shown correct is excluded from the design and says so at the top of its file.

| Sub-phase | State | Evidence |
|-----------|-------|----------|
| P8.1 inventory and verification | done | `scripts/simulate.sh --inventory` prints the table; every testbench runs |
| P8.2 core correctness | done for nine cores, explicitly unverified for thirteen | `scripts/simulate.sh`: 11 passed, 0 failed |
| P8.3 host interface | done and tested against a mock device | `cargo test -p engine-fpga`: 16 integration tests, protocol unit tests green |
| P8.4 timing and resources | **not measured** | `docs/FPGA_RESULTS.md` states what is missing and how to get it |

Nothing in this document claims a performance figure. There is no FPGA in this
repository, no vendor toolchain on the build machine and no board, so every
timing, utilisation and throughput number is absent rather than estimated. The
three numbers that were previously reported in this area, "1 hash/cycle",
"200,000,000 H/s" and "8W", were removed because all three were products of
assumptions rather than measurements.

## What the gate reports

```
simulator:  Icarus Verilog version 12.0 (stable) ()
vectors:    177 generated, none drifted
testbenches: 11

PASS  tb_crc_accelerator  (8 passed, 0 failed, 8 total)
PASS  tb_md4_core         (16 passed, 0 failed, 16 total)
PASS  tb_md5_core         (23 passed, 0 failed, 23 total)
PASS  tb_ntlm_core        (8 passed, 0 failed, 8 total)
PASS  tb_padding          (11 passed, 0 failed, 11 total)
PASS  tb_ripemd160_core   (16 passed, 0 failed, 16 total)
PASS  tb_sha1_core        (14 passed, 0 failed, 14 total)
PASS  tb_sha256_core      (17 passed, 0 failed, 17 total)
PASS  tb_sha384_core      (22 passed, 0 failed, 22 total)
PASS  tb_sha512_core      (22 passed, 0 failed, 22 total)
PASS  tb_top              (8 passed, 0 failed, 8 total)

================================
  11 passed, 0 failed
================================
```

## Verified cores

| Core | Vectors | Shape | Notes |
|------|---------|-------|-------|
| `md5_core` | 23 | pipelined, 1 block/cycle, 65 cycle latency | the one core worth pipelining |
| `md4_core` | 16 | iterative, 48 steps | the core NTLM is built on |
| `ntlm_core` | 8 | wrapper over `md4_core` | builds the UTF-16-LE block; refuses a password over 27 characters rather than truncating it |
| `sha1_core` | 14 | iterative, 80 rounds | |
| `sha256_core` | 17 | iterative, 64 rounds | |
| `sha512_core` | 22 | iterative, 80 rounds, 64 bit datapath | K table computed from cube roots and cross checked against the `sha2` crate |
| `sha384_core` | 22 | wrapper over `sha512_core` | different initial value, truncated digest |
| `ripemd160_core` | 16 | iterative, two parallel lines, 80 rounds | tables emitted from the reference that produced the vectors |
| `crc32_accel` | 8 | byte at a time | matches the host's `protocol::crc32` and zlib |
| `pwdcrack_top` | 8 | mux over seven cores | proves the wiring, which no per core test can |

## The word order rule, and why it is written down

`rtl/README.md` has the full rule. The short version: word 0 is in the least
significant bits, block words follow the algorithm's byte order while state and
digest ports carry words, and a rotate right by n is `{x[n-1:0], x[W-1:n]}`.

Every one of those three has been got wrong here, and each failure looked like a
core that was subtly broken rather than a rule that was misunderstood. They are
worth listing because they are the kind of defect that survives review:

| Mistake | Symptom | Caught by |
|---------|---------|-----------|
| rotate right written as a rotate left | SHA-256 wrong for every message; `sigma0` returned `{x[24:0], x[31:25]}`, which is ROL7 | the vectors |
| message schedule offsets taken from the wrong round | SHA-1 right through round 16, wrong from 17; every digest wrong | the vectors |
| schedule guard off by one | W[16] never written, slot 0 kept W[0] | the vectors |
| state bytes reversed | every digest wrong, state looked plausible | `check_word_order` in the generator |
| length field in the wrong byte order | every message except the empty one wrong | `check_padding` in the generator |
| core declared big endian when it is little endian | RIPEMD-160 failed all 16 vectors while its tables were all correct | `check_word_order` |
| drive window shorter than a cycle | every vector compared against the previous one, no error | the vectors |
| constant table in `always_comb` | every digest X | the vectors |

The last three generator checks exist because the first three of those bugs were
found by eye, one at a time, over a day.

## Unverified cores

These are in `rtl/cores` and carry a banner at the top saying so. None is
instantiated by `rtl/top.sv`, none has a testbench, and `scripts/simulate.sh`
reports no vectors for them.

| Core | What it would take |
|------|--------------------|
| `blake2b_core` | closest to usable: the vectors exist and are generated from hashlib. Needs the core rewritten to the common interface and a testbench. |
| `sha512_224_core` | same shape as `sha384_core`, which is a verified wrapper. A wrapper is all it is. |
| `ripemd128_core` | a testbench, and a decision about whether RIPEMD-128 is a target |
| `aes_cmac_core` | combinational only, with no port to feed a key and a message through |
| `pbkdf2_core` | a state machine driving a core whose interface no longer exists, and a real iteration count |
| `hmac_wrapper` | instantiates a SHA-256 core with a port list nothing has |
| `sha3_256_core` | Keccak is a sponge; the one block interface here does not fit it |
| `streebog256_core`, `whirlpool_core` | eight kilobytes of constants each, transcribed by hand, with no testbench to check them |
| `blake2s_core` | a testbench and its own generator entry |
| `md5_opt`, `sha1_opt` | superseded by the verified cores; no way to choose between them |
| `fifo`, `pipeline_stage` | utility blocks, not hash cores, not instantiated |

Two of these, Streebog and Whirlpool, failed on the same ground: the
implementation needs kilobytes of constants, and a kilobyte of constants written
from a specification is exactly the thing that cannot be reviewed. If they are
ever brought in, the constants belong in a generated include from the same
oracle as everything else.

## The corpus the vectors are built from

`scripts/gen-rtl-vectors.py` re-hashes every entry in `tests/test_vectors`
before using it, and it found three that were wrong:

| File | Password | Was | Is |
|------|----------|-----|-----|
| `md5.txt` | `password123!` | `fae35605...` | `b7e283a0...` |
| `md5.txt` | `ILoveYou` | `d8578edf...` | `62accaf2...` |
| `sha256.txt` | `abc` | `3e23e816...` | `ba7816bf...` |

Nothing had caught them, because the only test that read those files checked
that they parsed and never checked that the hash was the hash of the password.
They are fixed, the files say what was wrong, and CI now recomputes every entry.

## Host interface

Unchanged in shape from what was already here, and now covered:

- **Version and CRC.** `protocol.rs` carries a version field and verifies the
  CRC-32 before trusting any field. Both were defects before: the CRC was read
  into the struct and never compared, and there was no version field at all.
- **CRC agreement.** The host's `crc32` and the RTL's `crc32_accel` are now the
  same function, verified from the same generator, against zlib. The host had a
  variant that started from zero and omitted the final XOR; the RTL had the MPEG
  variant, which is a real CRC and not this one. Two different wrong answers, and
  every packet would have been rejected by the device with no explanation.
- **Reordering.** `CompletionQueue` buffers out of order completions and emits
  them in sequence order, refusing duplicates and undeclared sequences. Tested
  over all 24 arrival permutations of four completions.
- **The worker.** One thread per transport, tested against a mock that returns
  frames back to front.
- **The scheduler.** Takes a `Transport`, so it can be driven without hardware.
  Sixteen integration tests against a simulated device, including one that
  hashes real candidates through the simulated path.

## The top level

`rtl/top.sv` muxes seven cores onto one wide port and has its own testbench.

That testbench found a design fault: with every core tied to the same `valid`,
an unselected core started a block it would never report, and if that block was
still running when the caller selected it, the new block was dropped and the
caller got the digest of the discarded one. Each core now sees `valid` only when
it is selected. The failure was invisible to every per core testbench, which is
the argument for having one.

It also found three wiring faults of the same kind: one shared `ready` net and
one shared `done` net with seven drivers, one shared digest net that the 128 bit
cores both drove, and an `always @*` selector that never ran because no input
changed and so left every mux output at X.

## Timing and resources

Not measured. `docs/FPGA_RESULTS.md` has the table of what is missing, the
three previously reported numbers that were removed and why, the commands to
obtain the real ones, and an estimate of the critical path from logic depth,
labelled as an estimate.

`scripts/build.tcl` and `constraints/pwdcrack.xdc` have been rewritten so they
match this design. The old constraint file named `pcie_clk`, `pcie_rx_data*`,
`ddr_addr*` and `uart_rx`, none of which are ports of anything here, so applied
to this design it would have constrained nothing and Vivado would have warned
rather than failed. The new `build.tcl` fails if the constraints name a port that
does not exist, and fails on unconstrained endpoints, because a timing report
that silently omits paths looks exactly like a timing report that passes.

Neither has been run. There is no Vivado on this machine.

## Commands

```
scripts/setup-iverilog.sh              # unpack a simulator without root
scripts/simulate.sh                    # run every testbench
scripts/simulate.sh --inventory        # what is here and what is verified
scripts/simulate.sh sha256             # one testbench
./scripts/gen-rtl-vectors.py --list    # vectors per core
./scripts/gen-rtl-vectors.py --check   # fail on any drift
cargo test -p engine-fpga              # host side: protocol, queue, scheduler
```

## Next steps, ordered by value

1. **BLAKE2b.** The vectors are already generated and correct; the core needs
   rewriting to the common interface and a testbench. It is the cheapest
   remaining coverage.
2. **A second block per message.** Every core here is a single block
   compression function, so a message over 55 bytes is out of scope for all of
   them. The chaining state is already a port, so a wrapper is most of the work,
   and the protocol's 64 byte slot format is the part that has to change.
3. **Synthesis.** One run of `scripts/build.tcl` replaces the estimate in
   `docs/FPGA_RESULTS.md` with a measurement.
4. **A real transport.** `PcieTransport` reads and writes offset 0 of a device
   node, which is a placeholder. A working one needs a board.
5. **The `Stats` command.** The protocol has it and nothing implements it, so
   core count and clock are still `None` on the device, which is the honest
   answer and not a useful one.