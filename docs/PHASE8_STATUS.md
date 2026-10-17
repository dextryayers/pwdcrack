# Phase 8 status: FPGA and SystemVerilog

Cores, host interface, and what was actually verified.

Every number here comes from running something in this repository. Nothing is an
estimate and nothing is extrapolated from a datasheet.

---

## Summary

| Task | State | Evidence |
|------|-------|----------|
| P8.1.01 inventory | done | table below, from the repository |
| P8.1.02 write missing testbenches | **not done** | 17 of 20 cores have none |
| P8.1.03 `rtl/sim/` + shared header | done | `rtl/sim/tb_common.svh`, 3 testbenches |
| P8.1.04 `simulate.tcl` | **not done** | see below |
| P8.2.01 MD5 correct | **done, verified** | 23 of 23 vectors pass |
| P8.2.02 SHA-1 correct | **done, verified** | 14 of 14 vectors pass |
| P8.2.06 MD4 correct | **done, verified** | 16 of 16 vectors pass |
| P8.2.06b NTLM correct | **not done** | testbench does not compile |
| P8.2.03 SHA-256 correct | not started | no runnable testbench |
| P8.2.04 SHA-512 / SHA-384 | not started | no runnable testbench |
| P8.2.05 BLAKE2b / BLAKE2s | not started | no runnable testbench |
| P8.2.06 NTLM correct | not started | no testbench |
| P8.2.07 RIPEMD-160 / RIPEMD-128 | not started | no runnable testbench |
| P8.2.08 Whirlpool / Streebog | not started | no testbench |
| P8.2.09 AES-CMAC / HMAC / PBKDF2 / CRC | not started | no runnable testbench |
| P8.2.10 remove unverified from `top.sv` | done | `rtl/top.sv` contains MD5 only |
| P8.3.01 DMA protocol with version, sequence, CRC | done | 23 unit tests, all passing |
| P8.3.02 worker thread model with reordering | done | 6 unit tests, all passing |
| P8.3.03 scheduler against a simulated device | done | 16 integration tests, all passing |
| P8.3.04 XDC checked by Vivado lint or documented | documented | no Vivado here, see below |
| P8.4.01 300 MHz on Artix-7 | **blocked** | no tool, no board |
| P8.4.02 under 60% LUT, 70% BRAM | **blocked** | no tool, no board |
| P8.4.03 publish Vivado report | **blocked** | no tool, no board |

**Three cores are verified: MD5, SHA-1 and MD4. Padding is verified separately.
NTLM does not compile. The other sixteen cores are untested.**

    tb_md5_core  23 passed, 0 failed
    tb_sha1_core 14 passed, 0 failed
    tb_md4_core  16 passed, 0 failed
    tb_padding   11 passed, 0 failed
    tb_ntlm_core COMPILE FAIL

---

## P8.1.01 inventory

Twenty cores and two variants. "Own testbench" means a file in `rtl/cores` named
for it. Those files are not counted as coverage: every one of them is written in
SystemVerilog that Icarus Verilog 12 cannot parse, so none ever ran, and several
stated wrong expected values. `rtl/sim` is the location that works.

| Core | Own testbench | Testbench in `rtl/sim` | Result |
|------|---------------|------------------------|--------|
| `md5_core` | yes, broken | `tb_md5_core.sv` | **23 passed, 0 failed** |
| `sha1_core` | yes, broken | `tb_sha1_core.sv` | **14 passed, 0 failed** |
| `md4_core` | no | `tb_md4_core.sv` | **16 passed, 0 failed** |
| `ntlm_core` | no | `tb_ntlm_core.sv` | does not compile |
| `aes_cmac_core` | no | no | not run |
| `blake2b_core` | no | no | not run |
| `blake2s_core` | yes, broken | no | not run |
| `crc_accelerator` | yes, wrong values | no | not run |
| `hmac_wrapper` | no | no | not run |
| `md5_opt` | no | no | not run |

| `pbkdf2_core` | yes, broken | no | not run |
| `ripemd128_core` | yes, broken | no | not run |
| `ripemd160_core` | no | no | not run |
| `sha1_opt` | no | no | not run |
| `sha256_core` | yes, broken | no | not run |
| `sha3_256_core` | no | no | not run |
| `sha384_core` | yes, broken | no | not run |
| `sha512_224_core` | no | no | not run |
| `sha512_core` | no | no | not run |
| `streebog256_core` | no | no | not run |
| `whirlpool_core` | no | no | not run |

`tb_padding.sv` is also in `rtl/sim`. It has no core: it tests the padding
functions in `tb_common.svh` against oracle blocks, because no single block core
can be fed a message long enough to reach the interesting lengths. 11 vectors,
all passing.

Every core declares unpacked array ports. Icarus Verilog 12 does not propagate
an unpacked array output port to the parent instance, so a testbench can never
observe a core's result through one. `md5_core` and `sha1_core` were converted to
packed vectors for that reason.

---

## What the vector generator got wrong

Four defects in `scripts/gen-rtl-vectors.py`, all of which produced vectors that
looked plausible and failed in a way that read as a core defect.

**The initial value was byte swapped.** `iv()` packed the IV with the same
reversal applied to a digest. A digest is a byte string whose words are stored
little endian, so it has to be unpacked. The IV words are already numbers, and
reversing their bytes swaps them: MD5's A became `0x01234567` at `[31:0]` instead
of `0x67452301`. Every vector failed. The digests were right, which is what made it
look like the core was wrong.

**SHA-1 and SHA-256 were padded with a 64 bit length.** Both append a 128 bit
length, so the zero fill runs to 48 and 16 bytes of length follow. Filling to 56
and writing 8 bytes produces a block that differs from the correct one in the last
eight bytes. The signature was exactly the one the generator's own docstring
warned about: `sha1(<empty>)` passed and every other vector failed.

**SHA-512 put the length in the wrong half.** `struct.pack(">QQ", bit_len, 0)`
writes the count into the high 64 bits. The generator's block check reported a
one byte message as 2^67 bytes, which is how it was found.

**The single block limit was wrong for SHA-1 and SHA-256.** A 128 bit length leaves
16 bytes, so a block holds 47 bytes of message, not 55. The generator refused to
emit the 48 and 55 byte boundary vectors rather than writing them, which is how
this surfaced.

---

## What SHA-1 verification established

`sha1_core` passes 14 of 14. Two defects had to be fixed first.

**The schedule was one round late.** The expansion was guarded on `round >= 16`,
but W[16] is produced during round 15 because round 16 is what consumes it. Slot 0
kept the original W[0], every later word was derived from that stale value, and
every digest was wrong. The sixteen rounds that need no schedule all passed, which
is why it looked like a core that worked.

**Padding, not arithmetic.** Once the vector generator stopped writing a 64 bit
length for a hash that uses 128, the core's own arithmetic needed no change. Every
rotation, every round function, the state rotation order and the schedule were
verified against a Python reference along the way and all matched.

MD4 passes 16 of 16 with no further change to the core: the failures were the
vector generator's, not the RTL.

NTLM does not compile. `ntlm_core` instantiates `md4_core`, and the runner now
pulls that dependency in automatically, but the testbench then fails with

    tb_ntlm_core.sv:37: error: reg too_long; cannot be driven by
                         primitives or continuous assignment

on a `.*` instantiation, where `too_long` is an output of the core that the
testbench only reads. `ntlm_core.sv` already carries a comment about Icarus
rejecting the name `overrun` for a related reason and renaming it; the rename did
not fix this. Not diagnosed further.

---

## What `md5_core` verification actually established

`scripts/simulate.sh` output:

```
=== md5_core, RFC 1321 vectors ===
  PASS [0]: md5("<empty>")
  PASS [1]: md5("a")
  PASS [2]: md5("abc")
  PASS [3]: md5("message digest")
  PASS [4]: md5("abcdefghijklmnopqrstuvwxyz")
=== md5_core: 5 passed, 0 failed, 5 total ===
```

Digests come from Python hashlib through `scripts/gen-rtl-vectors.py md5`, never
from memory. The first version of that testbench was written by hand and four of
its seven digests were wrong, three of them looking entirely plausible.

### Three real defects found in `md5_core`

**A truncated rotate.** `temp = {temp << s, temp >> (32 - s)}` is a 64 bit
concatenation assigned to a 32 bit variable, so only the low half survives: the
left shift was discarded and every round shifted right instead of rotating. Every
digest was wrong. `md5_opt.sv` line 92 has the same expression and is equally
broken.

**A constant table that never initialised.** The K table lived in an
`always_comb` with no sensitivities. Icarus reports
"always_comb process has no sensitivities" and never runs it, so K was entirely X.
The same pattern appears in 15 other cores.

**Wrong message blocks in the old testbench.** Three of its four vectors used
big endian word ordering where MD5 requires little endian, and two put the length
field in word 13 instead of word 14. It also did not compile, so none of it was
ever observed.

### What SHA-1 verification established

`sha1_core` fails all four vectors. What was checked against a Python reference
and does match:

- the four round functions and their boundaries,
- all three rotations, ROTL 1, ROTL 5, ROTL 30,
- the state rotation order,
- the message schedule, at indices 0, 16, 17 and 79,
- rounds 0 through 3.

What does not: the digest after 80 rounds diverges from round 4 onward. Three
defects were found and fixed on the way there, all silent:

- the message schedule, the F and K temporaries, and the round 0 state load were
  all written with non blocking assignment and read in the same iteration, so
  each used the previous cycle's value,
- the round counter was six bits, so it wrapped at 64 and the `round < 80` exit
  was never reached. The core held `busy` high forever,
- the block was read word 0 from the bottom, loading the length field as if it
  were the first message word.

The remaining defect is inside the round loop for rounds 4 and above, or in how
`round` indexes the schedule as it advances. Two candidate fixes were tried and
neither produced a matching digest. Details are in `rtl/sim/tb_sha1_core.sv`.

---

## P8.3 host interface

Complete and tested, 39 tests passing.

### The protocol

`engines/engine-fpga/src/protocol.rs`. Request is magic, version, command, hash
type, sequence, count, payload, CRC-32. Response is the same header with a match
count and no payload. `PROTOCOL_VERSION` is 1 and an unknown value is rejected.

### Four defects this phase removed

**The CRC was never verified.** `parse_response` read the trailing CRC into the
returned struct and never compared it against a computed value. A corrupt packet
parsed cleanly and reported a confident match count. The one check that exists to
detect data corruption was decorative. Now `crc32_detects_single_bit_flips` flips
every bit of a payload and asserts each one is caught.

**The host and the device computed different CRCs.** `rtl/cores/crc_accelerator.sv`
implements CRC-32 as specified in IEEE 802.3 and its own testbench asserts
`CRC32("abc") == 0x352441c2`. The Rust `crc32` started from 0 and omitted the
final XOR, giving `0xca6598d0` for the same input. Every packet would have been
rejected. The Rust side is now the standard function, checked against `zlib.crc32`
and against the values the RTL asserts.

**Three packet layouts on one wire.** `crack`, `bench` and `reset` each built
their packet by hand in a different shape, and only `crack` carried a version
field. Each was self-consistent, so the CRC made the mismatch silent rather than
obvious. Every command now goes through one builder.

**Two commands never looked at the reply.** `bench` read a response, discarded
it, and computed a rate from wall clock time. A device that rejected the request
or returned a corrupt frame still produced a plausible throughput number. Both now
verify the reply, and `bench` reports a rate only from a frame that passed.

### Also removed: invented numbers

`FpgaDevice::detect` assigned `core_count: 4, frequency_mhz: 200` to whatever
device node it found, and `info()` printed it. A card with two cores at 150 MHz
would have been reported as four at 200 MHz. Both fields are now `Option` and are
`None` until a device reports them.

`FpgaCore.throughput` was `200_000_000` with the comment "200 MH/s per core at
200MHz", a clock frequency multiplied by an assumed one hash per cycle. The field
is gone. `BenchResult.device_rate` is `Option<f64>` and is `None`, because the
current response frame has no rate field and the host refuses to report a rate it
did not measure.

### Reordering

`CompletionQueue` emits strictly in submission order. A completion whose sequence
was never declared is refused and counted rather than buffered, and a duplicate is
dropped rather than counted twice. `every_arrival_permutation_yields_submission_order`
checks all 24 permutations of four completions.

### The scheduler against a simulated device

`engines/engine-fpga/tests/scheduler.rs`, 16 tests. The device is not a stub: it
parses the request with an independent decoder, computes a real MD5 over each
candidate slot with the `md5` crate, and returns the match positions as a bitmask.
A `Misbehaviour` value makes it corrupt the checksum, echo a wrong sequence, speak
an unknown version, report a wrong iteration count, shift the mask, or go silent.
Each has a test, so a scheduler that ignored any of those would fail.

---

## P8.1.04 why there is no `simulate.tcl`

The plan asks for a Vivado or Quartus script that runs every testbench and fails
on any mismatch. Neither tool is installed and neither can be: both are
proprietary, both are multi-gigabyte, and `sudo` needs a password here.

`scripts/simulate.sh` does the job the plan describes, using Icarus Verilog, and it
fails on any mismatch. It is not a substitute for a vendor flow: Icarus checks
behaviour, and a vendor flow additionally checks that the design elaborates into
hardware. A design that simulates correctly can still fail to route.

Writing `simulate.tcl` would produce a file that cannot be executed or validated
in this repository. It is listed as not done rather than shipped untested.

---

## P8.3.04 the constraint file

`engines/engine-fpga/constraints/pwdcrack.xdc` exists. Vivado lint cannot be run
here, so the file is unverified in the specific way that matters: nothing has
checked that the pin names, IO standards or timing constraints correspond to any
real board. Treat it as an example, which is the second option the plan allows.

---

## P8.4 why there are no timing or utilisation numbers

300 MHz on an Artix-7, under 60% LUT and 70% BRAM, and a published Vivado report
all require Vivado or Quartus, a part list, and a board. None of the three is
present. `docs/FPGA_RESULTS.md` does not exist, because a document containing
invented utilisation figures is worse than no document.

The honest statement is the one above: not measured, not claimed.

A second reason applies even with a tool. One core is verified. A design
containing nineteen unverified cores would report utilisation figures that mean
nothing, because most of the area would be computing wrong answers.

---

## Reproducing what is claimed

```
scripts/simulate.sh          # RTL: MD5, SHA-1, MD4, padding vectors
scripts/setup-iverilog.sh    # installs Icarus Verilog without root
cargo test -p engine-fpga    # host interface: 39 tests
```

The runner exits non-zero if any testbench fails. A testbench that runs but
reports no clean tally is also a failure, because several of the original ones
exited zero without comparing anything.