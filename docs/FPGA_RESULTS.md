# FPGA results

This document records what has been measured on FPGA, and states plainly that
almost nothing has, because nothing can be.

## What has been measured

| Property | Value | How |
|----------|-------|-----|
| Correctness of nine cores | every core passes its generated vectors | `scripts/simulate.sh` |
| Digest count verified | 177 vectors across 11 testbenches | `scripts/simulate.sh` |
| Oracle | Python `hashlib`, `zlib`, and a pure Python MD4 held against OpenSSL | `scripts/gen-rtl-vectors.py` |
| Simulator | Icarus Verilog 12.0 | the only simulator on the build machine |

That is the whole list. Everything else this document would normally contain is
below, marked as not measured.

## What has NOT been measured, and why

| Property | Status | Why |
|----------|--------|-----|
| Clock frequency | **not measured** | no FPGA, no vendor tool |
| Logic utilisation | **not measured** | same |
| Block RAM utilisation | **not measured** | same |
| Power | **not measured** | same |
| Bits per hash, or hashes per second | **not measured** | follows from the above |
| Bitstream correctness on hardware | **not measured** | no board |

There is no FPGA in this repository, no vendor toolchain installed on the build
machine, and no board. Any number in those rows would be a guess, and the
repository's rule, stated in `docs/plan.md` section 1 and enforced everywhere
else in this file, is that a number nobody measured is worse than no number: it
is indistinguishable from a measurement until someone relies on it.

Three numbers that were previously reported here have been removed for exactly
that reason, and they are worth naming because they looked plausible:

- "fully pipelined, 1 hash/cycle" for the MD5 core. The core *is* pipelined and
  accepts a block per cycle in simulation; the claim that mattered, that it
  closes at some clock rate on some device, was never established.
- "200,000,000 H/s", from a 200 MHz clock multiplied by an assumed one hash per
  cycle. Both factors were assumptions. The field is gone from
  `src/scheduler.rs`; a device now reports its own measured rate or nothing.
- "8W versus a GPU's 450W". No power measurement was taken on either side.

## How to obtain the missing numbers

For a synthesis and timing run with Vivado:

```bash
cd engines/engine-fpga
vivado -mode batch -source scripts/build.tcl
```

`scripts/build.tcl` elaborates `rtl/top.sv`, runs synthesis and implementation
for the part named by `PART`, and writes a utilisation and timing report to
`build/vivado/report_utilization.rpt` and `build/vivado/report_timing.rpt`.

The constraints file `constraints/pwdcrack.xdc` states a 300 MHz target and the
I/O placement for the board it was written for. **It is an example, not a
validated constraint set**: no board it describes is connected to anything here,
and it has not been through Vivado's lint. Change the part, the pinout and the
I/O standards before using it for anything; a constraint set that names a part
you do not have produces a design that reports success and cannot be built.

For ModelSim or Questa, which check the same sources through a different front
end:

```bash
cd engines/engine-fpga
vsim -c -do scripts/simulate.tcl
```

This has not been run here either. It exists to catch what a vendor tool rejects
that Icarus accepts, which is a real class of problem, and it is not a claim
about the results.

## Where to record a result

Append a section below with: the part, the tool and version, the Vivado version,
the clock constraint, the utilisation numbers, the achieved frequency, and the
commit the bitstream was built from. Anything less than that is a number
without a denominator.

## The timing target, and what it rests on

`docs/plan.md` P8.4.01 asks for 300 MHz for MD5, SHA-1, SHA-256 and NTLM on a
mid range Artix-7, and P8.4.02 for under 60 percent LUT and 70 percent BRAM.

The structure of the cores supports it, and structure is not measurement:

| Core | Critical path | Depth |
|------|---------------|-------|
| `md5_core` | one round: add, add, add, rotate, add | about 30 logic levels |
| `sha1_core` | one round: rotate, four adds, rotate | about 35 |
| `sha256_core` | one round plus one schedule step | about 40 |
| `md4_core` | one step | about 25 |
| `ripemd160_core` | two steps in parallel, left and right line | about 35 |
| `sha512_core` | one round, 64 bit | about 45 |

A path of 30 to 45 levels is comfortably inside 300 MHz on a mid range Artix-7
at a reasonable speed grade, and that sentence is an estimate from logic depth,
not a timing report. The first thing to do with a board in hand is synthesise
`rtl/top.sv` and replace this section with the numbers.