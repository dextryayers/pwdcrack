# RTL conventions

Everything in `rtl/cores`, `rtl/sim` and `rtl/top.sv` follows four rules. They
are written here because every one of them is a way to produce a wrong digest
with no diagnostic, and each has been got wrong in this repository at least once.

## 1. Word 0 is in the least significant bits

A block is `NW` words of `W` bits, packed so that **word 0 occupies
`[W-1:0]`**. A digest is `DW` words with the same rule, where word 0 is the
first `W/8` bytes of the digest as printed.

A hex literal therefore lists word `n-1` first. `scripts/gen-rtl-vectors.py`
emits every block and every digest this way, and re-reads what it wrote, so the
rule is applied in exactly one place.

Word 0 at the *top* also works. Mixing the two is the bug: a block built with
the opposite order produces a digest that is wrong for every message, with no
error anywhere.

## 2. Word order inside a word follows the algorithm

The block is a byte string. Word `i` is bytes `[i*W/8, (i+1)*W/8)` of the padded
block, read in the byte order the algorithm uses:

| Algorithm | Words are |
|-----------|-----------|
| MD4, MD5, RIPEMD-160, NTLM, BLAKE2b | little endian, bytes reversed inside each word |
| SHA-1, SHA-256, SHA-512, SHA-384 | big endian, bytes in place |

The state and digest ports are different. `state_in` and `digest_out` carry
*words*, not byte strings: a core loads `state_in[31:0]` straight into its `a`
register. So the initial state is packed with the word order reversed and each
word's bytes left alone. Reversing the bytes of the state produces a literal
that looks right and a digest that is wrong for every message.

The check that catches a mistake here is in the generator: `check_word_order`
compares the first word of an empty message's block against the rule, so a core
declared with the wrong endianness fails before a single testbench runs.

## 3. Rotate right by n is `{x[n-1:0], x[W-1:n]}`

The concatenation `{x[W-n-1:0], x[W-1:W-n]}` is a rotate **left** by n. Both
compile, both are `W` bits wide, and the difference is that every digest is
wrong.

This is the single most expensive mistake in this repository's history: SHA-256's
`sigma0` was written as `{x[24:0], x[31:25]}`, which is ROL7 rather than ROTR7.
The core returned plausible values for every input, and the first symptom was
"MD5 and SHA-1 pass, SHA-256 does not".

## 4. Constant tables are initialised in an `initial` block

`always_comb` with only constant assignments has no sensitivities. Icarus
Verilog reports that and never runs the process, leaving the table entirely X,
which propagates into every digest. `initial` is portable and synthesizable on
an FPGA, where the values become the initial contents of the register bank.

## Interface

Every hash core has the same ports:

```systemverilog
module <name>_core (
    input  logic          clk,
    input  logic          rst_n,
    input  logic          valid,       // a block is offered this cycle
    output logic          ready,       // the core can accept it
    input  logic [BLK-1:0] msg_blk,    // one padded block, rule 1 and 2
    input  logic [IVW-1:0] state_in,   // chaining state, rule 2
    output logic [DW-1:0] digest_out,  // result, rule 1 and 2
    output logic          done         // one cycle pulse, digest_out valid
);
```

`done` is a one cycle pulse and `digest_out` is valid in that cycle. A testbench
must sample both on the same edge, which for this repository means the falling
edge: on the rising edge, `done` is read one delta before the non blocking update
that raised it, and the loop runs one edge past the pulse and concludes the core
never fired.

## What is verified, and what that means

`scripts/simulate.sh` prints an inventory: every core in `rtl/cores`, whether it
has generated vectors, and whether a testbench instantiates it. A core appears
in `rtl/top.sv` only if its testbench passes.

Being in the inventory with vectors and a testbench is not the same as passing;
the run above the inventory is the verdict.

```
scripts/simulate.sh              # run everything
scripts/simulate.sh --inventory  # the table on its own
scripts/simulate.sh sha256       # one testbench
scripts/gen-rtl-vectors.py --list
```

## Simulator support

Written for and verified with Icarus Verilog 12, which is what this repository
can install without root (`scripts/setup-iverilog.sh`). The constructs that
version does not support are listed at the top of `rtl/sim/tb_common.svh`, each
with the error it produces, because every one of them fails silently or with a
message that points somewhere else.

Vivado's `xsim` and ModelSim's `vsim` are driven by `scripts/simulate.tcl`. They
have not been run here: no vendor tool is installed on the build machine, and
this repository does not claim a result it has not observed.