// pwdcrack FPGA top level.
//
// # What this design contains
//
// One core: MD5. That is the only core in this repository with a testbench that
// passes against an external oracle. `scripts/simulate.sh` reports:
//
//     md5_core: 5 passed, 0 failed, 5 total
//
// against RFC 1321 vectors produced by Python hashlib through
// `scripts/gen-rtl-vectors.py`.
//
// # Why the other cores are absent
//
// P8.2.10 requires that the design contain only verified blocks. The cores below
// are each excluded because `scripts/simulate.sh` does not report them as
// passing. Nothing here is a judgement about the algorithms; it is a statement
// about what has actually been run.
//
//   sha1_core     fails all four vectors. Rounds 0 to 3 and the message schedule
//                 were verified against a Python reference and match; the digest
//                 diverges from round 4. See rtl/sim/tb_sha1_core.sv.
//   sha256_core   has a testbench that does not compile.
//   sha512_core   no testbench.
//   ntlm_core     no testbench.
//   hmac_wrapper  no testbench.
//   sha384_core   has a testbench that does not compile.
//   sha512_224_core, md5_opt, sha1_opt  no testbench.
//
// Adding a core back means adding a testbench that passes. The inventory that
// `scripts/simulate.sh` prints is the authority, and this comment is kept in step
// with it by hand because a comment cannot run.
//
// # Interface
//
// The MD5 core is driven with packed vectors rather than unpacked arrays, because
// an unpacked array output port never propagates to the parent under Icarus
// Verilog 12, which is the only simulator available here. That is a simulation
// constraint, not a hardware preference; on real silicon either form works.
//
// `w` holds one 512 bit block with word i at [32*i +: 32], MD5 being little
// endian. `h_out` is the 128 bit final state with word i at [32*i +: 32].
//
// The PCIe and DDR paths the previous version of this file declared are not
// present. There is no FPGA, no vendor toolchain and no board in this
// repository, so nothing about a PCIe interface here could be compiled, let alone
// verified. Writing those ports produced a file that looked like a design and
// could not elaborate, which is worse than not having it.

module pwdcrack_top (
    input  logic          clk,
    input  logic          rst_n,

    // Core input. `block_valid` is the core's `valid`; `block_in` is the padded
    // 64 byte block as sixteen 32 bit words, word 0 in the low bits.
    input  logic          block_valid,
    input  logic [511:0]  block_in,
    input  logic [127:0]  state_in,

    // Core output. `state_out` is the 128 bit final state, `block_done` is the
    // core's `done` pulse, one cycle wide, aligned with `state_out`.
    output logic [127:0]  state_out,
    output logic          block_done,

    // Always able to accept the next block: this core is fully pipelined and
    // accepts a block every cycle.
    output logic          ready,

    // Idle indicator for a board level design. No board is built here, so this
    // is the only status the design can honestly report.
    output logic          idle
);

    md5_core u_md5 (
        .clk      (clk),
        .rst_n    (rst_n),
        .valid    (block_valid),
        .ready    (ready),
        .msg_word (block_in),
        .h_in     (state_in),
        .h_out    (state_out),
        .done     (block_done)
    );

    always_comb idle = ~block_valid & ~block_done;

endmodule