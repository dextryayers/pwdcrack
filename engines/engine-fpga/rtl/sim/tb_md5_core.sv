// MD5 core testbench.
//
// # What this establishes
//
// `md5_core` computes the right digest for every message Python hashlib can,
// which is the only claim that makes an RTL hash core worth instantiating. The
// digests and the padded blocks both come from `rtl/sim/vectors/md5.svh`, which
// scripts/gen-rtl-vectors.py emits from hashlib and from struct.pack. Nothing
// in this file is a transcribed number.
//
// # Why the previous testbench was worthless
//
// `rtl/cores/md5_tb.sv` stated four RFC 1321 digests correctly and fed the core
// four wrong message blocks: three used big endian word order where MD5 needs
// little endian, and two put the length field in word 13 instead of word 14. It
// also did not compile, so none of it was ever observed. A testbench with wrong
// inputs and a correct implementation reports failures, and a testbench with
// wrong expectations and a correct implementation reports failures too; there is
// no way to tell which from the output. Generating both sides removes the
// question.
//
// # Single block
//
// MD5 of a message longer than 55 bytes needs a second block. This core
// compresses one block; chaining several blocks is the wrapper's job. The
// vectors stop at 55 bytes because that is the limit of the core, not of the
// algorithm. `tb_padding` covers the padding itself across the boundary where a
// second block appears.
//
// # Timing
//
// The core is pipelined: it accepts a block every cycle and asserts `done` 65
// cycles later. The task in tb_common.svh waits for `done` on the falling edge
// and compares in the same cycle, because `done` is a one cycle pulse.

`include "tb_common.svh"

module tb_md5_core;

    logic         clk = 1'b0;
    logic         rst_n = 1'b0;
    logic         valid = 1'b0;
    logic         ready;
    logic         done;
    logic [511:0] msg_blk;
    logic [127:0] state_in;
    logic [127:0] digest_out;

    `TB_COUNTERS

    md5_core dut (.*);

    // 10 ns period.
    always #5 clk = ~clk;

    `TB_REPORT("md5_core")
    `TB_CHECK_CORE(32, 16, 128, 128)

    // 65 pipeline stages plus a cycle of slack. A testbench that waits forever
    // reports a core that never finished; one that waits too little reports a
    // core that finished too early. Both are the same number here.
    localparam integer WAIT = 120;

    initial begin
        $display("=== md5_core, RFC 1321 vectors, generated from hashlib ===");

        msg_blk  = '0;
        state_in = '0;

        // Hold reset across two rising edges before releasing it.
        //
        // The core resets on `posedge clk or negedge rst_n`. `rst_n` starts at 0
        // without ever having a negedge, so the only event that can enter the
        // reset branch is a rising edge while `rst_n` is still 0. Releasing
        // after a single edge races that edge: if the initial block resumes
        // first, the core sees rst_n already high and the pipeline is never
        // cleared.
        repeat (2) @(posedge clk);
        rst_n = 1'b1;
        @(posedge clk);

        `include "vectors/md5.svh"

        tb_report("md5_core");
    end

endmodule