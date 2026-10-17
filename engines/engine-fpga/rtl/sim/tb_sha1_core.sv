// SHA-1 core testbench.
//
// # What this establishes
//
// `sha1_core` produces the digest Python hashlib produces, for every message up
// to the single block limit of 55 bytes, from vectors emitted rather than
// transcribed by scripts/gen-rtl-vectors.py.
//
// # Single block
//
// SHA-1 of a longer message needs a second block. This core compresses one; the
// chaining state is a port, so a wrapper feeds several blocks through it. The
// vectors stop at 55 bytes because that is the limit of the core.
//
// # Timing
//
// Iterative: the core accepts a block when `ready` is high and asserts `done` 82
// cycles later. WAIT is set above that with margin, and below the point where a
// core that never finished would be reported as a hang.

`include "tb_common.svh"

module tb_sha1_core;

    logic         clk = 1'b0;
    logic         rst_n = 1'b0;
    logic         valid = 1'b0;
    logic         ready;
    logic         done;
    logic [511:0] msg_blk;
    logic [159:0] state_in;
    logic [159:0] digest_out;

    `TB_COUNTERS

    sha1_core dut (.*);

    // 10 ns period.
    always #5 clk = ~clk;

    `TB_REPORT("sha1_core")
    `TB_CHECK_CORE(32, 16, 160, 160)

    // 82 cycles of latency plus margin.
    localparam integer WAIT = 140;

    initial begin
        $display("=== sha1_core, FIPS 180-4 vectors, generated from hashlib ===");

        msg_blk  = '0;
        state_in = '0;

        // Two rising edges under reset, see tb_md5_core.sv.
        repeat (2) @(posedge clk);
        rst_n = 1'b1;
        @(posedge clk);

        `include "vectors/sha1.svh"

        tb_report("sha1_core");
    end

endmodule