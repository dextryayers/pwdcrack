// SHA-512 core testbench.
//
// # What this establishes
//
// `sha512_core` produces the digest Python hashlib produces for every message up
// to the single block limit of 111 bytes, from vectors emitted rather than
// transcribed by scripts/gen-rtl-vectors.py.
//
// # Single block
//
// 111 bytes: the 128 byte block holds 112 bytes of message plus the 0x80
// terminator, with the 16 byte length field taking the last sixteen. 112 bytes
// needs a second block, which this core does not do; the vectors stop at 111 and
// say so.
//
// # Timing
//
// 80 rounds plus load and feed forward.

`include "tb_common.svh"

module tb_sha512_core;

    logic          clk = 1'b0;
    logic          rst_n = 1'b0;
    logic          valid = 1'b0;
    logic          ready;
    logic          done;
    logic [1023:0] msg_blk;
    logic [511:0]  state_in;
    logic [511:0]  digest_out;

    `TB_COUNTERS

    sha512_core dut (.*);

    always #5 clk = ~clk;

    `TB_REPORT("sha512_core")
    `TB_CHECK_CORE(64, 16, 512, 512)

    localparam integer WAIT = 130;

    initial begin
        $display("=== sha512_core, FIPS 180-4 vectors, generated from hashlib ===");

        msg_blk  = '0;
        state_in = '0;

        repeat (2) @(posedge clk);
        rst_n = 1'b1;
        @(posedge clk);

        `include "vectors/sha512.svh"

        tb_report("sha512_core");
    end

endmodule