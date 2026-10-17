// SHA-384 core testbench.
//
// # What this establishes
//
// `sha384_core` produces the digest Python hashlib produces, which also covers
// the wrapper: the truncation, the initial value, and the handoff to
// `sha512_core`. The SHA-512 compression function itself is covered by
// `tb_sha512_core`, so a failure here is a failure of the wrapper rather than of
// the algorithm.

`include "tb_common.svh"

module tb_sha384_core;

    logic          clk = 1'b0;
    logic          rst_n = 1'b0;
    logic          valid = 1'b0;
    logic          ready;
    logic          done;
    logic [1023:0] msg_blk;
    logic [383:0]  state_in;
    logic [383:0]  digest_out;

    `TB_COUNTERS

    sha384_core dut (.*);

    always #5 clk = ~clk;

    `TB_REPORT("sha384_core")
    `TB_CHECK_CORE(64, 16, 384, 384)

    localparam integer WAIT = 140;

    initial begin
        $display("=== sha384_core, FIPS 180-4 vectors, generated from hashlib ===");

        msg_blk  = '0;
        state_in = '0;

        repeat (2) @(posedge clk);
        rst_n = 1'b1;
        @(posedge clk);

        `include "vectors/sha384.svh"

        tb_report("sha384_core");
    end

endmodule