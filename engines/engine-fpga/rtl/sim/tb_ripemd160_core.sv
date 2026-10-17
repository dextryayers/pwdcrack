// RIPEMD-160 core testbench.
//
// # What this establishes
//
// `ripemd160_core` produces the digest hashlib produces, for every message up to
// the single block limit of 55 bytes. RIPEMD-160 is a dual line algorithm, so
// this also covers the final combination step, which is where an implementation
// most easily loses a word.
//
// RIPEMD-160 is a target worth having: it is what Bitcoin's P2PKH addresses and
// several appliance firmware images use.

`include "tb_common.svh"

module tb_ripemd160_core;

    logic         clk = 1'b0;
    logic         rst_n = 1'b0;
    logic         valid = 1'b0;
    logic         ready;
    logic         done;
    logic [511:0] msg_blk;
    logic [159:0] state_in;
    logic [159:0] digest_out;

    `TB_COUNTERS

    ripemd160_core dut (.*);

    always #5 clk = ~clk;

    `TB_REPORT("ripemd160_core")
    `TB_CHECK_CORE(32, 16, 160, 160)

    localparam integer WAIT = 130;

    initial begin
        $display("=== ripemd160_core, vectors generated from hashlib ===");

        msg_blk  = '0;
        state_in = '0;

        repeat (2) @(posedge clk);
        rst_n = 1'b1;
        @(posedge clk);

        `include "vectors/ripemd160.svh"

        tb_report("ripemd160_core");
    end

endmodule