// MD4 core testbench.
//
// # What this establishes
//
// `md4_core` produces the digest of a pure Python MD4 that is itself held
// against OpenSSL's MD4 and against the RFC 1320 test suite. Python's hashlib
// dropped MD4 in 3.9 and OpenSSL 3 moved it to the legacy provider, so there is
// no system digest to compare against and the reference has to be written out.
// It is written out once, in scripts/gen-rtl-vectors.py, and checked there.
//
// # Single block
//
// 55 bytes is the limit, for the same reason as every other Merkle-Damgard core
// here: the terminator and the length field have to fit in one block.

`include "tb_common.svh"

module tb_md4_core;

    logic         clk = 1'b0;
    logic         rst_n = 1'b0;
    logic         valid = 1'b0;
    logic         ready;
    logic         done;
    logic [511:0] msg_blk;
    logic [127:0] state_in;
    logic [127:0] digest_out;

    `TB_COUNTERS

    md4_core dut (.*);

    always #5 clk = ~clk;

    `TB_REPORT("md4_core")
    `TB_CHECK_CORE(32, 16, 128, 128)

    localparam integer WAIT = 90;

    initial begin
        $display("=== md4_core, RFC 1320 vectors, generated from a Python MD4 ===");

        msg_blk  = '0;
        state_in = '0;

        repeat (2) @(posedge clk);
        rst_n = 1'b1;
        @(posedge clk);

        `include "vectors/md4.svh"

        tb_report("md4_core");
    end

endmodule