// SHA-256 core testbench.
//
// # What this establishes
//
// `sha256_core` produces the digest Python hashlib produces for every message up
// to the single block limit of 55 bytes, from vectors emitted rather than
// transcribed by scripts/gen-rtl-vectors.py. Three of the entries in
// `tests/test_vectors/sha256.txt`, the corpus the vector file is partly built
// from, were wrong when the generator first read them; see that file.
//
// # Single block
//
// 55 bytes is the limit of the core, not of the algorithm: the chaining state is
// a port, so a wrapper can feed several blocks through it.
//
// # Timing
//
// 64 rounds plus load and feed forward. WAIT is above the latency and below the
// point where a core that never finished would look like a hang.

`include "tb_common.svh"

module tb_sha256_core;

    logic         clk = 1'b0;
    logic         rst_n = 1'b0;
    logic         valid = 1'b0;
    logic         ready;
    logic         done;
    logic [511:0] msg_blk;
    logic [255:0] state_in;
    logic [255:0] digest_out;

    `TB_COUNTERS

    sha256_core dut (.*);

    always #5 clk = ~clk;

    `TB_REPORT("sha256_core")
    `TB_CHECK_CORE(32, 16, 256, 256)

    localparam integer WAIT = 110;

    initial begin
        $display("=== sha256_core, FIPS 180-4 vectors, generated from hashlib ===");

        msg_blk  = '0;
        state_in = '0;

        repeat (2) @(posedge clk);
        rst_n = 1'b1;
        @(posedge clk);

        `include "vectors/sha256.svh"

        tb_report("sha256_core");
    end

endmodule