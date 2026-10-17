// NTLM core testbench.
//
// # What this establishes
//
// Two things at once. `ntlm_core` produces the NTLMv1 hash of every password in
// the vector file, and `md4_core`, which it instantiates, is covered again from
// the outside: if the UTF-16-LE block this file builds is malformed, the MD4
// core will faithfully hash the malformed block and the vector will fail.
//
// The digests come from scripts/gen-rtl-vectors.py: a pure Python MD4 over
// UTF-16-LE, held against OpenSSL's MD4 and the RFC 1320 test suite.
//
// # The over long case
//
// The last vector is a password that does not fit in one MD4 block. The
// expectation is `too_long` and no `done`, never a digest of a truncated
// password. A core that hashed 28 characters and reported the result would be
// reporting a hash of a different password, which is worse than reporting
// nothing.

`include "tb_common.svh"

module tb_ntlm_core;

    logic         clk = 1'b0;
    logic         rst_n = 1'b0;
    logic         valid = 1'b0;
    logic         ready;
    logic         done;
    logic         too_long;
    logic [511:0] pass_bytes;
    logic [6:0]   pass_len;
    logic [127:0] digest_out;

    `TB_COUNTERS

    ntlm_core dut (.*);

    always #5 clk = ~clk;

    `TB_REPORT("ntlm_core")
    `TB_CHECK_NTLM(27)

    // MD4 needs 48 rounds plus load and feed forward, plus this core's own
    // start cycle.
    localparam integer WAIT = 90;

    initial begin
        $display("=== ntlm_core, NTLMv1 vectors, generated from MD4 over UTF-16-LE ===");

        pass_bytes = '0;
        pass_len   = 7'd0;

        repeat (2) @(posedge clk);
        rst_n = 1'b1;
        @(posedge clk);

        `include "vectors/ntlm.svh"

        // 28 characters: two bytes each is 56, one more than a block holds.
        check_ntlm_too_long("AAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                            "ntlm(28 characters, refused rather than truncated)",
                            WAIT);

        tb_report("ntlm_core");
    end

endmodule