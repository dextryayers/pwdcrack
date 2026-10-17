// Top level testbench.
//
// # What this establishes
//
// `rtl/top.sv` instantiates every verified core and muxes them onto one wide
// port. The per core testbenches prove the cores; this proves the wiring.
//
// That is not a formality. A mux wired to the wrong core produces a digest that
// is correct for a different algorithm, and no per core test can see it: every
// core still passes its own vectors. The failure appears on hardware, or in a
// cracker, as a hash that never matches, or worse as one that does.
//
// The vectors are the same ones each core was verified against, the message
// being the single block limit so the length field is exercised too.
//
// # One task, wide arguments
//
// `check_top` takes 1024 and 512 bit arguments for every core. Each core's own
// literal is zero extended by the generator, and the upper bits are above every
// core's payload, so one task drives all of them. That is why this file needs no
// per core task: the comparison is against the zero extended expectation, and a
// core that returned a short digest would differ in the bits above its own
// payload, which is caught.

`include "tb_common.svh"

module tb_top;

    logic          clk = 1'b0;
    logic          rst_n = 1'b0;
    logic [3:0]    hash_sel = 4'h0;
    logic          valid = 1'b0;
    logic          ready;
    logic          done;
    logic [1023:0] msg_blk;
    logic [511:0]  state_in;
    logic [511:0]  digest_out;
    logic          crc_init = 1'b0;
    logic          crc_valid = 1'b0;
    logic          crc_byte_last = 1'b0;
    logic [7:0]    crc_byte_in = 8'h00;
    logic [31:0]   crc_out;
    logic          crc_done;

    `TB_COUNTERS

    pwdcrack_top dut (.*);

    always #5 clk = ~clk;

    `TB_REPORT("pwdcrack_top")

    // Long enough for the slowest core in the mux: SHA-512 and SHA-384 at 82
    // cycles, plus load and feed forward.
    localparam integer WAIT = 150;

    // Drives one block through the mux and compares the selected core's digest.
    //
    // The selector is set two cycles before `valid` so it is settled at the core's
    // sampling edge. Setting it in the same cycle as `valid` is the same half
    // cycle problem `check_core` documents.
    task automatic check_top(
        input [3:0]    sel,
        input [1023:0] blk,
        input [511:0]  iv,
        input [511:0]  want,
        input string   name,
        input integer  cycles
    );
        int waited;
        begin
            hash_sel = sel;
            @(negedge clk);
            hash_sel = sel;
            msg_blk   = blk;
            state_in  = iv;
            valid     = 1'b1;
            @(negedge clk);
            valid     = 1'b0;
            waited = 0;
            while (waited < cycles && done !== 1'b1) begin
                @(negedge clk);
                waited = waited + 1;
            end
            if (done !== 1'b1) begin
                `TB_FAIL_NOTE(name, "no done signal from the selected core");
            end else if (digest_out === want) begin
                `TB_PASS(name);
            end else begin
                $display("  FAIL [%0d]: %s", test_num, name);
                $display("        selector  %h", sel);
                $display("        got       %h", digest_out);
                $display("        expected  %h", want);
                fail_count = fail_count + 1;
                test_num   = test_num + 1;
            end
        end
    endtask

    initial begin
        $display("=== pwdcrack_top, one vector per core through the mux ===");

        msg_blk  = '0;
        state_in = '0;

        repeat (2) @(posedge clk);
        rst_n = 1'b1;
        @(posedge clk);

        `include "vectors/top.svh"

        // The selector must not leak, and the cores must not share state. Two
        // vectors with no reset in between prove both: if a core kept a previous
        // result, the second run would return the first one.
        //
        // The block is the padded empty message, so word 0 is 0x00000080, the
        // terminator in the low byte, because MD5 reads words little endian. An
        // all zero block is a different message: it digests to
        // f90ca6392b68d832a5483681f7cd1c97, which is what this test produced
        // before the block was corrected.
        check_top(4'h0,
                  1024'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080,
                  512'h1032547698badcfeefcdab8967452301,
                  // Word 0 at the low bits, so the printed digest reads
                  // backwards here: d41d8cd9 8f00b204 e9800998 ecf8427e is
                  // 7e42f8ec 980980e9 04b2008f d98c1dd4 packed.
                  512'h7e42f8ec980980e904b2008fd98c1dd4,
                  "md5 through the top, second run", WAIT);

        tb_report("pwdcrack_top");
    end

endmodule