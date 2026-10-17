// Padding testbench for MD4, MD5 and SHA-256 style messages.
//
// # Why this is separate from the core testbenches
//
// A one block core cannot check padding past 55 bytes, because the message does
// not fit. `md5_padded_block` refuses anything longer, which is correct, but it
// leaves the 56, 64 and 119 byte cases with no coverage anywhere.
//
// Those are exactly the lengths where a padding loop written with the wrong
// comparison goes wrong. The terminator must land on the first byte after the
// message and the length field starts at byte 56 of the final block. A loop that
// checks `len % 64 != 56` before appending the terminator rather than after
// produces a different block at 55 and at 56 and nowhere else in the range. No
// core in this repository can be fed those messages, so the padding itself has to
// be verified directly. That is what this file does.
//
// # Word order in the literals
//
// The helpers place word i at `[32*i +: 32]`, so word 0 occupies the lowest 32
// bits and a hex literal must therefore list word 15 first. The literals below
// were generated with that reversal applied; writing them the other way round
// transposes the message and is the same class of error as the endianness bug in
// the old `md5_tb.sv`.

`include "tb_common.svh"

module tb_padding;

    `TB_COUNTERS
    `TB_REPORT("padding")

    logic [511:0] b0;
    logic [511:0] b1;
    int           blocks;

    // Compares one produced block against the oracle block, word by word, and
    // names the first word that differs.
    task automatic check_block_words(
        input [511:0] got,
        input [511:0] want,
        input string  name
    );
        int first_bad;
        begin
            first_bad = -1;
            for (int i = 0; i < 16; i = i + 1) begin
                if (got[32*i +: 32] !== want[32*i +: 32] && first_bad < 0)
                    first_bad = i;
            end
            if (first_bad < 0) begin
                `TB_PASS(name);
            end else begin
                $display("  FAIL [%0d]: %s", test_num, name);
                $display("        first differing word is %0d", first_bad);
                $display("        got      %08x", got[32*first_bad +: 32]);
                $display("        expected %08x", want[32*first_bad +: 32]);
                fail_count = fail_count + 1;
                test_num   = test_num + 1;
            end
        end
    endtask

    initial begin
        $display("=== MD4/MD5/SHA-256 padding ===");

        // ---- Oracle blocks, generated from Python struct.pack ----
        // The message is 64 repetitions of y. Its bytes are not
        // symmetric, so a block built with the wrong word order differs
        // visibly rather than matching by accident.

        check_block_words(md5_padded_block(""),
            512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080,
            "empty");

        check_block_words(md5_padded_block("y"),
            512'h00000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008079,
            "one byte");

        check_block_words(md5_padded_block("yyy"),
            512'h00000000000000180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080797979,
            "three bytes");

        check_block_words(md5_padded_block("yyyyyyyyyyyyyy"),
            512'h00000000000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000807979797979797979797979797979,
            "fourteen bytes");

        check_block_words(md5_padded_block("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"),
            512'h00000000000001b88079797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
            "55 bytes, the longest that fits one block");

        md5_pad_blocks("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", b0, b1, blocks);
        if (blocks != 2) `TB_FAIL_NOTE("56 bytes, the first length needing a second block", "expected 2 blocks");
        check_block_words(b0,
            512'h00000000000000807979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
            "56 bytes, the first length needing a second block, block 0");
        check_block_words(b1,
            512'h00000000000001c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,
            "56 bytes, the first length needing a second block, block 1");

        md5_pad_blocks("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", b0, b1, blocks);
        if (blocks != 2) `TB_FAIL_NOTE("64 bytes, exactly one full block", "expected 2 blocks");
        check_block_words(b0,
            512'h79797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
            "64 bytes, exactly one full block, block 0");
        check_block_words(b1,
            512'h00000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080,
            "64 bytes, exactly one full block, block 1");

        md5_pad_blocks("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", b0, b1, blocks);
        if (blocks != 2) `TB_FAIL_NOTE("119 bytes, the two block ceiling", "expected 2 blocks");
        check_block_words(b0,
            512'h79797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
            "119 bytes, the two block ceiling, block 0");
        check_block_words(b1,
            512'h00000000000003b88079797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
            "119 bytes, the two block ceiling, block 1");

        tb_report("padding");
    end

endmodule
