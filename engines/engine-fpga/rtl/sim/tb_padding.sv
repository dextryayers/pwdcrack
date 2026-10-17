// Padding testbench for MD4, MD5, RIPEMD-160 and SHA-1 style messages.
//
// # Why this is separate from the core testbenches
//
// A single block core cannot check padding past 55 bytes, because the message
// does not fit. The padding helpers in tb_common.svh refuse anything longer,
// which is correct and which leaves the 56, 64 and 119 byte cases with no
// coverage anywhere.
//
// Those are exactly the lengths where a padding loop written with the wrong
// comparison goes wrong. The terminator must land on the first byte after the
// message and the length field starts at byte 56 of the final block. A loop that
// checks `len % 64 != 56` before appending the terminator rather than after
// produces a different block at 55 and at 56 and nowhere else in the range. No
// core in this repository can be fed those messages, so the padding itself has
// to be verified directly.
//
// # Against what
//
// `scripts/gen-rtl-vectors.py`, from `struct.pack`. The blocks in
// `vectors/padding.svh` are emitted, not transcribed: the previous version of
// this file carried them as literals, and three of the four MD5 blocks were
// wrong, using big endian word order where MD5 needs little endian and placing
// the length field in word 13 instead of word 14.
//
// The same generator produces the block and the digest for each core, so a
// padding error here and a core error there cannot both be explained by the
// same mistake.

`include "tb_common.svh"

module tb_padding;

    `TB_COUNTERS
    `TB_REPORT("padding")

    logic [511:0] b0;
    logic [511:0] b1;
    int           blocks;

    // Compares one produced block against the oracle block, word by word, and
    // names the first word that differs. Word by word because a whole block
    // comparison only says "wrong", and the first differing word says which
    // half of the padding rule is wrong.
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
        $display("=== MD4/MD5/RIPEMD-160/SHA-1 padding, generated from struct.pack ===");

        `include "vectors/padding.svh"

        tb_report("padding");
    end

endmodule