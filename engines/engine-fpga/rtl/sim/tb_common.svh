// Shared testbench support for the FPGA cores.
//
// # Why this file exists
//
// Every core testbench needs the same four things: build an input block, drive
// the core, wait for the result, and compare it against an expected value with a
// pass or fail line. Eight testbenches each had their own copy, written in
// SystemVerilog that Icarus Verilog 12 cannot parse. None of them ever ran.
//
// # Icarus Verilog 12 limitations this header works around
//
// Each was confirmed by compiling a minimal case, not assumed:
//
//   1. Assignment patterns are unsupported. Neither in a procedural assignment
//      (`w = '{default: '0}`) nor as a task argument. Every vector in every old
//      testbench used them.
//   2. Subroutine ports may not carry unpacked dimensions, so no task can take
//      `input [31:0] m [15:0]`.
//   3. Assignment to an entire unpacked array is unsupported, in a continuous
//      assignment and in always_comb alike.
//   4. Tasks reached through `include` land in the `$unit` scope, so they cannot
//      see the including module's signals or counters. Confirmed by compiling
//      `tb_common.svh` as an include and reading the errors.
//
// # The quietest trap in this file
//
// A quoted string passed to a vector task argument is silently mis-encoded.
//
//     task automatic show(input [127:0] v); ...
//     show("d41d8cd98f00b204e9800998ecf8427e");   // yields 65393830303939386563663834323765
//     show(128'hd41d8cd98f00b204e9800998ecf8427e); // yields d41d8cd98f00b204e9800998ecf8427e
//
// The first produces a value with no relation to the characters, and Icarus
// reports no error of any kind. Every test then fails with an expected value that
// looks like a mangled digest, which reads as a core defect rather than as a
// testbench bug. This cost an afternoon of chasing a working MD5 core.
//
// Always pass digests as sized hex literals: `128'h...` for MD5 and MD4,
// `160'h...` for SHA-1, `256'h...` for SHA-224 and SHA-256,
// `512'h...` for SHA-384 and SHA-512. `scripts/gen-rtl-vectors.py` emits them
// correctly for this reason.
//
// Module ports with unpacked arrays do work, so the cores keep their existing
// interfaces. Everything above is a testbench side problem. The fix is the split
// below: pure helpers stay functions reached through `include`, and anything
// touching a module signal becomes a macro, because a macro expands textually
// inside the module and sidesteps the scope problem entirely.
//
// # Usage
//
//     `include "tb_common.svh"
//     module tb_whatever;
//         logic clk = 0;
//         logic rst_n = 0;
//         logic valid = 0, ready, done;
//         logic [31:0] msg_word [15:0];
//         logic [31:0] h_in [3:0];
//         logic [31:0] h_out [3:0];
//
//         `TB_COUNTERS
//         `TB_REPORT("whatever")
//         `TB_CHECK_BLOCK(16)      // 16 message words
//         `TB_DRIVE_BLOCK(4)       // 4 state words
//
//         // ...
//         initial begin
//             check_message("abc", md5_iv(), "<digest>", "md5(abc)", 200);
//             tb_report("whatever");
//         end
//     endmodule

// ---------------------------------------------------------------------------
// Pure helpers. Reached through `include`; none of these touch module scope.
// ---------------------------------------------------------------------------

// The MD5 and MD4 initial value, as four little endian words.
//
// Word i of MD5 is word i of the digest as printed, so this is the digest
// `67452301 efcdab89 98badcfe 10325476` with no reordering.
function automatic [127:0] md5_iv;
    md5_iv = 128'h67452301_efcdab89_98badcfe_10325476;
endfunction

// The SHA-256 and SHA-224 initial state, eight words.
function automatic [255:0] sha256_iv;
    sha256_iv = 256'h6a09e667_bb67ae85_3c6ef372_a54ff53a_510e527f_9b05688c_1f83d9ab_5be0cd19;
endfunction

// The SHA-1 initial state, five words.
function automatic [159:0] sha1_iv;
    sha1_iv = 160'h67452301_efcdab89_98badcfe_10325476_c3d2e1f0;
endfunction

// Builds the single 512 bit block for a message short enough to fit one block.
//
// MD4 and MD5 pad identically: the message, then one 0x80 byte, then zeros, then
// the message length in bits as a 64 bit little endian value in the final eight
// bytes. Sixteen little endian words result, word 0 first.
//
// `blk[32*i +: 32]` is word i, so word 14 holds the low 32 bits of the length and
// word 15 the high 32, which is zero for any message below 512 megabytes.
//
// The block is built here rather than transcribed as a literal per vector. A
// transcribed block is 64 hex digits with no internal check, and the old MD5
// testbench got three of four wrong that way. Deriving the block from the
// message leaves the digest as the only transcribed value.
//
// Length limit: 55 bytes, and the check is enforced rather than left in a
// comment. The terminator lands at byte 55 for a 55 byte message and the length
// field starts at byte 56, so 55 is the longest single block message. At 56 the
// terminator would be written over the first byte of the length field, and at 64
// it would be written past the end of the vector. Both corrupt the block without
// any diagnostic. Messages of 56 bytes and above need a second block and belong
// in `tb_padding`, which exercises the padding itself across that boundary.
//
// `md5_padded_block` and `sha256_padded_block` agree on all sixteen words for
// every message under 56 bytes, because MD4, MD5 and SHA-256 share the same
// padding length encoding. They differ only in what the block means.
function automatic [511:0] md5_padded_block(input string msg);
    logic [511:0] block;
    int           n;
    int           i;

    n = msg.len();
    if (n > 55) begin
        $display("FATAL: md5_padded_block was given a %0d byte message.", n);
        $display("       A single padded block holds at most 55 bytes.");
        $fatal(1, "message too long for one padded block");
    end

    block = '0;

    for (i = 0; i < n; i = i + 1) begin
        block[32 * (i / 4) +: 32] =
            block[32 * (i / 4) +: 32] | (32'(msg[i]) << (8 * (i % 4)));
    end

    // `(8 * n) +: 8`, not `[8 * n]`. A plain bit select truncates 8'h80 to its low
    // bit, which is zero, so the terminator would never be written. The parenthesised
    // base is also required, since `8 * n +: 8` binds as `8 * (n +: 8)`.
    block[(8 * n) +: 8] = 8'h80;
    block[32 * 14 +: 32] = n * 8;

    return block;
endfunction

// Pads a message of up to 119 bytes into one or two blocks.
//
// Sets `blocks` to 1 when the message fits one block and 2 when it does not.
// `b0` receives the first block and `b1` the second, left zero when only one is
// needed. The length field carries the whole message length, not the remainder,
// which is the detail a two block implementation gets wrong most easily and
// which no single block test can reach.
//
// The layout is derived rather than special cased, because special casing it is
// where the earlier version of this function went wrong. For a 56 byte message
// the terminator lands in block 0 at byte 56 and block 1 is nothing but zeros
// and the length; for 64 bytes the terminator opens block 1 instead. The rule
// that covers both is:
//
//   1. The terminator sits at global byte n, in whichever block holds byte n.
//   2. Zeros fill from there until byte 56 of the final block.
//   3. The 64 bit little endian length occupies bytes 56..63 of the final block.
//
// Step 1 is what a `block = n / 64` shortcut gets wrong for every length from 56
// to 63, and step 2 is what an `n % 64` shortcut gets wrong for lengths that fill
// a block exactly. Both were found by the oracle vectors in `tb_padding`.
//
// The 119 byte ceiling is deliberate: 119 plus terminator plus length is exactly
// 128, and 120 bytes needs a third block. No core here consumes more than two, so
// supporting a third would be untested code.
//
// A task rather than a function because Icarus Verilog 12 rejects output ports on
// functions outright. The task lives in `$unit` via the include and needs no
// module scope, so that costs nothing.
task automatic md5_pad_blocks(
    input string msg,
    output logic [511:0] b0,
    output logic [511:0] b1,
    output int blocks
);
    int n;
    int i;
    int after_terminator;
    int zeros;
    int total;

    n = msg.len();
    if (n > 119) begin
        $display("FATAL: md5_pad_blocks was given a %0d byte message.", n);
        $display("       The ceiling is 119 bytes, two blocks.");
        $fatal(1, "message too long for two padded blocks");
    end

    // Derive the total length first, so the terminator, the zero run and the
    // length field all land relative to the same block boundary.
    after_terminator = n + 1;
    zeros = (56 - (after_terminator % 64) + 64) % 64;
    total = after_terminator + zeros + 8;
    blocks = total / 64;

    b0 = '0;
    b1 = '0;

    // Message bytes, little endian within each word.
    for (i = 0; i < n; i = i + 1) begin
        if (i < 64) begin
            b0[32 * (i / 4) +: 32] =
                b0[32 * (i / 4) +: 32] | (32'(msg[i]) << (8 * (i % 4)));
        end else begin
            b1[32 * ((i - 64) / 4) +: 32] =
                b1[32 * ((i - 64) / 4) +: 32] | (32'(msg[i]) << (8 * (i % 4)));
        end
    end

    // Terminator at global byte n, in whichever block holds it.
    //
    // Two mistakes live here and both were made before the oracle vectors caught
    // them:
    //
    //   `[8*n]` is a bit select, so writing 8'h80 truncates it to its low bit,
    //   zero, and the terminator is never written at all.
    //   `8*n +: 8` binds as `8 * (n +: 8)` because `+:` has no precedence of its
    //   own, so the base must be parenthesised: `(8 * n) +: 8`.
    if (n < 64) begin
        b0[(8 * n) +: 8] = 8'h80;
    end else begin
        b1[(8 * (n - 64)) +: 8] = 8'h80;
    end

    // Length in the final block, bytes 56..63.
    if (blocks == 1) begin
        b0[32 * 14 +: 32] = n * 8;
    end else begin
        b1[32 * 14 +: 32] = n * 8;
    end
endtask

// The same padding rule, named for SHA-256. See `md5_padded_block`: the two
// produce identical blocks for messages under 56 bytes, which is a fact about
// the padding and not about the hash functions.
function automatic [511:0] sha256_padded_block(input string msg);
    sha256_padded_block = md5_padded_block(msg);
endfunction

// Builds a block from explicitly stated words, for vectors whose length field
// does not follow from the message.
//
// `words` is packed, word i at `words[32*i +: 32]`. Prefer the padding functions
// when the message is a normal one: stating sixteen words by hand is the step
// that produced the earlier endianness errors.
function automatic [511:0] block_from_words(input [511:0] words);
    block_from_words = words;
endfunction

// ---------------------------------------------------------------------------
// Macros. Expand inside the testbench module, where module scope is visible.
// ---------------------------------------------------------------------------

// Declares the tally the reporting macros use.
`define TB_COUNTERS \
    int pass_count = 0; \
    int fail_count = 0; \
    int test_num   = 0;

// Advances to the next vector and prints a pass line.
`define TB_PASS(NAME) \
    begin \
        $display("  PASS [%0d]: %s", test_num, NAME); \
        pass_count = pass_count + 1; \
        test_num   = test_num + 1; \
    end

// Prints a failing digest comparison and advances.
//
// Both sides are printed as four 32 bit words in order, not as one wide vector.
// Word 0 lives at `[31:0]` so that it maps to port index 0, and `%x` on the whole
// vector would therefore print word 3 first: the digest backwards. Printing the
// words separately keeps the output in digest order.
`define TB_FAIL_DIGEST(NAME, GOT, WANT) \
    begin \
        $display("  FAIL [%0d]: %s", test_num, NAME); \
        $display("        got      %08x%08x%08x%08x", \
                 GOT[127:96], GOT[95:64], GOT[63:32], GOT[31:0]); \
        $display("        expected %08x%08x%08x%08x", \
                 WANT[127:96], WANT[95:64], WANT[63:32], WANT[31:0]); \
        fail_count = fail_count + 1; \
        test_num   = test_num + 1; \
    end

// Prints a failure with a note instead of a value, for a core that never
// asserted done or produced nothing comparable.
`define TB_FAIL_NOTE(NAME, NOTE) \
    begin \
        $display("  FAIL [%0d]: %s (%s)", test_num, NAME, NOTE); \
        fail_count = fail_count + 1; \
        test_num   = test_num + 1; \
    end

// Defines `tb_report(NAME)`, which prints the tally and fails the process if
// anything failed.
//
// `$fatal` rather than `$finish`, so the exit status is non zero. A testbench
// that reports failures and exits zero is a testbench whose result can be
// ignored, which is the defect this macro exists to remove.
`define TB_REPORT(SUITE) \
    task automatic tb_report(input string suite); \
        begin \
            $display("=== %s: %0d passed, %0d failed, %0d total ===", \
                     suite, pass_count, fail_count, test_num); \
            if (fail_count != 0) begin \
                $fatal(1, "%0d assertion(s) failed in %s", fail_count, suite); \
            end \
        end \
    endtask

// Defines `check_block(blk, iv, want, name, cycles)` for a core whose ports are
// named `clk`, `msg_word`, `h_in`, `h_out`, `valid` and `done`.
//
// `blk`, `iv` and `want` are packed with word i at `[32*i +: 32]`, so a digest
// appears in its printed order and the port indices line up.
//
// The wait for `done` is bounded. A core that never completes and a core that
// completes wrongly need different investigations, so the two are reported
// separately.
`define TB_CHECK_BLOCK(NWORDS) \
    task automatic check_block( \
        input [((NWORDS)*32)-1:0] blk, \
        input [127:0] iv, \
        input [127:0] want, \
        input string name, \
        input integer cycles \
    ); \
        int waited; \
        logic [127:0] got; \
        begin \
            @(posedge clk); \
            for (int i = 0; i < (NWORDS); i = i + 1) \
                msg_word[i] <= blk[32*i +: 32]; \
            for (int i = 0; i < 4; i = i + 1) \
                h_in[i] <= iv[32*i +: 32]; \
            @(posedge clk); \
            valid <= 1'b1; \
            @(posedge clk); \
            valid <= 1'b0; \
            /* `done` is driven by the core. The testbench only watches it. */ \
            waited = 0; \
            while (waited < cycles && done !== 1'b1) begin \
                @(posedge clk); \
                waited = waited + 1; \
            end \
            /* Sample on the falling edge, not here. `done` and the output */ \
            /* registers are both updated by non blocking assignment at the */ \
            /* rising edge, and those updates land after the active region, so */ \
            /* reading on the rising edge sees the previous transaction. Half a */ \
            /* cycle later every update has settled and the pairing is right. */ \
            @(negedge clk); \
            /* Pack the words into a plain vector. A concatenation cannot be bit */ \
            /* selected in Verilog, so TB_FAIL_DIGEST cannot index one. */ \
            got = {h_out[3], h_out[2], h_out[1], h_out[0]}; \
            if (done !== 1'b1) begin \
                `TB_FAIL_NOTE(name, "no done signal"); \
            end else if (got === want) begin \
                `TB_PASS(name); \
            end else begin \
                `TB_FAIL_DIGEST(name, got, want); \
            end \
        end \
    endtask

// Defines `check_message(msg, iv, want, name, cycles)`.
//
// Pads the message into one block, then delegates. The digest is the only
// transcribed value, which is one number to get wrong rather than seventeen.
`define TB_CHECK_MESSAGE(NWORDS) \
    task automatic check_message( \
        input string msg, \
        input [127:0] iv, \
        input [127:0] want, \
        input string name, \
        input integer cycles \
    ); \
        begin \
            check_block(md5_padded_block(msg), iv, want, name, cycles); \
        end \
    endtask