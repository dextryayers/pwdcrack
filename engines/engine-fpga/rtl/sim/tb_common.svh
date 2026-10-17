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

// ---------------------------------------------------------------------------
// Initial values
//
// # Word order in every packed value in this file
//
// Word i occupies `[32*i +: 32]`, so word 0 sits in the LOW 32 bits and word n-1
// at the top. Every packed value here follows that: blocks, states, initial
// values and expected digests alike.
//
// That means an initial value written in the order the specification lists it,
// which puts A in the high bits, is wrong for these cores. MD5's A is 0x67452301
// and it must land at `[31:0]`, so the literal reads `10325476 98badcfe efcdab89
// 67452301`. This is the same transposition `scripts/gen-rtl-vectors.py` corrects
// for digests, and getting it wrong produces a wrong answer rather than an error.
// ---------------------------------------------------------------------------

// The MD5 and MD4 initial state, four words.
function automatic [127:0] md5_iv;
    md5_iv = 128'h10325476_98badcfe_efcdab89_67452301;
endfunction

// The SHA-1 initial state, five words.
function automatic [159:0] sha1_iv;
    sha1_iv = 160'hc3d2e1f0_10325476_98badcfe_efcdab89_67452301;
endfunction

// The SHA-256 and SHA-224 initial state, eight words.
function automatic [255:0] sha256_iv;
    sha256_iv = 256'h5be0cd19_1f83d9ab_9b05688c_510e527f_a54ff53a_3c6ef372_bb67ae85_6a09e667;
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

// Builds the single 512 bit block for SHA-1 and SHA-256.
//
// Same padding rule as MD5 and MD4, but big endian within each word, because
// SHA-1 and SHA-256 read the message most significant byte first. Word i of the
// result is therefore the bytes at offset 4i in big endian order, which is the
// opposite of `md5_padded_block` and not interchangeable with it.
//
// 55 byte ceiling for the same reason: at 56 the terminator would land on the
// first byte of the length field.
function automatic [511:0] sha1_padded_block(input string msg);
    logic [511:0] block;
    int           n;
    int           i;
    logic [7:0]   ch;

    n = msg.len();
    if (n > 55) begin
        $display("FATAL: sha1_padded_block was given a %0d byte message.", n);
        $display("       A single padded block holds at most 55 bytes.");
        $fatal(1, "message too long for one padded block");
    end

    block = '0;

    // The byte goes through a temporary before the shift.
    //
    // `32'(msg[i]) << k` inside the expression does not evaluate as expected under
    // Icarus Verilog: for i = 1 it yields 0x00620000 rather than 0x00000062
    // shifted, so the assembled word came out as 0x61626300 instead of
    // 0x61626380. Loading the byte into a plain integer first makes the shift
    // operate on the value it is supposed to.
    // Bytes are placed with an explicit concatenation, not a variable shift or a
    // part-select assignment.
    //
    // Both alternatives look correct and both are wrong under Icarus Verilog 12:
    //
    //   `32'(msg[i]) << (8 * (3 - (i % 4)))` assembles "abc" as 0x61626300: the
    //   byte at offset 2 never lands. The same expression is right for one and two
    //   byte messages, so a test using only short strings does not see it.
    //   `w[23:16] = msg[1]; w[15:8] = msg[2];` on a word preloaded with msg[0]
    //   gives 0x00626361, with the first byte pushed out.
    //
    // A four byte concatenation reproduces the expected word exactly and is also
    // what a synthesis tool will build, since it is the natural structure.
    for (i = 0; i + 4 <= n; i = i + 4) begin
        block[32 * (i / 4) +: 32] = {
            8'(msg[i]), 8'(msg[i + 1]), 8'(msg[i + 2]), 8'(msg[i + 3])
        };
    end

    // Trailing group of one to three bytes, left aligned as big endian requires.
    if ((n % 4) != 0) begin
        ch = 8'(msg[n - 1]);
        case (n % 4)
            1: block[32 * (n / 4) +: 32] = {ch, 24'h000000};
            2: block[32 * (n / 4) +: 32] = {8'(msg[n - 2]), ch, 16'h0000};
            3: block[32 * (n / 4) +: 32] =
                   {8'(msg[n - 3]), 8'(msg[n - 2]), ch, 8'h00};
        endcase
    end

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

// Defines `tb_report(NAME)`, which prints the tally, ends the simulation, and
// fails the process if anything failed.
//
// # Both exit paths, and why each one is required
//
// On failure: `$fatal(1, ...)`, so the exit status is non zero. A testbench that
// reports failures and exits zero is a testbench whose result can be ignored,
// which is the defect this macro exists to remove.
//
// On success: `$finish`. Without it the free running clock in the testbench
// keeps scheduling events after the last assertion, the simulation never ends,
// and `vvp` runs until something kills it. That is not a slow test, it is a hang
// with no output, and it is indistinguishable from a core that never finished.
// `scripts/simulate.sh` puts a deadline on every run for the same reason, so a
// future testbench that forgets this line is reported as a timeout rather than
// stalling the gate.
//
// The tally is printed before either exit, so the counts survive into the log
// whichever path is taken.
`define TB_REPORT(SUITE) \
    task automatic tb_report(input string suite); \
        begin \
            $display("=== %s: %0d passed, %0d failed, %0d total ===", \
                     suite, pass_count, fail_count, test_num); \
            if (fail_count != 0) begin \
                $fatal(1, "%0d assertion(s) failed in %s", fail_count, suite); \
            end \
            if (test_num == 0) begin \
                $fatal(1, "%s ran no assertions at all", suite); \
            end \
            $finish; \
        end \
    endtask

// Defines `check_core(blk, iv, want, name, cycles)` for any core in `rtl/cores`.
//
// This is the only task a hash core testbench needs, because every core uses the
// same port names and the same handshake: `clk`, `rst_n`, `valid`, `ready`,
// `msg_blk`, `state_in`, `digest_out`, `done`. One task for all of them means a
// new core is tested by writing a module and including a generated vector file,
// with no new stimulus code to get wrong.
//
// Arguments are sized by the macro parameters so the same task drives a 128 bit
// MD5 state and a 512 bit SHA-512 state:
//
//     `TB_CHECK_CORE(32, 16, 128, 128)     MD5, MD4, NTLM: 512 bit block
//     `TB_CHECK_CORE(32, 16, 160, 160)     SHA-1, RIPEMD-160
//     `TB_CHECK_CORE(32, 16, 256, 256)     SHA-256
//     `TB_CHECK_CORE(64, 16, 512, 512)     SHA-512, BLAKE2b
//     `TB_CHECK_CORE(64, 16, 512, 384)     SHA-384, 1024 bit block
//
// `blk`, `iv` and `want` are packed with word 0 in the least significant bits, so
// a digest literal is written with its words reversed relative to the printed
// digest. scripts/gen-rtl-vectors.py does that and re-reads what it wrote.
//
// # Why the wait polls on the falling edge
//
// `done` is a one cycle pulse and the output registers are written by non
// blocking assignment on the rising edge. Both are correct only in the window
// between one rising edge and the next.
//
// Polling on `@(posedge clk)` reads `done` in the active region, which is one
// delta after the non blocking update that raised it. By the time the loop re
// tests, the core has already scheduled `done` low again for the next cycle, so
// the loop runs one edge past the pulse and then finds `done` low. That reads as
// a core that never fired. Polling on the falling edge puts both the flag and
// the data in the same cycle, which is the only place they are in step.
`define TB_CHECK_CORE(W, NW, IW, DW) \
    task automatic check_core( \
        input [(NW*W)-1:0] blk, \
        input [IW-1:0] iv, \
        input [DW-1:0] want, \
        input string name, \
        input integer cycles \
    ); \
        int waited; \
        int saw_done; \
        logic [DW-1:0] got; \
        begin \
            /* Wait for the core to be ready. A core that is always ready */ \
            /* passes immediately; an iterative one holds here while busy. */ \
            waited = 0; \
            while (ready !== 1'b1 && waited < cycles) begin \
                @(negedge clk); \
                waited = waited + 1; \
            end \
            if (ready !== 1'b1) begin \
                `TB_FAIL_NOTE(name, "core never became ready"); \
            end else begin \
                /* Drive from a falling edge. Values set immediately after a */ \
                /* rising edge are visible for half a cycle, and the core's */ \
                /* next sampling edge is a whole cycle away, so the block is */ \
                /* never captured. `done` then never fires for that vector and */ \
                /* every following vector compares against the previous */ \
                /* block's digest: a silent off by one that looks like a core */ \
                /* that computes MD5 slightly wrong. */ \
                @(negedge clk); \
                msg_blk   <= blk; \
                state_in  <= iv; \
                valid     <= 1'b1; \
                @(negedge clk); \
                valid     <= 1'b0; \
                waited = 0; \
                saw_done = 0; \
                while (waited < cycles && saw_done == 0) begin \
                    @(negedge clk); \
                    waited = waited + 1; \
                    if (done === 1'b1) saw_done = 1; \
                end \
                /* Sample in the same cycle the flag was seen. Half a cycle */ \
                /* later the core has moved on to the next transaction. */ \
                got = digest_out; \
                if (saw_done == 0) begin \
                    `TB_FAIL_NOTE(name, "no done signal"); \
                end else if (got === want) begin \
                    `TB_PASS(name); \
                end else begin \
                    $display("  FAIL [%0d]: %s", test_num, name); \
                    $display("        got      %h", got); \
                    $display("        expected %h", want); \
                    fail_count = fail_count + 1; \
                    test_num   = test_num + 1; \
                end \
            end \
        end \
    endtask

// Defines `check_ntlm(pw, want, name, cycles)` for `ntlm_core`.
//
// NTLM needs its own task only because it takes the ASCII password and a length
// instead of a block: the UTF-16-LE encoding happens on the device, and building
// it on the host would leave the device side of that conversion untested, which
// is the part that can be wrong.
//
// A password that does not fit one UTF-16-LE block cannot be hashed by this
// core. The vector file contains one such length on purpose and the core is
// expected to refuse it with `done` and an error flag; see `check_ntlm_too_long`.
`define TB_CHECK_NTLM(MAXCHARS) \
    task automatic drive_ntlm( \
        input string pw, \
        input string name, \
        input integer cycles, \
        output int saw_done \
    ); \
        int waited; \
        begin \
            saw_done = 0; \
            while (ready !== 1'b1 && waited < cycles) begin \
                @(negedge clk); \
                waited = waited + 1; \
            end \
            @(negedge clk); \
            pass_bytes = '0; \
            for (int i = 0; i < pw.len() && i < 64; i = i + 1) \
                pass_bytes[8*i +: 8] = pw[i]; \
            pass_len = pw.len(); \
            valid <= 1'b1; \
            @(negedge clk); \
            valid <= 1'b0; \
            waited = 0; \
            while (waited < cycles && done !== 1'b1 && too_long !== 1'b1) begin \
                @(negedge clk); \
                waited = waited + 1; \
            end \
            saw_done = (done === 1'b1); \
        end \
    endtask \
    task automatic check_ntlm( \
        input string pw, \
        input [127:0] want, \
        input string name, \
        input integer cycles \
    ); \
        int saw; \
        begin \
            drive_ntlm(pw, name, cycles, saw); \
            if (saw == 0) begin \
                `TB_FAIL_NOTE(name, "no done signal"); \
            end else if (digest_out === want) begin \
                `TB_PASS(name); \
            end else begin \
                $display("  FAIL [%0d]: %s", test_num, name); \
                $display("        got      %h", digest_out); \
                $display("        expected %h", want); \
                fail_count = fail_count + 1; \
                test_num   = test_num + 1; \
            end \
        end \
    endtask \
    task automatic check_ntlm_too_long( \
        input string pw, \
        input string name, \
        input integer cycles \
    ); \
        int saw; \
        begin \
            drive_ntlm(pw, name, cycles, saw); \
            /* A refused password must raise `too_long` and must not */ \
            /* produce a digest: acting on a truncated password is a */ \
            /* wrong answer that looks like a right one. */ \
            if (saw == 0 && too_long === 1'b1) begin \
                `TB_PASS(name); \
            end else begin \
                `TB_FAIL_NOTE(name, \
                    "an over long password must raise too_long and no done"); \
            end \
        end \
    endtask

// Defines `check_crc(data, n, want, name, cycles)` and
// `check_crc_empty(want, name, cycles)` for `crc32_accel`.
//
// The bytes arrive as one packed literal plus a count rather than as an array.
// A subroutine port carrying an unpacked dimension is rejected outright by Icarus
// Verilog 12, which is the whole reason no port in this file is an array; a
// packed literal with an explicit length sidesteps that without reintroducing
// hand transcription, because the generator emits it.
//
// A byte at a time, because that is the interface the protocol needs: the CRC
// covers a packet whose length is not known until the last byte has been sent.
// `byte_last` marks it and the core then applies the final XOR. `crc_init`
// starts a fresh message, which is what makes a zero length message testable.
`define TB_CHECK_CRC \
    task automatic drive_crc_byte( \
        input logic [7:0] b, \
        input logic last \
    ); \
        begin \
            data_in   <= b; \
            valid     <= 1'b1; \
            byte_last <= last; \
            @(negedge clk); \
            valid     <= 1'b0; \
            byte_last <= 1'b0; \
        end \
    endtask \
    task automatic check_crc( \
        input [511:0] data, \
        input integer n, \
        input [31:0] want, \
        input string name, \
        input integer cycles \
    ); \
        int waited; \
        int i; \
        begin \
            crc_init <= 1'b0; \
            for (i = 0; i < n; i = i + 1) \
                drive_crc_byte(data[8*i +: 8], i == n - 1); \
            waited = 0; \
            while (waited < cycles && done !== 1'b1) begin \
                @(negedge clk); \
                waited = waited + 1; \
            end \
            if (done !== 1'b1) begin \
                `TB_FAIL_NOTE(name, "no done signal"); \
            end else if (crc_out === want) begin \
                `TB_PASS(name); \
            end else begin \
                $display("  FAIL [%0d]: %s", test_num, name); \
                $display("        got      %08x", crc_out); \
                $display("        expected %08x", want); \
                fail_count = fail_count + 1; \
                test_num   = test_num + 1; \
            end \
        end \
    endtask \
    task automatic check_crc_empty( \
        input logic [31:0] want, \
        input string name, \
        input integer cycles \
    ); \
        int waited; \
        begin \
            crc_init <= 1'b1; \
            data_in  <= 8'h00; \
            valid    <= 1'b1; \
            byte_last <= 1'b1; \
            @(negedge clk); \
            valid     <= 1'b0; \
            byte_last <= 1'b0; \
            crc_init  <= 1'b0; \
            waited = 0; \
            while (waited < cycles && done !== 1'b1) begin \
                @(negedge clk); \
                waited = waited + 1; \
            end \
            if (done !== 1'b1) begin \
                `TB_FAIL_NOTE(name, "no done signal"); \
            end else if (crc_out === want) begin \
                `TB_PASS(name); \
            end else begin \
                $display("  FAIL [%0d]: %s", test_num, name); \
                $display("        got      %08x", crc_out); \
                $display("        expected %08x", want); \
                fail_count = fail_count + 1; \
                test_num   = test_num + 1; \
            end \
        end \
    endtask