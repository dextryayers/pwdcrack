// NTLMv1 core: MD4 over the password encoded as UTF-16-LE.
//
// STATUS: VERIFIED against every vector in `rtl/sim/vectors/ntlm.svh`, which
// scripts/gen-rtl-vectors.py emits from a Python MD4 over UTF-16-LE, itself
// held against OpenSSL's MD4.
//
// # Why this is a wrapper and not another algorithm
//
// NTLMv1 is defined as MD4(UTF16LE(password)). There is no arithmetic of its
// own, only the encoding, so the interesting part is the encoding and this core
// is deliberately thin: it builds the block and instantiates `md4_core`. That
// also means one hash core is covered by two testbenches, `tb_md4_core` for the
// compression function and this one for the encoding in front of it.
//
// # The encoding, in detail
//
// Each character becomes two bytes, the character then zero, which on a little
// endian machine is a 16 bit word holding the character. The block is then the
// ordinary MD4 block of those bytes: terminator 0x80, zeros, and a length field
// counting BITS, so a password of L characters has a length field of 16L.
//
// A block holds 55 bytes of message, so 27 characters fit exactly: 27 pairs are
// 54 bytes, the terminator lands at byte 54, byte 55 is zero, and the length
// field occupies bytes 56 to 63.
//
// A 28 character password does not fit, and this core says so with `overrun`
// rather than hashing a truncated password. A truncated NTLM hash is a wrong
// answer that looks like a right one, and a cracking tool that reports it as a
// mismatch has silently lost the candidate. Longer passwords are the CPU
// engine's job: they are rare, and a multi block MD4 wrapper is a different
// core that would need its own vectors.
//
// # Interface
//
// Different from the other cores on purpose: it takes the password rather than a
// block, because building the block is what it is here to do. The ports are
// packed for the same reason as everywhere else in this design: an unpacked
// array port does not propagate to the parent under Icarus Verilog 12.

module ntlm_core (
    input  logic          clk,
    input  logic          rst_n,
    input  logic          valid,
    output logic          ready,
    // The password, byte i at [8*i +: 8]. Bytes past `pass_len` are ignored.
    input  logic [511:0]  pass_bytes,
    // Character count, not byte count. Seven bits covers the 64 byte port.
    input  logic [6:0]    pass_len,
    output logic [127:0]  digest_out,
    output logic          done,
    // Set for one cycle when the password is too long for a single MD4 block.
    // `done` does not pulse in that case, so a consumer that waits only for
    // `done` waits rather than acting on a digest of a truncated password.
    //
    // Named `too_long` rather than `overrun`: Icarus Verilog 12 rejects the
    // latter as a port name with "reg overrun; cannot be driven by primitives or
    // continuous assignment", which stops `.*` instantiation entirely.
    output logic          too_long
);

    localparam int MAX_CHARS = 27;

    localparam logic [1:0] S_IDLE  = 2'd0;
    localparam logic [1:0] S_START = 2'd1;
    localparam logic [1:0] S_WAIT  = 2'd2;

    logic [1:0]   state;
    logic         done_r;
    logic         md4_valid;
    logic         md4_ready;
    logic         md4_done;
    // Built on accept, see `build_block`.
    logic [511:0] md4_blk;
    logic [127:0] md4_digest;

    assign ready  = (state == S_IDLE);
    assign done   = done_r;
    assign digest_out = md4_digest;

    // The MD4 core's initial state, which is MD4's: A, B, C, D with A at the low
    // bits. NTLMv1 has no chaining, so the core is always fed this value.
    localparam logic [127:0] MD4_IV = 128'h10325476_98badcfe_efcdab89_67452301;

    // The block the MD4 core is fed is built when a password is accepted, not
    // combinationally from the ports.
    //
    // # Why not combinationally
    //
    // The obvious shape is an always_comb over pass_bytes and pass_len. Under
    // Icarus Verilog 12 that block is elaborated once and never re-evaluated
    // when its inputs change, because the sensitivity it infers from a part
    // select with a computed base, `pass_bytes[8 * (2 * w) +: 8]`, does not
    // include the vector. The block then holds whatever it computed at time
    // zero, the MD4 core compresses it faithfully, and the result is a wrong
    // digest with no X anywhere and nothing in the log to explain it. Reading
    // the same expression from a testbench returns the right byte, which is
    // what makes this expensive to find: the expression is fine, the block is
    // not.
    //
    // # Why this is correct anyway
    //
    // The block has to be stable for the whole 50 cycle MD4 run, and it is:
    // it is written once, on the cycle the password is accepted, and the core
    // is busy until the digest comes out. A new password cannot overwrite it in
    // the meantime because the state machine is not in S_IDLE.
    //
    // # The encoding
    //
    // UTF-16-LE puts one character in every other byte: character 2w at byte 0
    // of word w, a zero at byte 1, character 2w+1 at byte 2, a zero at byte 3.
    // Putting the two characters in bytes 0 and 1 instead leaves bytes 1 and 3
    // undriven, and an undriven bit in the input is an X through the whole hash
    // rather than a diagnostic.
    task automatic build_block(
        input [511:0] bytes_in,
        input [6:0]   len_in,
        output [511:0] blk
    );
        int i;
        begin
            blk = '0;
            // Byte i of the message holds character i/2, and only when i is
            // even: that is what UTF-16-LE means. The terminator goes at byte
            // 2L, not at byte L, which is the mistake a loop written over "the
            // characters" makes: it produces a block that is right for the
            // characters and wrong for the terminator, so the digest differs
            // from the reference for every non empty password and matches for
            // the empty one.
            for (i = 0; i < 56; i = i + 1) begin
                if ((i % 2) == 0 && (i / 2) < len_in)
                    blk[8 * i +: 8] = bytes_in[8 * (i / 2) +: 8];
                else if (i == 2 * len_in)
                    blk[8 * i +: 8] = 8'h80;
            end
            // A length in bits, not in bytes: each character is two bytes, and
            // the field counts bits, so 16L for a password of L characters.
            blk[32 * 14 +: 32] = len_in * 16;
        end
    endtask

    md4_core u_md4 (
        .clk        (clk),
        .rst_n      (rst_n),
        .valid      (md4_valid),
        .ready      (md4_ready),
        .msg_blk    (md4_blk),
        .state_in   (MD4_IV),
        .digest_out (md4_digest),
        .done       (md4_done)
    );

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state     <= S_IDLE;
            md4_valid <= 1'b0;
            done_r    <= 1'b0;
        end else begin
            case (state)
                S_IDLE: begin
                    md4_valid <= 1'b0;
                    done_r    <= 1'b0;
                    if (valid && pass_len <= MAX_CHARS) begin
                        // Too long passwords are refused, not truncated; see
                        // the header and `too_long` below.
                        build_block(pass_bytes, pass_len, md4_blk);
                        md4_valid <= 1'b1;
                        state     <= S_START;
                    end
                end

                // One cycle of `valid` for the MD4 core. Held for exactly one
                // cycle: the MD4 core ignores `valid` while it is busy, so a
                // longer pulse would start a second, unwanted block the moment
                // the first finished.
                S_START: begin
                    md4_valid <= 1'b0;
                    state     <= S_WAIT;
                end

                S_WAIT: begin
                    if (md4_done) begin
                        // `done` is registered rather than derived from
                        // `(state == S_WAIT) && md4_done`. Both conditions are
                        // true in the same cycle, so the combinational form is
                        // already false by the time a consumer samples it on the
                        // other edge of that cycle: the result appears to never
                        // arrive.
                        done_r <= 1'b1;
                        state  <= S_IDLE;
                    end else begin
                        done_r <= 1'b0;
                    end
                end

                default: state <= S_IDLE;
            endcase
        end
    end

    // `too_long` is a one cycle pulse, set when a password that does not fit is
    // offered and cleared by the next accepted one. Kept out of the state
    // machine above because it is a report, not a state: no digest is produced
    // and the core returns to idle either way.
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n)
            too_long <= 1'b0;
        else if (valid)
            too_long <= (pass_len > MAX_CHARS);
    end

endmodule