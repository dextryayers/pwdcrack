// MD4 compression core, RFC 1320.
//
// STATUS: VERIFIED against every vector in `rtl/sim/vectors/md4.svh`, which
// scripts/gen-rtl-vectors.py emits from a pure Python MD4 that is itself held
// against OpenSSL's MD4 and against the RFC 1320 test suite.
//
// # Why it matters
//
// NTLM is MD4 over UTF-16-LE, and NTLM is the hash that Windows domain
// controllers answer with. A core for NTLM is an MD4 core plus an encoding step,
// so this file is the one that matters and `ntlm_core` is a thin wrapper over it.
//
// # Interface
//
// Same as every core in `rtl/cores`; see `md5_core.sv` and `rtl/README.md`.
// MD4 is little endian, exactly like MD5, so `msg_blk[32*i +: 32]` is word i
// with the bytes reversed and `state_in[31:0]` is A.
//
// # Iterative
//
// 48 rounds at one per cycle. Unlike SHA-1 there is no message schedule, only
// four state words, so the core is tiny; unrolling all 48 rounds to reach one
// block per cycle would cost about 4,000 flip flops for one hash per 48 cycles,
// which is not a trade worth making. Instantiate several.
//
// # The three rounds
//
//     round 1  F(x,y,z) = (x AND y) OR (NOT x AND z)     K = 0
//     round 2  G(x,y,z) = majority                        K = 0x5A827999
//     round 3  H(x,y,z) = x XOR y XOR z                   K = 0x6ED9EBA1
//
// and in all three the four registers are updated in the order a, d, c, b, each
// reading a different word of the message. Round 2 walks the words in columns
// and round 3 walks them in the order 0, 2, 1, 3, which is not a reversal of
// round 2 and is the detail an implementation most often gets wrong. The
// tables below spell all three out rather than deriving them.

module md4_core (
    input  logic          clk,
    input  logic          rst_n,
    input  logic          valid,
    output logic          ready,
    // One 512 bit block, word i at [32*i +: 32], little endian words.
    input  logic [511:0]  msg_blk,
    input  logic [127:0]  state_in,
    output logic [127:0]  digest_out,
    output logic          done
);

    localparam int LATENCY = 50;

    // Six bits: 48 rounds need a counter that holds 0..47, and `round < 48` has
    // to be false at 48.
    logic [5:0]  round;
    logic        busy;
    logic        done_r;

    logic [31:0] acc_a, acc_b, acc_c, acc_d;

    assign ready = ~busy;

    function automatic [31:0] rol(input [31:0] x, input [4:0] n);
        case (n)
            5'd3:  rol = {x[28:0], x[31:29]};
            5'd5:  rol = {x[26:0], x[31:27]};
            5'd7:  rol = {x[24:0], x[31:25]};
            5'd9:  rol = {x[22:0], x[31:23]};
            5'd11: rol = {x[20:0], x[31:21]};
            5'd13: rol = {x[18:0], x[31:19]};
            5'd15: rol = {x[16:0], x[31:17]};
            5'd19: rol = {x[12:0], x[31:13]};
            default: rol = {x[28:0], x[31:29]};
        endcase
    endfunction

    // The three nonlinear functions, selected by kind rather than by round.
    //
    // The kind comes from the MD4_FKN table, and the table is read in the
    // sequential block rather than in here: Icarus Verilog 12 cannot bind an
    // unpacked array from inside a function ("Unable to bind wire/reg/memory
    // MD4_FKN[r] in f_of"), which is the same limitation that keeps every port
    // in this design packed.
    function automatic [31:0] f_kind(input [1:0] kind, input [31:0] x,
                                    input [31:0] y, input [31:0] z);
        begin
            case (kind)
                2'd0: f_kind = (x & y) | (~x & z);           // round 1
                2'd1: f_kind = (x & y) | (x & z) | (y & z);  // round 2
                default: f_kind = x ^ y ^ z;                  // round 3
            endcase
        end
    endfunction

    logic [3:0]  MD4_WORD  [0:47];
    logic [4:0]  MD4_SHIFT [0:47];
    logic [31:0] MD4_KCON  [0:47];
    logic [1:0]  MD4_FKN   [0:47];
    logic [1:0]  MD4_SEL   [0:47];

    // Round tables, 48 entries, one per round.
    //
    // One assignment per entry, not a slice assignment: Icarus Verilog 12
    // rejects `WORD[0:7] = {...}` outright, with "cannot perform a part select
    // on array", and a flat list of 48 assignments is what every tool accepts.
    //
    // Every entry was emitted from the same Python reference that produced the
    // digests in the vector file, so the tables and the expectations cannot
    // disagree. Writing them by hand is how round 3 ends up with the word
    // offsets in the wrong order: its sequence is 0, 2, 1, 3, and it is not a
    // reversal of round 2.
    initial begin
        MD4_WORD[ 0] = 4'd0; MD4_WORD[ 1] = 4'd1; MD4_WORD[ 2] = 4'd2; MD4_WORD[ 3] = 4'd3; MD4_WORD[ 4] = 4'd4; MD4_WORD[ 5] = 4'd5;
        MD4_WORD[ 6] = 4'd6; MD4_WORD[ 7] = 4'd7; MD4_WORD[ 8] = 4'd8; MD4_WORD[ 9] = 4'd9; MD4_WORD[10] = 4'd10; MD4_WORD[11] = 4'd11;
        MD4_WORD[12] = 4'd12; MD4_WORD[13] = 4'd13; MD4_WORD[14] = 4'd14; MD4_WORD[15] = 4'd15; MD4_WORD[16] = 4'd0; MD4_WORD[17] = 4'd4;
        MD4_WORD[18] = 4'd8; MD4_WORD[19] = 4'd12; MD4_WORD[20] = 4'd1; MD4_WORD[21] = 4'd5; MD4_WORD[22] = 4'd9; MD4_WORD[23] = 4'd13;
        MD4_WORD[24] = 4'd2; MD4_WORD[25] = 4'd6; MD4_WORD[26] = 4'd10; MD4_WORD[27] = 4'd14; MD4_WORD[28] = 4'd3; MD4_WORD[29] = 4'd7;
        MD4_WORD[30] = 4'd11; MD4_WORD[31] = 4'd15; MD4_WORD[32] = 4'd0; MD4_WORD[33] = 4'd8; MD4_WORD[34] = 4'd4; MD4_WORD[35] = 4'd12;
        MD4_WORD[36] = 4'd2; MD4_WORD[37] = 4'd10; MD4_WORD[38] = 4'd6; MD4_WORD[39] = 4'd14; MD4_WORD[40] = 4'd1; MD4_WORD[41] = 4'd9;
        MD4_WORD[42] = 4'd5; MD4_WORD[43] = 4'd13; MD4_WORD[44] = 4'd3; MD4_WORD[45] = 4'd11; MD4_WORD[46] = 4'd7; MD4_WORD[47] = 4'd15;
        MD4_SHIFT[ 0] = 5'd3; MD4_SHIFT[ 1] = 5'd7; MD4_SHIFT[ 2] = 5'd11; MD4_SHIFT[ 3] = 5'd19; MD4_SHIFT[ 4] = 5'd3; MD4_SHIFT[ 5] = 5'd7;
        MD4_SHIFT[ 6] = 5'd11; MD4_SHIFT[ 7] = 5'd19; MD4_SHIFT[ 8] = 5'd3; MD4_SHIFT[ 9] = 5'd7; MD4_SHIFT[10] = 5'd11; MD4_SHIFT[11] = 5'd19;
        MD4_SHIFT[12] = 5'd3; MD4_SHIFT[13] = 5'd7; MD4_SHIFT[14] = 5'd11; MD4_SHIFT[15] = 5'd19; MD4_SHIFT[16] = 5'd3; MD4_SHIFT[17] = 5'd5;
        MD4_SHIFT[18] = 5'd9; MD4_SHIFT[19] = 5'd13; MD4_SHIFT[20] = 5'd3; MD4_SHIFT[21] = 5'd5; MD4_SHIFT[22] = 5'd9; MD4_SHIFT[23] = 5'd13;
        MD4_SHIFT[24] = 5'd3; MD4_SHIFT[25] = 5'd5; MD4_SHIFT[26] = 5'd9; MD4_SHIFT[27] = 5'd13; MD4_SHIFT[28] = 5'd3; MD4_SHIFT[29] = 5'd5;
        MD4_SHIFT[30] = 5'd9; MD4_SHIFT[31] = 5'd13; MD4_SHIFT[32] = 5'd3; MD4_SHIFT[33] = 5'd9; MD4_SHIFT[34] = 5'd11; MD4_SHIFT[35] = 5'd15;
        MD4_SHIFT[36] = 5'd3; MD4_SHIFT[37] = 5'd9; MD4_SHIFT[38] = 5'd11; MD4_SHIFT[39] = 5'd15; MD4_SHIFT[40] = 5'd3; MD4_SHIFT[41] = 5'd9;
        MD4_SHIFT[42] = 5'd11; MD4_SHIFT[43] = 5'd15; MD4_SHIFT[44] = 5'd3; MD4_SHIFT[45] = 5'd9; MD4_SHIFT[46] = 5'd11; MD4_SHIFT[47] = 5'd15;
        MD4_KCON[ 0] = 32'h00000000; MD4_KCON[ 1] = 32'h00000000; MD4_KCON[ 2] = 32'h00000000; MD4_KCON[ 3] = 32'h00000000; MD4_KCON[ 4] = 32'h00000000; MD4_KCON[ 5] = 32'h00000000;
        MD4_KCON[ 6] = 32'h00000000; MD4_KCON[ 7] = 32'h00000000; MD4_KCON[ 8] = 32'h00000000; MD4_KCON[ 9] = 32'h00000000; MD4_KCON[10] = 32'h00000000; MD4_KCON[11] = 32'h00000000;
        MD4_KCON[12] = 32'h00000000; MD4_KCON[13] = 32'h00000000; MD4_KCON[14] = 32'h00000000; MD4_KCON[15] = 32'h00000000; MD4_KCON[16] = 32'h5a827999; MD4_KCON[17] = 32'h5a827999;
        MD4_KCON[18] = 32'h5a827999; MD4_KCON[19] = 32'h5a827999; MD4_KCON[20] = 32'h5a827999; MD4_KCON[21] = 32'h5a827999; MD4_KCON[22] = 32'h5a827999; MD4_KCON[23] = 32'h5a827999;
        MD4_KCON[24] = 32'h5a827999; MD4_KCON[25] = 32'h5a827999; MD4_KCON[26] = 32'h5a827999; MD4_KCON[27] = 32'h5a827999; MD4_KCON[28] = 32'h5a827999; MD4_KCON[29] = 32'h5a827999;
        MD4_KCON[30] = 32'h5a827999; MD4_KCON[31] = 32'h5a827999; MD4_KCON[32] = 32'h6ed9eba1; MD4_KCON[33] = 32'h6ed9eba1; MD4_KCON[34] = 32'h6ed9eba1; MD4_KCON[35] = 32'h6ed9eba1;
        MD4_KCON[36] = 32'h6ed9eba1; MD4_KCON[37] = 32'h6ed9eba1; MD4_KCON[38] = 32'h6ed9eba1; MD4_KCON[39] = 32'h6ed9eba1; MD4_KCON[40] = 32'h6ed9eba1; MD4_KCON[41] = 32'h6ed9eba1;
        MD4_KCON[42] = 32'h6ed9eba1; MD4_KCON[43] = 32'h6ed9eba1; MD4_KCON[44] = 32'h6ed9eba1; MD4_KCON[45] = 32'h6ed9eba1; MD4_KCON[46] = 32'h6ed9eba1; MD4_KCON[47] = 32'h6ed9eba1;
        MD4_FKN[ 0] = 2'd0; MD4_FKN[ 1] = 2'd0; MD4_FKN[ 2] = 2'd0; MD4_FKN[ 3] = 2'd0; MD4_FKN[ 4] = 2'd0; MD4_FKN[ 5] = 2'd0;
        MD4_FKN[ 6] = 2'd0; MD4_FKN[ 7] = 2'd0; MD4_FKN[ 8] = 2'd0; MD4_FKN[ 9] = 2'd0; MD4_FKN[10] = 2'd0; MD4_FKN[11] = 2'd0;
        MD4_FKN[12] = 2'd0; MD4_FKN[13] = 2'd0; MD4_FKN[14] = 2'd0; MD4_FKN[15] = 2'd0; MD4_FKN[16] = 2'd1; MD4_FKN[17] = 2'd1;
        MD4_FKN[18] = 2'd1; MD4_FKN[19] = 2'd1; MD4_FKN[20] = 2'd1; MD4_FKN[21] = 2'd1; MD4_FKN[22] = 2'd1; MD4_FKN[23] = 2'd1;
        MD4_FKN[24] = 2'd1; MD4_FKN[25] = 2'd1; MD4_FKN[26] = 2'd1; MD4_FKN[27] = 2'd1; MD4_FKN[28] = 2'd1; MD4_FKN[29] = 2'd1;
        MD4_FKN[30] = 2'd1; MD4_FKN[31] = 2'd1; MD4_FKN[32] = 2'd2; MD4_FKN[33] = 2'd2; MD4_FKN[34] = 2'd2; MD4_FKN[35] = 2'd2;
        MD4_FKN[36] = 2'd2; MD4_FKN[37] = 2'd2; MD4_FKN[38] = 2'd2; MD4_FKN[39] = 2'd2; MD4_FKN[40] = 2'd2; MD4_FKN[41] = 2'd2;
        MD4_FKN[42] = 2'd2; MD4_FKN[43] = 2'd2; MD4_FKN[44] = 2'd2; MD4_FKN[45] = 2'd2; MD4_FKN[46] = 2'd2; MD4_FKN[47] = 2'd2;
        MD4_SEL[ 0] = 2'd0; MD4_SEL[ 1] = 2'd1; MD4_SEL[ 2] = 2'd2; MD4_SEL[ 3] = 2'd3; MD4_SEL[ 4] = 2'd0; MD4_SEL[ 5] = 2'd1;
        MD4_SEL[ 6] = 2'd2; MD4_SEL[ 7] = 2'd3; MD4_SEL[ 8] = 2'd0; MD4_SEL[ 9] = 2'd1; MD4_SEL[10] = 2'd2; MD4_SEL[11] = 2'd3;
        MD4_SEL[12] = 2'd0; MD4_SEL[13] = 2'd1; MD4_SEL[14] = 2'd2; MD4_SEL[15] = 2'd3; MD4_SEL[16] = 2'd0; MD4_SEL[17] = 2'd1;
        MD4_SEL[18] = 2'd2; MD4_SEL[19] = 2'd3; MD4_SEL[20] = 2'd0; MD4_SEL[21] = 2'd1; MD4_SEL[22] = 2'd2; MD4_SEL[23] = 2'd3;
        MD4_SEL[24] = 2'd0; MD4_SEL[25] = 2'd1; MD4_SEL[26] = 2'd2; MD4_SEL[27] = 2'd3; MD4_SEL[28] = 2'd0; MD4_SEL[29] = 2'd1;
        MD4_SEL[30] = 2'd2; MD4_SEL[31] = 2'd3; MD4_SEL[32] = 2'd0; MD4_SEL[33] = 2'd1; MD4_SEL[34] = 2'd2; MD4_SEL[35] = 2'd3;
        MD4_SEL[36] = 2'd0; MD4_SEL[37] = 2'd1; MD4_SEL[38] = 2'd2; MD4_SEL[39] = 2'd3; MD4_SEL[40] = 2'd0; MD4_SEL[41] = 2'd1;
        MD4_SEL[42] = 2'd2; MD4_SEL[43] = 2'd3; MD4_SEL[44] = 2'd0; MD4_SEL[45] = 2'd1; MD4_SEL[46] = 2'd2; MD4_SEL[47] = 2'd3;
    end

    initial begin
        round  = 6'd0;
        busy   = 1'b0;
        done_r = 1'b0;
        acc_a  = 32'h67452301;
        acc_b  = 32'hEFCDAB89;
        acc_c  = 32'h98BADCFE;
        acc_d  = 32'h10325476;
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            round  <= 6'd0;
            busy   <= 1'b0;
            done_r <= 1'b0;
            acc_a  <= 32'h67452301;
            acc_b  <= 32'hEFCDAB89;
            acc_c  <= 32'h98BADCFE;
            acc_d  <= 32'h10325476;
        end else begin
            done_r <= 1'b0;

            if (valid && !busy) begin
                busy  <= 1'b1;
                round <= 6'd0;
                acc_a <= state_in[31:0];
                acc_b <= state_in[63:32];
                acc_c <= state_in[95:64];
                acc_d <= state_in[127:96];
            end else if (busy) begin
                if (round < 6'd48) begin
                    logic [31:0] f, k;
                    logic [1:0]  sel;

                    k  = MD4_KCON[round[5:0]];
                    sel = MD4_SEL[round[5:0]];

                    // The three function arguments rotate with the register
                    // being updated: the a step uses F(b,c,d), the d step
                    // F(a,b,c), the c step F(d,a,b), the b step F(c,d,a).
                    //
                    // Round 1's F is not symmetric in its arguments, so passing
                    // (b, c, d) for every step computes three of the four steps
                    // against the wrong triple. Round 2's G and round 3's H are
                    // symmetric, so the same code is right there by accident,
                    // which is what makes this look like a core that is almost
                    // correct.
                    case (sel)
                        2'd0: f = f_kind(MD4_FKN[round[5:0]], acc_b, acc_c, acc_d);
                        2'd1: f = f_kind(MD4_FKN[round[5:0]], acc_a, acc_b, acc_c);
                        2'd2: f = f_kind(MD4_FKN[round[5:0]], acc_d, acc_a, acc_b);
                        default: f = f_kind(MD4_FKN[round[5:0]], acc_c, acc_d, acc_a);
                    endcase

                    // MD4 updates exactly one register per step and the value it updates is the
                    // one it accumulates into:
                    //
                    //     a = ROL(a + F(b,c,d) + X + K, s)
                    //     d = ROL(d + F(a,b,c) + X + K, s)
                    //     c = ROL(c + F(d,a,b) + X + K, s)
                    //     b = ROL(b + F(c,d,a) + X + K, s)
                    //
                    // This is the structural difference from SHA-1, where all
                    // five registers rotate and the accumulator is always a.
                    // Computing `a + F(...)` once and writing it to whichever
                    // register the step selects looks right for the first step
                    // and is wrong for the other three, because steps one, two
                    // and three accumulate into d, c and b respectively.
                    case (sel)
                        2'd0: acc_a <= rol(acc_a + f
                                           + msg_blk[32 * MD4_WORD[round[5:0]] +: 32] + k,
                                           MD4_SHIFT[round[5:0]]);
                        2'd1: acc_d <= rol(acc_d + f
                                           + msg_blk[32 * MD4_WORD[round[5:0]] +: 32] + k,
                                           MD4_SHIFT[round[5:0]]);
                        2'd2: acc_c <= rol(acc_c + f
                                           + msg_blk[32 * MD4_WORD[round[5:0]] +: 32] + k,
                                           MD4_SHIFT[round[5:0]]);
                        default: acc_b <= rol(acc_b + f
                                             + msg_blk[32 * MD4_WORD[round[5:0]] +: 32] + k,
                                             MD4_SHIFT[round[5:0]]);
                    endcase

                    round <= round + 6'd1;
                end else begin
                    acc_a  <= acc_a + state_in[31:0];
                    acc_b  <= acc_b + state_in[63:32];
                    acc_c  <= acc_c + state_in[95:64];
                    acc_d  <= acc_d + state_in[127:96];
                    busy   <= 1'b0;
                    done_r <= 1'b1;
                end
            end
        end
    end

    assign digest_out[31:0]   = acc_a;
    assign digest_out[63:32]  = acc_b;
    assign digest_out[95:64]  = acc_c;
    assign digest_out[127:96] = acc_d;
    assign done = done_r;

endmodule