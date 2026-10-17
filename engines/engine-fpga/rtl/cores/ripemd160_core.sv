// RIPEMD-160 compression core.
//
// STATUS: VERIFIED against every vector in `rtl/sim/vectors/ripemd160.svh`,
// which scripts/gen-rtl-vectors.py emits from hashlib.
//
// # Interface
//
// Same as every core in `rtl/cores`; see `md5_core.sv` and `rtl/README.md`.
// Big endian words like SHA-1, word 0 in the low bits, 160 bit state and digest.
//
// # What RIPEMD-160 is
//
// Two parallel lines of 80 rounds each, running side by side over the same
// message with different functions, different constants, different word orders
// and different rotation amounts. At the end the two lines are combined with
// each other's middle state:
//
//     T = h1 + c + d2,  h2 + d + e1,  h3 + e + a2,  h4 + a + b2,  h5 + b + c2
//
// Four tables of eighty entries each drive it: which word a step reads, and how
// far it rotates, for the left line and the right. Writing them by hand is how
// the previous version of this core got them wrong: it used a round selector of
// two bits for five rounds, called functions named fp1 to fp5 that were never
// defined, and derived the right line's word order with a formula that happens
// to be right for one of the five rounds.
//
// The tables below are emitted from the same Python reference that produced the
// digests in the vector file, so they and the expectations cannot disagree.
//
// # Iterative
//
// One round pair per cycle, so 80 cycles of latency: each cycle advances both
// lines by one step. Fully unrolling all eighty would be about 160 stages of two
// five word states, roughly 50,000 flip flops.
//
// # Both lines advance together
//
// The left and right steps for round j step i are computed in the same cycle,
// each from its own registers. A design that ran the lines in sequence would be
// correct and twice as long.

module ripemd160_core (
    input  logic          clk,
    input  logic          rst_n,
    input  logic          valid,
    output logic          ready,
    input  logic [511:0]  msg_blk,
    input  logic [159:0]  state_in,
    output logic [159:0]  digest_out,
    output logic          done
);

    localparam int LATENCY = 82;

    logic [4:0]  RIPEMD_R  [0:79];
    logic [4:0]  RIPEMD_RP [0:79];
    logic [4:0]  RIPEMD_S  [0:79];
    logic [4:0]  RIPEMD_SP [0:79];

    initial begin
        RIPEMD_R[ 0] = 5'd0;
        RIPEMD_R[ 1] = 5'd1;
        RIPEMD_R[ 2] = 5'd2;
        RIPEMD_R[ 3] = 5'd3;
        RIPEMD_R[ 4] = 5'd4;
        RIPEMD_R[ 5] = 5'd5;
        RIPEMD_R[ 6] = 5'd6;
        RIPEMD_R[ 7] = 5'd7;
        RIPEMD_R[ 8] = 5'd8;
        RIPEMD_R[ 9] = 5'd9;
        RIPEMD_R[10] = 5'd10;
        RIPEMD_R[11] = 5'd11;
        RIPEMD_R[12] = 5'd12;
        RIPEMD_R[13] = 5'd13;
        RIPEMD_R[14] = 5'd14;
        RIPEMD_R[15] = 5'd15;
        RIPEMD_R[16] = 5'd7;
        RIPEMD_R[17] = 5'd4;
        RIPEMD_R[18] = 5'd13;
        RIPEMD_R[19] = 5'd1;
        RIPEMD_R[20] = 5'd10;
        RIPEMD_R[21] = 5'd6;
        RIPEMD_R[22] = 5'd15;
        RIPEMD_R[23] = 5'd3;
        RIPEMD_R[24] = 5'd12;
        RIPEMD_R[25] = 5'd0;
        RIPEMD_R[26] = 5'd9;
        RIPEMD_R[27] = 5'd5;
        RIPEMD_R[28] = 5'd2;
        RIPEMD_R[29] = 5'd14;
        RIPEMD_R[30] = 5'd11;
        RIPEMD_R[31] = 5'd8;
        RIPEMD_R[32] = 5'd3;
        RIPEMD_R[33] = 5'd10;
        RIPEMD_R[34] = 5'd14;
        RIPEMD_R[35] = 5'd4;
        RIPEMD_R[36] = 5'd9;
        RIPEMD_R[37] = 5'd15;
        RIPEMD_R[38] = 5'd8;
        RIPEMD_R[39] = 5'd1;
        RIPEMD_R[40] = 5'd2;
        RIPEMD_R[41] = 5'd7;
        RIPEMD_R[42] = 5'd0;
        RIPEMD_R[43] = 5'd6;
        RIPEMD_R[44] = 5'd13;
        RIPEMD_R[45] = 5'd11;
        RIPEMD_R[46] = 5'd5;
        RIPEMD_R[47] = 5'd12;
        RIPEMD_R[48] = 5'd1;
        RIPEMD_R[49] = 5'd9;
        RIPEMD_R[50] = 5'd11;
        RIPEMD_R[51] = 5'd10;
        RIPEMD_R[52] = 5'd0;
        RIPEMD_R[53] = 5'd8;
        RIPEMD_R[54] = 5'd12;
        RIPEMD_R[55] = 5'd4;
        RIPEMD_R[56] = 5'd13;
        RIPEMD_R[57] = 5'd3;
        RIPEMD_R[58] = 5'd7;
        RIPEMD_R[59] = 5'd15;
        RIPEMD_R[60] = 5'd14;
        RIPEMD_R[61] = 5'd5;
        RIPEMD_R[62] = 5'd6;
        RIPEMD_R[63] = 5'd2;
        RIPEMD_R[64] = 5'd4;
        RIPEMD_R[65] = 5'd0;
        RIPEMD_R[66] = 5'd5;
        RIPEMD_R[67] = 5'd9;
        RIPEMD_R[68] = 5'd7;
        RIPEMD_R[69] = 5'd12;
        RIPEMD_R[70] = 5'd2;
        RIPEMD_R[71] = 5'd10;
        RIPEMD_R[72] = 5'd14;
        RIPEMD_R[73] = 5'd1;
        RIPEMD_R[74] = 5'd3;
        RIPEMD_R[75] = 5'd8;
        RIPEMD_R[76] = 5'd11;
        RIPEMD_R[77] = 5'd6;
        RIPEMD_R[78] = 5'd15;
        RIPEMD_R[79] = 5'd13;
        RIPEMD_RP[ 0] = 5'd5;
        RIPEMD_RP[ 1] = 5'd14;
        RIPEMD_RP[ 2] = 5'd7;
        RIPEMD_RP[ 3] = 5'd0;
        RIPEMD_RP[ 4] = 5'd9;
        RIPEMD_RP[ 5] = 5'd2;
        RIPEMD_RP[ 6] = 5'd11;
        RIPEMD_RP[ 7] = 5'd4;
        RIPEMD_RP[ 8] = 5'd13;
        RIPEMD_RP[ 9] = 5'd6;
        RIPEMD_RP[10] = 5'd15;
        RIPEMD_RP[11] = 5'd8;
        RIPEMD_RP[12] = 5'd1;
        RIPEMD_RP[13] = 5'd10;
        RIPEMD_RP[14] = 5'd3;
        RIPEMD_RP[15] = 5'd12;
        RIPEMD_RP[16] = 5'd6;
        RIPEMD_RP[17] = 5'd11;
        RIPEMD_RP[18] = 5'd3;
        RIPEMD_RP[19] = 5'd7;
        RIPEMD_RP[20] = 5'd0;
        RIPEMD_RP[21] = 5'd13;
        RIPEMD_RP[22] = 5'd5;
        RIPEMD_RP[23] = 5'd10;
        RIPEMD_RP[24] = 5'd14;
        RIPEMD_RP[25] = 5'd15;
        RIPEMD_RP[26] = 5'd8;
        RIPEMD_RP[27] = 5'd12;
        RIPEMD_RP[28] = 5'd4;
        RIPEMD_RP[29] = 5'd9;
        RIPEMD_RP[30] = 5'd1;
        RIPEMD_RP[31] = 5'd2;
        RIPEMD_RP[32] = 5'd15;
        RIPEMD_RP[33] = 5'd5;
        RIPEMD_RP[34] = 5'd1;
        RIPEMD_RP[35] = 5'd3;
        RIPEMD_RP[36] = 5'd7;
        RIPEMD_RP[37] = 5'd14;
        RIPEMD_RP[38] = 5'd6;
        RIPEMD_RP[39] = 5'd9;
        RIPEMD_RP[40] = 5'd11;
        RIPEMD_RP[41] = 5'd8;
        RIPEMD_RP[42] = 5'd12;
        RIPEMD_RP[43] = 5'd2;
        RIPEMD_RP[44] = 5'd10;
        RIPEMD_RP[45] = 5'd0;
        RIPEMD_RP[46] = 5'd4;
        RIPEMD_RP[47] = 5'd13;
        RIPEMD_RP[48] = 5'd8;
        RIPEMD_RP[49] = 5'd6;
        RIPEMD_RP[50] = 5'd4;
        RIPEMD_RP[51] = 5'd1;
        RIPEMD_RP[52] = 5'd3;
        RIPEMD_RP[53] = 5'd11;
        RIPEMD_RP[54] = 5'd15;
        RIPEMD_RP[55] = 5'd0;
        RIPEMD_RP[56] = 5'd5;
        RIPEMD_RP[57] = 5'd12;
        RIPEMD_RP[58] = 5'd2;
        RIPEMD_RP[59] = 5'd13;
        RIPEMD_RP[60] = 5'd9;
        RIPEMD_RP[61] = 5'd7;
        RIPEMD_RP[62] = 5'd10;
        RIPEMD_RP[63] = 5'd14;
        RIPEMD_RP[64] = 5'd12;
        RIPEMD_RP[65] = 5'd15;
        RIPEMD_RP[66] = 5'd10;
        RIPEMD_RP[67] = 5'd4;
        RIPEMD_RP[68] = 5'd1;
        RIPEMD_RP[69] = 5'd5;
        RIPEMD_RP[70] = 5'd8;
        RIPEMD_RP[71] = 5'd7;
        RIPEMD_RP[72] = 5'd6;
        RIPEMD_RP[73] = 5'd2;
        RIPEMD_RP[74] = 5'd13;
        RIPEMD_RP[75] = 5'd14;
        RIPEMD_RP[76] = 5'd0;
        RIPEMD_RP[77] = 5'd3;
        RIPEMD_RP[78] = 5'd9;
        RIPEMD_RP[79] = 5'd11;
        RIPEMD_S[ 0] = 5'd11;
        RIPEMD_S[ 1] = 5'd14;
        RIPEMD_S[ 2] = 5'd15;
        RIPEMD_S[ 3] = 5'd12;
        RIPEMD_S[ 4] = 5'd5;
        RIPEMD_S[ 5] = 5'd8;
        RIPEMD_S[ 6] = 5'd7;
        RIPEMD_S[ 7] = 5'd9;
        RIPEMD_S[ 8] = 5'd11;
        RIPEMD_S[ 9] = 5'd13;
        RIPEMD_S[10] = 5'd14;
        RIPEMD_S[11] = 5'd15;
        RIPEMD_S[12] = 5'd6;
        RIPEMD_S[13] = 5'd7;
        RIPEMD_S[14] = 5'd9;
        RIPEMD_S[15] = 5'd8;
        RIPEMD_S[16] = 5'd7;
        RIPEMD_S[17] = 5'd6;
        RIPEMD_S[18] = 5'd8;
        RIPEMD_S[19] = 5'd13;
        RIPEMD_S[20] = 5'd11;
        RIPEMD_S[21] = 5'd9;
        RIPEMD_S[22] = 5'd7;
        RIPEMD_S[23] = 5'd15;
        RIPEMD_S[24] = 5'd7;
        RIPEMD_S[25] = 5'd12;
        RIPEMD_S[26] = 5'd15;
        RIPEMD_S[27] = 5'd9;
        RIPEMD_S[28] = 5'd11;
        RIPEMD_S[29] = 5'd7;
        RIPEMD_S[30] = 5'd13;
        RIPEMD_S[31] = 5'd12;
        RIPEMD_S[32] = 5'd11;
        RIPEMD_S[33] = 5'd13;
        RIPEMD_S[34] = 5'd6;
        RIPEMD_S[35] = 5'd7;
        RIPEMD_S[36] = 5'd14;
        RIPEMD_S[37] = 5'd9;
        RIPEMD_S[38] = 5'd13;
        RIPEMD_S[39] = 5'd15;
        RIPEMD_S[40] = 5'd14;
        RIPEMD_S[41] = 5'd8;
        RIPEMD_S[42] = 5'd13;
        RIPEMD_S[43] = 5'd6;
        RIPEMD_S[44] = 5'd5;
        RIPEMD_S[45] = 5'd12;
        RIPEMD_S[46] = 5'd7;
        RIPEMD_S[47] = 5'd5;
        RIPEMD_S[48] = 5'd11;
        RIPEMD_S[49] = 5'd12;
        RIPEMD_S[50] = 5'd14;
        RIPEMD_S[51] = 5'd15;
        RIPEMD_S[52] = 5'd14;
        RIPEMD_S[53] = 5'd15;
        RIPEMD_S[54] = 5'd9;
        RIPEMD_S[55] = 5'd8;
        RIPEMD_S[56] = 5'd9;
        RIPEMD_S[57] = 5'd14;
        RIPEMD_S[58] = 5'd5;
        RIPEMD_S[59] = 5'd6;
        RIPEMD_S[60] = 5'd8;
        RIPEMD_S[61] = 5'd6;
        RIPEMD_S[62] = 5'd5;
        RIPEMD_S[63] = 5'd12;
        RIPEMD_S[64] = 5'd9;
        RIPEMD_S[65] = 5'd15;
        RIPEMD_S[66] = 5'd5;
        RIPEMD_S[67] = 5'd11;
        RIPEMD_S[68] = 5'd6;
        RIPEMD_S[69] = 5'd8;
        RIPEMD_S[70] = 5'd13;
        RIPEMD_S[71] = 5'd12;
        RIPEMD_S[72] = 5'd5;
        RIPEMD_S[73] = 5'd12;
        RIPEMD_S[74] = 5'd13;
        RIPEMD_S[75] = 5'd14;
        RIPEMD_S[76] = 5'd11;
        RIPEMD_S[77] = 5'd8;
        RIPEMD_S[78] = 5'd5;
        RIPEMD_S[79] = 5'd6;
        RIPEMD_SP[ 0] = 5'd8;
        RIPEMD_SP[ 1] = 5'd9;
        RIPEMD_SP[ 2] = 5'd9;
        RIPEMD_SP[ 3] = 5'd11;
        RIPEMD_SP[ 4] = 5'd13;
        RIPEMD_SP[ 5] = 5'd15;
        RIPEMD_SP[ 6] = 5'd15;
        RIPEMD_SP[ 7] = 5'd5;
        RIPEMD_SP[ 8] = 5'd7;
        RIPEMD_SP[ 9] = 5'd7;
        RIPEMD_SP[10] = 5'd8;
        RIPEMD_SP[11] = 5'd11;
        RIPEMD_SP[12] = 5'd14;
        RIPEMD_SP[13] = 5'd14;
        RIPEMD_SP[14] = 5'd12;
        RIPEMD_SP[15] = 5'd6;
        RIPEMD_SP[16] = 5'd9;
        RIPEMD_SP[17] = 5'd13;
        RIPEMD_SP[18] = 5'd15;
        RIPEMD_SP[19] = 5'd7;
        RIPEMD_SP[20] = 5'd12;
        RIPEMD_SP[21] = 5'd8;
        RIPEMD_SP[22] = 5'd9;
        RIPEMD_SP[23] = 5'd11;
        RIPEMD_SP[24] = 5'd7;
        RIPEMD_SP[25] = 5'd7;
        RIPEMD_SP[26] = 5'd12;
        RIPEMD_SP[27] = 5'd7;
        RIPEMD_SP[28] = 5'd6;
        RIPEMD_SP[29] = 5'd15;
        RIPEMD_SP[30] = 5'd13;
        RIPEMD_SP[31] = 5'd11;
        RIPEMD_SP[32] = 5'd9;
        RIPEMD_SP[33] = 5'd7;
        RIPEMD_SP[34] = 5'd15;
        RIPEMD_SP[35] = 5'd11;
        RIPEMD_SP[36] = 5'd8;
        RIPEMD_SP[37] = 5'd6;
        RIPEMD_SP[38] = 5'd6;
        RIPEMD_SP[39] = 5'd14;
        RIPEMD_SP[40] = 5'd12;
        RIPEMD_SP[41] = 5'd13;
        RIPEMD_SP[42] = 5'd5;
        RIPEMD_SP[43] = 5'd14;
        RIPEMD_SP[44] = 5'd13;
        RIPEMD_SP[45] = 5'd13;
        RIPEMD_SP[46] = 5'd7;
        RIPEMD_SP[47] = 5'd5;
        RIPEMD_SP[48] = 5'd15;
        RIPEMD_SP[49] = 5'd5;
        RIPEMD_SP[50] = 5'd8;
        RIPEMD_SP[51] = 5'd11;
        RIPEMD_SP[52] = 5'd14;
        RIPEMD_SP[53] = 5'd14;
        RIPEMD_SP[54] = 5'd6;
        RIPEMD_SP[55] = 5'd14;
        RIPEMD_SP[56] = 5'd6;
        RIPEMD_SP[57] = 5'd9;
        RIPEMD_SP[58] = 5'd12;
        RIPEMD_SP[59] = 5'd9;
        RIPEMD_SP[60] = 5'd12;
        RIPEMD_SP[61] = 5'd5;
        RIPEMD_SP[62] = 5'd15;
        RIPEMD_SP[63] = 5'd8;
        RIPEMD_SP[64] = 5'd8;
        RIPEMD_SP[65] = 5'd5;
        RIPEMD_SP[66] = 5'd12;
        RIPEMD_SP[67] = 5'd9;
        RIPEMD_SP[68] = 5'd12;
        RIPEMD_SP[69] = 5'd5;
        RIPEMD_SP[70] = 5'd14;
        RIPEMD_SP[71] = 5'd6;
        RIPEMD_SP[72] = 5'd8;
        RIPEMD_SP[73] = 5'd13;
        RIPEMD_SP[74] = 5'd6;
        RIPEMD_SP[75] = 5'd5;
        RIPEMD_SP[76] = 5'd15;
        RIPEMD_SP[77] = 5'd13;
        RIPEMD_SP[78] = 5'd11;
        RIPEMD_SP[79] = 5'd11;
    end

    // The five nonlinear functions. The left line runs f1 to f5, the right line
    // f5 to f1, so a step selects by round on the left and by 4 minus the round
    // on the right.
    function automatic [31:0] f_of(input [2:0] j, input [31:0] x,
                                  input [31:0] y, input [31:0] z);
        begin
            case (j)
                3'd0: f_of = x ^ y ^ z;
                3'd1: f_of = (x & y) | (~x & z);
                3'd2: f_of = (x | ~y) ^ z;
                3'd3: f_of = (x & z) | (y & ~z);
                default: f_of = x ^ (y | ~z);
            endcase
        end
    endfunction

    // Rotation amounts run from 5 to 15. Each is an explicit rotate left by n,
    // which is {x[31-n:0], x[31:32-n]}; the reversed form of that, which is what
    // a rotate right looks like, is the mistake sha256_core documents.
    function automatic [31:0] rol(input [31:0] x, input [4:0] n);
        case (n)
            5'd5:  rol = {x[26:0], x[31:27]};
            5'd6:  rol = {x[25:0], x[31:26]};
            5'd7:  rol = {x[24:0], x[31:25]};
            5'd8:  rol = {x[23:0], x[31:24]};
            5'd9:  rol = {x[22:0], x[31:23]};
            5'd10: rol = {x[21:0], x[31:22]};
            5'd11: rol = {x[20:0], x[31:21]};
            5'd12: rol = {x[19:0], x[31:20]};
            5'd13: rol = {x[18:0], x[31:19]};
            5'd14: rol = {x[17:0], x[31:18]};
            5'd15: rol = {x[16:0], x[31:17]};
            default: rol = {x[20:0], x[31:21]};
        endcase
    endfunction

    // Round constants. Left line f1..f5, right line in the opposite order.
    function automatic [31:0] k_left(input [2:0] j);
        case (j)
            3'd0: k_left = 32'h00000000;
            3'd1: k_left = 32'h5A827999;
            3'd2: k_left = 32'h6ED9EBA1;
            3'd3: k_left = 32'h8F1BBCDC;
            default: k_left = 32'hA953FD4E;
        endcase
    endfunction

    function automatic [31:0] k_right(input [2:0] j);
        case (j)
            3'd0: k_right = 32'h50A28BE6;
            3'd1: k_right = 32'h5C4DD124;
            3'd2: k_right = 32'h6D703EF3;
            3'd3: k_right = 32'h7A6D76E9;
            default: k_right = 32'h00000000;
        endcase
    endfunction

    logic [6:0] step;
    logic       busy;
    logic       done_r;

    // Left line: a, b, c, d, e. Right line: aa, bb, cc, dd, ee.
    logic [31:0] la, lb, lc, ld, le;
    logic [31:0] ra, rb, rc, rd, re;

    assign ready = ~busy;

    initial begin
        step   = 7'd0;
        busy   = 1'b0;
        done_r = 1'b0;
        la = 32'h67452301; lb = 32'hEFCDAB89; lc = 32'h98BADCFE;
        ld = 32'h10325476; le = 32'hC3D2E1F0;
        ra = 32'h67452301; rb = 32'hEFCDAB89; rc = 32'h98BADCFE;
        rd = 32'h10325476; re = 32'hC3D2E1F0;
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            step   <= 7'd0;
            busy   <= 1'b0;
            done_r <= 1'b0;
            la <= 32'h67452301; lb <= 32'hEFCDAB89; lc <= 32'h98BADCFE;
            ld <= 32'h10325476; le <= 32'hC3D2E1F0;
            ra <= 32'h67452301; rb <= 32'hEFCDAB89; rc <= 32'h98BADCFE;
            rd <= 32'h10325476; re <= 32'hC3D2E1F0;
        end else begin
            done_r <= 1'b0;

            if (valid && !busy) begin
                busy <= 1'b1;
                step <= 7'd0;
                la <= state_in[ 31:  0]; lb <= state_in[ 63: 32];
                lc <= state_in[ 95: 64]; ld <= state_in[127: 96];
                le <= state_in[159:128];
                ra <= state_in[ 31:  0]; rb <= state_in[ 63: 32];
                rc <= state_in[ 95: 64]; rd <= state_in[127: 96];
                re <= state_in[159:128];
            end else if (busy) begin
                if (step < 7'd80) begin
                    logic [2:0]  rnd;
                    logic [31:0] tl, tr;

                    rnd = step[6:4];

                    tl = rol(la + f_of(rnd, lb, lc, ld)
                             + msg_blk[32 * RIPEMD_R[step[6:0]] +: 32]
                             + k_left(rnd), RIPEMD_S[step[6:0]]) + le;

                    tr = rol(ra + f_of(3'd4 - rnd, rb, rc, rd)
                             + msg_blk[32 * RIPEMD_RP[step[6:0]] +: 32]
                             + k_right(rnd), RIPEMD_SP[step[6:0]]) + re;

                    la <= le; le <= ld; ld <= rol(lc, 10); lc <= lb; lb <= tl;
                    ra <= re; re <= rd; rd <= rol(rc, 10); rc <= rb; rb <= tr;

                    step <= step + 7'd1;
                end else begin
                    // Combine the two lines. The specification writes this as a
                    // rotation of the chaining values rather than in place:
                    //
                    //     T  = h0 + c + d2
                    //     h0 = h1 + d + e2
                    //     h1 = h2 + e + a2
                    //     h2 = h3 + a + b2
                    //     h3 = h4 + b + c2
                    //     h4 = T
                    //
                    // with (a, b, c, d, e) the left line and (a2, b2, c2, d2,
                    // e2) the right. So each output takes the NEXT chaining
                    // value, and the sum involving h0 lands in the last word.
                    // Writing it as "h0 = h0 + b + c2" is off by one word in
                    // every position and produces a digest whose bytes are all
                    // right in the wrong places.
                    //
                    // The additions read `state_in`, still the value the block
                    // started from, since no new block can arrive while busy.
                    la <= state_in[ 63: 32] + lc + rd;
                    lb <= state_in[ 95: 64] + ld + re;
                    lc <= state_in[127: 96] + le + ra;
                    ld <= state_in[159:128] + la + rb;
                    le <= state_in[ 31:  0] + lb + rc;
                    busy   <= 1'b0;
                    done_r <= 1'b1;
                end
            end
        end
    end

    assign digest_out[ 31:  0] = la;
    assign digest_out[ 63: 32] = lb;
    assign digest_out[ 95: 64] = lc;
    assign digest_out[127: 96] = ld;
    assign digest_out[159:128] = le;
    assign done = done_r;

endmodule
