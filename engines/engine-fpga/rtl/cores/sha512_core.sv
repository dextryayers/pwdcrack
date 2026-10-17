// SHA-512 compression core, FIPS 180-4.
//
// STATUS: VERIFIED against every vector in `rtl/sim/vectors/sha512.svh`, which
// scripts/gen-rtl-vectors.py emits from Python hashlib.
//
// # Interface
//
// Same shape as every core in `rtl/cores`, with 64 bit words: a 1024 bit block,
// a 512 bit state, a 512 bit digest, word 0 in the low bits. Big endian, like
// SHA-1 and SHA-256. See `md5_core.sv` and `rtl/README.md`.
//
// # The uppercase sigmas rotate three times, unlike SHA-256's
//
//     sigma0 = ROTR1  ^ ROTR8  ^ SHR7        (schedule)
//     sigma1 = ROTR19 ^ ROTR61 ^ SHR6        (schedule)
//     Sigma0 = ROTR28 ^ ROTR34 ^ ROTR39      (compression)
//     Sigma1 = ROTR14 ^ ROTR18 ^ ROTR41      (compression)
//
// The last two are the detail that costs an afternoon. SHA-256's Sigma0 and
// Sigma1 end in a logical right shift, and so do SHA-512's lowercase sigmas, so
// writing SHA-512's uppercase ones by analogy with SHA-256's produces three
// correct-looking rotate expressions and a wrong digest. They are all rotates.
//
// # Iterative
//
// 80 rounds at one per cycle, 82 cycles of latency. A pipelined SHA-512 would
// need eighty stages of eight 64 bit registers plus a sixteen word schedule
// window, which is over 60,000 flip flops for one hash per 82 cycles.
//
// # Constant table
//
// The eighty round constants are the first 64 bits of the fractional parts of
// the cube roots of the first eighty primes. They were computed with an exact
// integer cube root and cross checked against the table in the `sha2` crate,
// which is in the Cargo registry this repository already depends on: both agree
// on all eighty. The first entry is 0x428a2f98d728ae22, which is what
// floor(frac(cbrt(2)) * 2^64) gives; the value usually quoted from memory,
// 0x428a2f728d728ae2, is not SHA-512's first constant and produces wrong digests.

module sha512_core (
    input  logic          clk,
    input  logic          rst_n,
    input  logic          valid,
    output logic          ready,
    input  logic [1023:0] msg_blk,
    input  logic [511:0]  state_in,
    output logic [511:0]  digest_out,
    output logic          done
);

    // Cycles from `valid` to `done`.
    localparam int LATENCY = 82;

    // Round constants: see the header. An `initial` block rather than
    // always_comb, because every assignment is a constant and Icarus reports a
    // constant only always_comb as having no sensitivities and never runs it.
    logic [63:0] K [0:79];

    initial begin
        K[ 0] = 64'h428a2f98d728ae22; K[ 1] = 64'h7137449123ef65cd;
        K[ 2] = 64'hb5c0fbcfec4d3b2f; K[ 3] = 64'he9b5dba58189dbbc;
        K[ 4] = 64'h3956c25bf348b538; K[ 5] = 64'h59f111f1b605d019;
        K[ 6] = 64'h923f82a4af194f9b; K[ 7] = 64'hab1c5ed5da6d8118;
        K[ 8] = 64'hd807aa98a3030242; K[ 9] = 64'h12835b0145706fbe;
        K[10] = 64'h243185be4ee4b28c; K[11] = 64'h550c7dc3d5ffb4e2;
        K[12] = 64'h72be5d74f27b896f; K[13] = 64'h80deb1fe3b1696b1;
        K[14] = 64'h9bdc06a725c71235; K[15] = 64'hc19bf174cf692694;
        K[16] = 64'he49b69c19ef14ad2; K[17] = 64'hefbe4786384f25e3;
        K[18] = 64'h0fc19dc68b8cd5b5; K[19] = 64'h240ca1cc77ac9c65;
        K[20] = 64'h2de92c6f592b0275; K[21] = 64'h4a7484aa6ea6e483;
        K[22] = 64'h5cb0a9dcbd41fbd4; K[23] = 64'h76f988da831153b5;
        K[24] = 64'h983e5152ee66dfab; K[25] = 64'ha831c66d2db43210;
        K[26] = 64'hb00327c898fb213f; K[27] = 64'hbf597fc7beef0ee4;
        K[28] = 64'hc6e00bf33da88fc2; K[29] = 64'hd5a79147930aa725;
        K[30] = 64'h06ca6351e003826f; K[31] = 64'h142929670a0e6e70;
        K[32] = 64'h27b70a8546d22ffc; K[33] = 64'h2e1b21385c26c926;
        K[34] = 64'h4d2c6dfc5ac42aed; K[35] = 64'h53380d139d95b3df;
        K[36] = 64'h650a73548baf63de; K[37] = 64'h766a0abb3c77b2a8;
        K[38] = 64'h81c2c92e47edaee6; K[39] = 64'h92722c851482353b;
        K[40] = 64'ha2bfe8a14cf10364; K[41] = 64'ha81a664bbc423001;
        K[42] = 64'hc24b8b70d0f89791; K[43] = 64'hc76c51a30654be30;
        K[44] = 64'hd192e819d6ef5218; K[45] = 64'hd69906245565a910;
        K[46] = 64'hf40e35855771202a; K[47] = 64'h106aa07032bbd1b8;
        K[48] = 64'h19a4c116b8d2d0c8; K[49] = 64'h1e376c085141ab53;
        K[50] = 64'h2748774cdf8eeb99; K[51] = 64'h34b0bcb5e19b48a8;
        K[52] = 64'h391c0cb3c5c95a63; K[53] = 64'h4ed8aa4ae3418acb;
        K[54] = 64'h5b9cca4f7763e373; K[55] = 64'h682e6ff3d6b2b8a3;
        K[56] = 64'h748f82ee5defb2fc; K[57] = 64'h78a5636f43172f60;
        K[58] = 64'h84c87814a1f0ab72; K[59] = 64'h8cc702081a6439ec;
        K[60] = 64'h90befffa23631e28; K[61] = 64'ha4506cebde82bde9;
        K[62] = 64'hbef9a3f7b2c67915; K[63] = 64'hc67178f2e372532b;
        K[64] = 64'hca273eceea26619c; K[65] = 64'hd186b8c721c0c207;
        K[66] = 64'heada7dd6cde0eb1e; K[67] = 64'hf57d4f7fee6ed178;
        K[68] = 64'h06f067aa72176fba; K[69] = 64'h0a637dc5a2c898a6;
        K[70] = 64'h113f9804bef90dae; K[71] = 64'h1b710b35131c471b;
        K[72] = 64'h28db77f523047d84; K[73] = 64'h32caab7b40c72493;
        K[74] = 64'h3c9ebe0a15c9bebc; K[75] = 64'h431d67c49c100d4c;
        K[76] = 64'h4cc5d4becb3e42b6; K[77] = 64'h597f299cfc657e2a;
        K[78] = 64'h5fcb6fab3ad6faec; K[79] = 64'h6c44198c4a475817;
    end

    // ROTR by n is {x[n-1:0], x[31:n]} for a 32 bit word and the same rule for
    // 64 bits: {x[n-1:0], x[63:n]}. The reversed form, {x[63-n:0], x[63:63-n]},
    // is a rotate left and produces a plausible wrong answer; see sha256_core.
    function automatic [63:0] rotr1(input [63:0] x);
        rotr1 = {x[ 0:0], x[63: 1]};
    endfunction

    function automatic [63:0] rotr8(input [63:0] x);
        rotr8 = {x[ 7:0], x[63: 8]};
    endfunction

    function automatic [63:0] rotr19(input [63:0] x);
        rotr19 = {x[18:0], x[63:19]};
    endfunction

    function automatic [63:0] rotr61(input [63:0] x);
        rotr61 = {x[60:0], x[63:61]};
    endfunction

    function automatic [63:0] rotr28(input [63:0] x);
        rotr28 = {x[27:0], x[63:28]};
    endfunction

    function automatic [63:0] rotr34(input [63:0] x);
        rotr34 = {x[33:0], x[63:34]};
    endfunction

    function automatic [63:0] rotr39(input [63:0] x);
        rotr39 = {x[38:0], x[63:39]};
    endfunction

    function automatic [63:0] rotr14(input [63:0] x);
        rotr14 = {x[13:0], x[63:14]};
    endfunction

    function automatic [63:0] rotr18(input [63:0] x);
        rotr18 = {x[17:0], x[63:18]};
    endfunction

    function automatic [63:0] rotr41(input [63:0] x);
        rotr41 = {x[40:0], x[63:41]};
    endfunction

    function automatic [63:0] sigma0(input [63:0] x);
        sigma0 = rotr1(x) ^ rotr8(x) ^ {57'b0, x[63:7]};
    endfunction

    function automatic [63:0] sigma1(input [63:0] x);
        sigma1 = rotr19(x) ^ rotr61(x) ^ {58'b0, x[63:6]};
    endfunction

    function automatic [63:0] Sigma0(input [63:0] x);
        Sigma0 = rotr28(x) ^ rotr34(x) ^ rotr39(x);
    endfunction

    function automatic [63:0] Sigma1(input [63:0] x);
        Sigma1 = rotr14(x) ^ rotr18(x) ^ rotr41(x);
    endfunction

    function automatic [63:0] Ch(input [63:0] e, input [63:0] f, input [63:0] g);
        Ch = (e & f) ^ (~e & g);
    endfunction

    function automatic [63:0] Maj(input [63:0] a, input [63:0] b, input [63:0] c);
        Maj = (a & b) ^ (a & c) ^ (b & c);
    endfunction

    logic [63:0] w [0:15];

    logic [6:0] round;
    logic       busy;
    logic       done_r;

    logic [63:0] a, b, c, d, e, f, g, h;

    assign ready = ~busy;

    function automatic [3:0] slot(input [6:0] n);
        slot = n[3:0];
    endfunction

    initial begin
        for (int i = 0; i < 16; i = i + 1) w[i] = 64'h0;
        round  = 7'd0;
        busy   = 1'b0;
        done_r = 1'b0;
        a = 64'h6a09e667f3bcc908; b = 64'hbb67ae8584caa73b;
        c = 64'h3c6ef372fe94f82b; d = 64'ha54ff53a5f1d36f1;
        e = 64'h510e527fade682d1; f = 64'h9b05688c2b3e6c1f;
        g = 64'h1f83d9abfb41bd6b; h = 64'h5be0cd19137e2179;
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < 16; i = i + 1) w[i] <= 64'h0;
            round  <= 7'd0;
            busy   <= 1'b0;
            done_r <= 1'b0;
            a <= 64'h6a09e667f3bcc908; b <= 64'hbb67ae8584caa73b;
            c <= 64'h3c6ef372fe94f82b; d <= 64'ha54ff53a5f1d36f1;
            e <= 64'h510e527fade682d1; f <= 64'h9b05688c2b3e6c1f;
            g <= 64'h1f83d9abfb41bd6b; h <= 64'h5be0cd19137e2179;
        end else begin
            done_r <= 1'b0;

            if (valid && !busy) begin
                busy  <= 1'b1;
                round <= 7'd0;
                a <= state_in[ 63:  0]; b <= state_in[127: 64];
                c <= state_in[191:128]; d <= state_in[255:192];
                e <= state_in[319:256]; f <= state_in[383:320];
                g <= state_in[447:384]; h <= state_in[511:448];
            end else if (busy) begin
                if (round < 7'd80) begin
                    logic [63:0] wsel, t1, t2;

                    if (round < 7'd16)
                        wsel = msg_blk[64 * round[3:0] +: 64];
                    else
                        wsel = sigma1(w[slot(round - 7'd2)])
                             + w[slot(round - 7'd7)]
                             + sigma0(w[slot(round - 7'd15)])
                             + w[slot(round - 7'd16)];

                    w[slot(round)] <= wsel;

                    t1 = h + Sigma1(e) + Ch(e, f, g) + K[round[6:0]] + wsel;
                    t2 = Sigma0(a) + Maj(a, b, c);

                    h <= g;
                    g <= f;
                    f <= e;
                    e <= d + t1;
                    d <= c;
                    c <= b;
                    b <= a;
                    a <= t1 + t2;
                    round <= round + 7'd1;
                end else begin
                    a <= a + state_in[ 63:  0]; b <= b + state_in[127: 64];
                    c <= c + state_in[191:128]; d <= d + state_in[255:192];
                    e <= e + state_in[319:256]; f <= f + state_in[383:320];
                    g <= g + state_in[447:384]; h <= h + state_in[511:448];
                    busy   <= 1'b0;
                    done_r <= 1'b1;
                end
            end
        end
    end

    assign digest_out[ 63:  0] = a;
    assign digest_out[127: 64] = b;
    assign digest_out[191:128] = c;
    assign digest_out[255:192] = d;
    assign digest_out[319:256] = e;
    assign digest_out[383:320] = f;
    assign digest_out[447:384] = g;
    assign digest_out[511:448] = h;
    assign done = done_r;

endmodule
