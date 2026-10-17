// SHA-256 compression core, FIPS 180-4.
//
// STATUS: VERIFIED against every vector in `rtl/sim/vectors/sha256.svh`, which
// scripts/gen-rtl-vectors.py emits from Python hashlib.
//
// # Interface
//
// Same as every core in `rtl/cores`; see `md5_core.sv` and `rtl/README.md`.
// Big endian, like SHA-1 and unlike MD5: `msg_blk[32*i +: 32]` is word i of the
// block with no byte reversal, and `state_in[31:0]` is H, the first state word.
//
// # Iterative
//
// 64 rounds at one per cycle, 65 cycles of latency. A fully pipelined SHA-256
// would need 64 stages each carrying eight state words and a sixteen word
// schedule window: about 15,000 flip flops for one hash per 65 cycles. The
// iterative form needs the state, one sixteen word window, and one adder.
// Instantiate several instead of one wide one.
//
// # The schedule
//
// W[i] for i below 16 is the message. Above that it is
//
//     W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
//
// with a sixteen word rotating window, so all four operands are present and
// W[i-16] is the slot being written. The value is read before the write, which
// is why `wsel` is computed into a temporary first: writing
// `w[slot(round)] <= ... w[slot(round)] ...` reads the old value in Verilog, but
// only because the assignment is non blocking, and that is a subtle enough rule
// that this file does not rely on it.
//
// # What was wrong before
//
// The previous sha256_core held its constant table in an `always_comb` with 64
// constant part select assignments. Every assignment is a constant, so the
// process has no sensitivities; Icarus Verilog reports "always_comb process has
// no sensitivities" and never runs it, leaving K entirely X, so every digest
// came out X. The pipeline also indexed its schedule window with
// `W_pipe[r][r]`, which is only correct for round r below 16 because the window
// rotates, and it drove eight unpacked array ports that do not propagate to the
// parent under this simulator. All three are gone.

module sha256_core (
    input  logic          clk,
    input  logic          rst_n,
    input  logic          valid,
    output logic          ready,
    input  logic [511:0]  msg_blk,
    input  logic [255:0]  state_in,
    output logic [255:0]  digest_out,
    output logic          done
);

    // Cycles from `valid` to `done`.
    localparam int LATENCY = 66;

    // Round constants, the first 32 bits of the fractional parts of the cube
    // roots of the first sixty four primes. An `initial` block, not always_comb:
    // see the header.
    logic [31:0] K [0:63];

    initial begin
        K[ 0] = 32'h428a2f98; K[ 1] = 32'h71374491; K[ 2] = 32'hb5c0fbcf; K[ 3] = 32'he9b5dba5;
        K[ 4] = 32'h3956c25b; K[ 5] = 32'h59f111f1; K[ 6] = 32'h923f82a4; K[ 7] = 32'hab1c5ed5;
        K[ 8] = 32'hd807aa98; K[ 9] = 32'h12835b01; K[10] = 32'h243185be; K[11] = 32'h550c7dc3;
        K[12] = 32'h72be5d74; K[13] = 32'h80deb1fe; K[14] = 32'h9bdc06a7; K[15] = 32'hc19bf174;
        K[16] = 32'he49b69c1; K[17] = 32'hefbe4786; K[18] = 32'h0fc19dc6; K[19] = 32'h240ca1cc;
        K[20] = 32'h2de92c6f; K[21] = 32'h4a7484aa; K[22] = 32'h5cb0a9dc; K[23] = 32'h76f988da;
        K[24] = 32'h983e5152; K[25] = 32'ha831c66d; K[26] = 32'hb00327c8; K[27] = 32'hbf597fc7;
        K[28] = 32'hc6e00bf3; K[29] = 32'hd5a79147; K[30] = 32'h06ca6351; K[31] = 32'h14292967;
        K[32] = 32'h27b70a85; K[33] = 32'h2e1b2138; K[34] = 32'h4d2c6dfc; K[35] = 32'h53380d13;
        K[36] = 32'h650a7354; K[37] = 32'h766a0abb; K[38] = 32'h81c2c92e; K[39] = 32'h92722c85;
        K[40] = 32'ha2bfe8a1; K[41] = 32'ha81a664b; K[42] = 32'hc24b8b70; K[43] = 32'hc76c51a3;
        K[44] = 32'hd192e819; K[45] = 32'hd6990624; K[46] = 32'hf40e3585; K[47] = 32'h106aa070;
        K[48] = 32'h19a4c116; K[49] = 32'h1e376c08; K[50] = 32'h2748774c; K[51] = 32'h34b0bcb5;
        K[52] = 32'h391c0cb3; K[53] = 32'h4ed8aa4a; K[54] = 32'h5b9cca4f; K[55] = 32'h682e6ff3;
        K[56] = 32'h748f82ee; K[57] = 32'h78a5636f; K[58] = 32'h84c87814; K[59] = 32'h8cc70208;
        K[60] = 32'h90befffa; K[61] = 32'ha4506ceb; K[62] = 32'hbef9a3f7; K[63] = 32'hc67178f2;
    end

    // The four small functions of SHA-256.
    //
    // # The rotation rule, written out because getting it wrong is invisible
    //
    // A rotate right by n is {x[n-1:0], x[31:n]}: the low n bits move to the top
    // and everything else moves down by n. It is NOT {x[31-n:0], x[31:31-n]},
    // which looks equivalent and is actually a rotate LEFT by n. Both compile,
    // both are 32 bits wide, and the difference is that every digest is wrong.
    //
    // The previous revision of this core wrote sigma0 as {x[24:0], x[31:25]},
    // which is ROL7 rather than ROTR7. It returned a plausible 32 bit value for
    // every input, so nothing looked wrong: the core simply did not compute
    // SHA-256, and with no testbench that ran, nothing said so.
    //
    // # Which function is which
    //
    //   sigma0, sigma1   message schedule only: ROTR7^ROTR18^SHR3 and
    //                    ROTR17^ROTR19^SHR10
    //   Sigma0, Sigma1   compression function:  ROTR2^ROTR13^ROTR22 and
    //                    ROTR6^ROTR11^ROTR25
    function automatic [31:0] sigma0(input [31:0] x);
        sigma0 = {x[ 6:0], x[31: 7]} ^ {x[17:0], x[31:18]} ^ {29'b0, x[31:3]};
    endfunction

    function automatic [31:0] sigma1(input [31:0] x);
        sigma1 = {x[16:0], x[31:17]} ^ {x[18:0], x[31:19]} ^ {22'b0, x[31:10]};
    endfunction

    function automatic [31:0] Sigma0(input [31:0] x);
        Sigma0 = {x[ 1:0], x[31: 2]} ^ {x[12:0], x[31:13]} ^ {x[21:0], x[31:22]};
    endfunction

    function automatic [31:0] Sigma1(input [31:0] x);
        Sigma1 = {x[ 5:0], x[31: 6]} ^ {x[10:0], x[31:11]} ^ {x[24:0], x[31:25]};
    endfunction

    function automatic [31:0] Ch(input [31:0] e, input [31:0] f, input [31:0] g);
        Ch = (e & f) ^ (~e & g);
    endfunction

    function automatic [31:0] Maj(input [31:0] a, input [31:0] b, input [31:0] c);
        Maj = (a & b) ^ (a & c) ^ (b & c);
    endfunction

    // Sixteen word rotating schedule window.
    logic [31:0] w [0:15];

    logic [6:0] round;
    logic       busy;
    logic       done_r;

    logic [31:0] a, b, c, d, e, f, g, h;

    assign ready = ~busy;

    function automatic [3:0] slot(input [6:0] n);
        slot = n[3:0];
    endfunction

    initial begin
        for (int i = 0; i < 16; i = i + 1) w[i] = 32'h0;
        round  = 7'd0;
        busy   = 1'b0;
        done_r = 1'b0;
        a = 32'h6a09e667; b = 32'hbb67ae85; c = 32'h3c6ef372; d = 32'ha54ff53a;
        e = 32'h510e527f; f = 32'h9b05688c; g = 32'h1f83d9ab; h = 32'h5be0cd19;
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < 16; i = i + 1) w[i] <= 32'h0;
            round  <= 7'd0;
            busy   <= 1'b0;
            done_r <= 1'b0;
            a <= 32'h6a09e667; b <= 32'hbb67ae85; c <= 32'h3c6ef372; d <= 32'ha54ff53a;
            e <= 32'h510e527f; f <= 32'h9b05688c; g <= 32'h1f83d9ab; h <= 32'h5be0cd19;
        end else begin
            done_r <= 1'b0;

            if (valid && !busy) begin
                busy  <= 1'b1;
                round <= 7'd0;
                a <= state_in[31:0];
                b <= state_in[63:32];
                c <= state_in[95:64];
                d <= state_in[127:96];
                e <= state_in[159:128];
                f <= state_in[191:160];
                g <= state_in[223:192];
                h <= state_in[255:224];
            end else if (busy) begin
                if (round < 7'd64) begin
                    logic [31:0] wsel, t1, t2;

                    // The schedule word for this round. Below round 16 it is the
                    // message; above it is expanded from the window.
                    if (round < 7'd16)
                        wsel = msg_blk[32 * round[3:0] +: 32];
                    else
                        wsel = sigma1(w[slot(round - 7'd2)])
                             + w[slot(round - 7'd7)]
                             + sigma0(w[slot(round - 7'd15)])
                             + w[slot(round - 7'd16)];

                    w[slot(round)] <= wsel;

                    t1 = h + Sigma1(e) + Ch(e, f, g) + K[round[5:0]] + wsel;
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
                    a <= a + state_in[31:0];
                    b <= b + state_in[63:32];
                    c <= c + state_in[95:64];
                    d <= d + state_in[127:96];
                    e <= e + state_in[159:128];
                    f <= f + state_in[191:160];
                    g <= g + state_in[223:192];
                    h <= h + state_in[255:224];
                    busy   <= 1'b0;
                    done_r <= 1'b1;
                end
            end
        end
    end

    assign digest_out[31:0]   = a;
    assign digest_out[63:32]  = b;
    assign digest_out[95:64]  = c;
    assign digest_out[127:96] = d;
    assign digest_out[159:128] = e;
    assign digest_out[191:160] = f;
    assign digest_out[223:192] = g;
    assign digest_out[255:224] = h;
    assign done = done_r;

endmodule