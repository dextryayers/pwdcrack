// ============================================================
// SHA-256 Pipelined Core — 1 hash/cycle, 65-cycle latency
// 64 rounds fully unrolled
// ============================================================

module sha256_core (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        valid,
    output logic        ready,
    input  logic [31:0] msg_word  [15:0],
    input  logic [31:0] h_in      [7:0],
    output logic [31:0] h_out     [7:0],
    output logic        done
);

    // SHA-256 K constants (first 32 bits of fractional parts of cube roots of primes 2-311)
    logic [31:0] K [0:63];
    always_comb begin
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

    // Pipeline registers (65 stages: 64 rounds + final addition)
    logic [31:0] a_pipe [65:0];
    logic [31:0] b_pipe [65:0];
    logic [31:0] c_pipe [65:0];
    logic [31:0] d_pipe [65:0];
    logic [31:0] e_pipe [65:0];
    logic [31:0] f_pipe [65:0];
    logic [31:0] g_pipe [65:0];
    logic [31:0] h_pipe [65:0];
    logic        valid_pipe [65:0];

    // Message schedule expansion (Wt)
    logic [31:0] W_pipe [65:0][15:0];
    always_comb begin
        for (int i = 0; i < 16; i++) W_pipe[0][i] = msg_word[i];
    end

    function automatic [31:0] sigma0(input [31:0] x);
        return {x[ 1:0], x[31:2]} ^ {x[12:0], x[31:13]} ^ {x[21:0], 10'b0, x[31:22]};
    endfunction

    function automatic [31:0] sigma1(input [31:0] x);
        return {x[ 5:0], x[31:6]} ^ {x[10:0], x[31:11]} ^ {x[24:0], 7'b0, x[31:25]};
    endfunction

    function automatic [31:0] Sigma0(input [31:0] x);
        return {x[ 1:0], x[31:2]} ^ {x[12:0], x[31:13]} ^ {x[21:0], 10'b0, x[31:22]};
    endfunction

    function automatic [31:0] Sigma1(input [31:0] x);
        return {x[ 5:0], x[31:6]} ^ {x[10:0], x[31:11]} ^ {x[24:0], 7'b0, x[31:25]};
    endfunction

    function automatic [31:0] Maj(input [31:0] a, b, c);
        return (a & b) ^ (a & c) ^ (b & c);
    endfunction

    function automatic [31:0] Ch(input [31:0] e, f, g);
        return (e & f) ^ (~e & g);
    endfunction

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < 66; i++) begin
                a_pipe[i] <= '0; b_pipe[i] <= '0; c_pipe[i] <= '0; d_pipe[i] <= '0;
                e_pipe[i] <= '0; f_pipe[i] <= '0; g_pipe[i] <= '0; h_pipe[i] <= '0;
                valid_pipe[i] <= '0;
                for (int j = 0; j < 16; j++) W_pipe[i][j] <= '0;
            end
        end else begin
            // Stage 0: load
            a_pipe[0] <= h_in[0]; b_pipe[0] <= h_in[1]; c_pipe[0] <= h_in[2]; d_pipe[0] <= h_in[3];
            e_pipe[0] <= h_in[4]; f_pipe[0] <= h_in[5]; g_pipe[0] <= h_in[6]; h_pipe[0] <= h_in[7];
            valid_pipe[0] <= valid;

            // Rounds 0-63
            for (int r = 0; r < 64; r++) begin
                logic [31:0] w;
                if (r < 16)
                    w = W_pipe[r][r];
                else
                    w = sigma1(W_pipe[r][14]) + W_pipe[r][9] + sigma0(W_pipe[r][1]) + W_pipe[r][0];

                // Message schedule expansion for next stage
                if (r >= 16) begin
                    for (int i = 0; i < 15; i++)
                        W_pipe[r+1][i] <= W_pipe[r][i+1];
                    W_pipe[r+1][15] <= w;
                end else begin
                    for (int i = 0; i < 16; i++)
                        W_pipe[r+1][i] <= W_pipe[r][i];
                end

                logic [31:0] t1, t2;
                t1 = h_pipe[r] + Sigma1(e_pipe[r]) + Ch(e_pipe[r], f_pipe[r], g_pipe[r]) + K[r] + w;
                t2 = Sigma0(a_pipe[r]) + Maj(a_pipe[r], b_pipe[r], c_pipe[r]);

                a_pipe[r+1] <= t1 + t2;
                b_pipe[r+1] <= a_pipe[r];
                c_pipe[r+1] <= b_pipe[r];
                d_pipe[r+1] <= c_pipe[r];
                e_pipe[r+1] <= d_pipe[r] + t1;
                f_pipe[r+1] <= e_pipe[r];
                g_pipe[r+1] <= f_pipe[r];
                h_pipe[r+1] <= g_pipe[r];
                valid_pipe[r+1] <= valid_pipe[r];
            end

            // Stage 65: final addition
            a_pipe[65] <= a_pipe[64] + h_in[0];
            b_pipe[65] <= b_pipe[64] + h_in[1];
            c_pipe[65] <= c_pipe[64] + h_in[2];
            d_pipe[65] <= d_pipe[64] + h_in[3];
            e_pipe[65] <= e_pipe[64] + h_in[4];
            f_pipe[65] <= f_pipe[64] + h_in[5];
            g_pipe[65] <= g_pipe[64] + h_in[6];
            h_pipe[65] <= h_pipe[64] + h_in[7];
            valid_pipe[65] <= valid_pipe[64];
        end
    end

    assign h_out[0] = a_pipe[65];
    assign h_out[1] = b_pipe[65];
    assign h_out[2] = c_pipe[65];
    assign h_out[3] = d_pipe[65];
    assign h_out[4] = e_pipe[65];
    assign h_out[5] = f_pipe[65];
    assign h_out[6] = g_pipe[65];
    assign h_out[7] = h_pipe[65];
    assign done = valid_pipe[65];
    assign ready = 1'b1;

endmodule
