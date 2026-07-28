// ============================================================
// SHA3-256 Keccak Core — 24 rounds, 1600-bit state
// Theta, Rho, Pi, Chi, Iota steps per FIPS 202
// ============================================================

module sha3_256_core (
    input  logic         clk,
    input  logic         rst_n,
    input  logic         start,
    input  logic [63:0]  block [24:0],  // 1600-bit state init
    output logic [63:0]  digest [3:0],
    output logic         ready
);

    typedef logic [63:0] lane_t;
    lane_t state [5][5];
    lane_t round_const [24];
    logic        busy;
    logic [4:0]  round;

    assign ready = ~busy;

    // Keccak-f round constants (first 24)
    always_comb begin
        round_const[0]  = 64'h0000000000000001; round_const[1]  = 64'h0000000000008082;
        round_const[2]  = 64'h800000000000808a; round_const[3]  = 64'h8000000080008000;
        round_const[4]  = 64'h000000000000808b; round_const[5]  = 64'h0000000080000001;
        round_const[6]  = 64'h8000000080008081; round_const[7]  = 64'h8000000000008009;
        round_const[8]  = 64'h000000000000008a; round_const[9]  = 64'h0000000000000088;
        round_const[10] = 64'h0000000080008009; round_const[11] = 64'h000000008000000a;
        round_const[12] = 64'h000000008000808b; round_const[13] = 64'h800000000000008b;
        round_const[14] = 64'h8000000000008089; round_const[15] = 64'h8000000000008003;
        round_const[16] = 64'h8000000000008002; round_const[17] = 64'h8000000000000080;
        round_const[18] = 64'h000000000000800a; round_const[19] = 64'h800000008000000a;
        round_const[20] = 64'h8000000080008081; round_const[21] = 64'h8000000000008080;
        round_const[22] = 64'h0000000080000001; round_const[23] = 64'h8000000080008008;
    end

    // Rotation offsets for Rho
    function automatic logic [5:0] rho_off(input int x, y);
        int offsets[5][5] = '{
            '{0, 1, 62, 28, 27},
            '{36, 44, 6, 55, 20},
            '{3, 10, 43, 25, 39},
            '{41, 45, 15, 21, 8},
            '{18, 2, 61, 56, 14}
        };
        return offsets[x][y];
    endfunction

    function automatic lane_t rotl(lane_t x, input int n);
        return {x[n-1:0], x[63:n]};
    endfunction

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy <= 0; round <= 0;
        end else if (start && !busy) begin
            busy <= 1; round <= 0;
            for (int y = 0; y < 5; y++)
                for (int x = 0; x < 5; x++)
                    state[x][y] <= block[y*5 + x];
        end else if (busy) begin
            if (round < 24) begin
                // Theta
                lane_t C[5], D[5];
                for (int x = 0; x < 5; x++)
                    C[x] = state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4];
                for (int x = 0; x < 5; x++)
                    D[x] = C[(x+4)%5] ^ rotl(C[(x+1)%5], 1);

                // Rho and Pi
                lane_t B[5][5];
                for (int y = 0; y < 5; y++)
                    for (int x = 0; x < 5; x++)
                        B[y][(2*x+3*y)%5] = rotl(state[x][y] ^ D[x], rho_off(x,y));

                // Chi
                for (int y = 0; y < 5; y++)
                    for (int x = 0; x < 5; x++)
                        state[x][y] <= B[x][y] ^ ((~B[(x+1)%5][y]) & B[(x+2)%5][y]);

                // Iota
                state[0][0] <= state[0][0] ^ round_const[round];

                round <= round + 1;
            end else begin
                busy <= 0;
            end
        end
    end

    // SHA3-256: take first 256 bits (4 lanes) of state
    assign digest[0] = state[0][0];
    assign digest[1] = state[1][0];
    assign digest[2] = state[2][0];
    assign digest[3] = state[3][0];

endmodule
