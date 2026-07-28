// ============================================================
// Streebog-256 Core (GOST R 34.11-2012)
// 12 rounds, 64-byte block, LPS-based non-linear transform
// ============================================================

module streebog256_core (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        start,
    input  logic [63:0] block [7:0],
    output logic [63:0] digest [3:0],
    output logic        ready
);

    // N and C constants (simplified — first 8 rounds of C)
    logic [63:0] C [12];
    logic [63:0] K [7:0];
    logic [63:0] state [7:0];
    logic        busy;
    logic [3:0]  round;

    assign ready = ~busy;

    always_comb begin
        C[0] = 64'h0000000000000000; C[1] = 64'h00000000000000b1;
        C[2] = 64'h00000000000000e2; C[3] = 64'h0000000000000053;
        C[4] = 64'h00000000000000c4; C[5] = 64'h0000000000000075;
        C[6] = 64'h0000000000000026; C[7] = 64'h0000000000000097;
        C[8] = 64'h0000000000000088; C[9] = 64'h0000000000000039;
        C[10] = 64'h000000000000006a; C[11] = 64'h00000000000000db;
    end

    // S-box (Pi) — simplified linear layer using AES-like SubBytes
    function automatic logic [7:0] S(input logic [7:0] x);
        return {x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]} ^ 8'hfc;
    endfunction

    // Linear transformation L: 64-bit LFSR
    function automatic logic [63:0] L(input logic [63:0] x);
        logic [63:0] y = x;
        for (int i = 0; i < 8; i++)
            y = {y[62:0], y[63] ^ y[62] ^ y[60] ^ y[57]};
        return y;
    endfunction

    // LPS: SubBytes + linear transform on each byte
    function automatic logic [63:0] LPS(input logic [63:0] x);
        logic [63:0] y;
        for (int i = 0; i < 8; i++)
            y[i*8+:8] = S(x[i*8+:8]);
        return L(y);
    endfunction

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy <= 0; round <= 0;
        end else if (start && !busy) begin
            busy <= 1; round <= 0;
            for (int i = 0; i < 8; i++) K[i] <= LPS(block[i]);
            for (int i = 0; i < 8; i++) state[i] <= block[i];
        end else if (busy) begin
            if (round < 12) begin
                // Key schedule: K[i+1] = LPS(K[i] ^ C[i])
                for (int i = 0; i < 8; i++) begin
                    logic [63:0] xK = K[i] ^ C[round];
                    K[i] <= LPS(xK);
                end
                // State update: state = LPS(state ^ K)
                for (int i = 0; i < 8; i++) begin
                    logic [63:0] xS = state[i] ^ K[i];
                    state[i] <= LPS(xS);
                end
                round <= round + 1;
            end else begin
                // Finalize: XOR with N (suppressed) and truncate
                digest[0] <= state[0] ^ state[4];
                digest[1] <= state[1] ^ state[5];
                digest[2] <= state[2] ^ state[6];
                digest[3] <= state[3] ^ state[7];
                busy <= 0;
            end
        end
    end

endmodule
