// ============================================================
// BLAKE2b-512 Core — 12 rounds, 128-byte block
// 8-word IV, 16-word message
// ============================================================

module blake2b_core (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        start,
    input  logic [63:0] msg [15:0],
    output logic [63:0] digest [7:0],
    output logic        ready
);

    logic [63:0] iv [7:0];
    assign iv[0] = 64'h6a09e667f3bcc908; assign iv[1] = 64'hbb67ae8584caa73b;
    assign iv[2] = 64'h3c6ef372fe94f82b; assign iv[3] = 64'ha54ff53a5f1d36f1;
    assign iv[4] = 64'h510e527fade682d1; assign iv[5] = 64'h9b05688c2b3e6c1f;
    assign iv[6] = 64'h1f83d9abfb41bd6b; assign iv[7] = 64'h5be0cd19137e2179;

    logic [3:0] sigma [12][16];
    always_comb begin
        sigma[0]  = '{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        sigma[1]  = '{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3};
        sigma[2]  = '{11,8,12,0,5,2,15,13,10,14,3,6,7,1,9,4};
        sigma[3]  = '{7,9,3,1,13,12,11,14,2,6,5,10,4,0,15,8};
        sigma[4]  = '{9,0,5,7,2,4,10,15,14,1,11,12,6,8,3,13};
        sigma[5]  = '{2,12,6,10,0,11,8,3,4,13,7,5,15,14,1,9};
        sigma[6]  = '{12,5,1,15,14,13,4,10,0,7,6,3,9,2,8,11};
        sigma[7]  = '{13,11,7,14,12,1,3,9,5,0,15,4,8,6,2,10};
        sigma[8]  = '{6,15,14,9,11,3,0,8,12,2,13,7,1,4,10,5};
        sigma[9]  = '{10,2,8,4,7,6,1,5,15,11,9,14,3,12,13,0};
        sigma[10] = '{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
        sigma[11] = '{14,10,4,8,9,15,13,6,1,12,0,2,11,7,5,3};
    end

    logic [63:0] v [15:0];
    logic        busy;
    logic [3:0]  round;

    assign ready = ~busy;

    function automatic logic [63:0] rotr64(input logic [63:0] x, input logic [5:0] n);
        return {x[n-1:0], x[63:n]};
    endfunction

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy <= 0; round <= 0;
        end else if (start && !busy) begin
            busy <= 1; round <= 0;
            v[0] <= iv[0]; v[1] <= iv[1]; v[2] <= iv[2]; v[3] <= iv[3];
            v[4] <= iv[4]; v[5] <= iv[5]; v[6] <= iv[6]; v[7] <= iv[7];
            v[8] <= 64'h0; v[9] <= 64'h0; v[10] <= 64'h0; v[11] <= 64'h0;
            v[12] <= 64'h0; v[13] <= 64'h0; v[14] <= ~(64'h0); v[15] <= 64'h0;
        end else if (busy) begin
            if (round < 12) begin
                for (int i = 0; i < 8; i++) begin
                    int s = sigma[round][2*i];
                    int t = sigma[round][2*i+1];
                    v[0] <= v[0] + v[4] + msg[s];
                    v[12] <= rotr64(v[12] ^ v[0], 32);
                    v[8] <= v[8] + v[12];
                    v[4] <= rotr64(v[4] ^ v[8], 24);
                    v[0] <= v[0] + v[4] + msg[t];
                    v[12] <= rotr64(v[12] ^ v[0], 16);
                    v[8] <= v[8] + v[12];
                    v[4] <= rotr64(v[4] ^ v[8], 63);
                end
                round <= round + 1;
            end else begin
                digest[0] <= v[0] ^ v[8];  digest[1] <= v[1] ^ v[9];
                digest[2] <= v[2] ^ v[10]; digest[3] <= v[3] ^ v[11];
                digest[4] <= v[4] ^ v[12]; digest[5] <= v[5] ^ v[13];
                digest[6] <= v[6] ^ v[14]; digest[7] <= v[7] ^ v[15];
                busy <= 0;
            end
        end
    end

endmodule
