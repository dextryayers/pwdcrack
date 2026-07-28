// ============================================================
// PBKDF2-HMAC-SHA256 Core
// Configurable iteration count
// Implements FIPS 198 HMAC + PKCS#5 v2.1
// ============================================================

module pbkdf2_core #(
    parameter int ITERATIONS = 1000
) (
    input  logic         clk,
    input  logic         rst_n,
    input  logic         start,
    input  logic [511:0] password,
    input  logic [511:0] salt,
    input  logic [31:0]  pass_len,
    input  logic [31:0]  salt_len,
    output logic [255:0] dk,
    output logic         ready
);

    typedef enum logic [3:0] { IDLE, HMAC_INNER1, HMAC_INNER2, HMAC_OUTER1,
                               HMAC_OUTER2, XOR_RESULT, ITER_LOOP, DONE } state_t;
    state_t state;

    // SHA-256 core instantiation
    logic        sha_valid, sha_ready, sha_done;
    logic [31:0] sha_msg [15:0];
    logic [31:0] sha_h_in [7:0], sha_h_out [7:0];

    sha256_core sha_inst (.*);

    logic [255:0] U, T, ipad_hash, opad_hash;
    logic [31:0]  iter_cnt;
    logic [511:0] ipad_key, opad_key;

    always_comb begin
        for (int i = 0; i < 64; i++) begin
            ipad_key[i*8+:8] = (i < pass_len) ? password[i*8+:8] ^ 8'h36 : 8'h36;
            opad_key[i*8+:8] = (i < pass_len) ? password[i*8+:8] ^ 8'h5c : 8'h5c;
        end
    end

    logic [31:0] sha_iv [7:0];
    assign sha_iv[0] = 32'h6a09e667; sha_iv[1] = 32'hbb67ae85;
    assign sha_iv[2] = 32'h3c6ef372; sha_iv[3] = 32'ha54ff53a;
    assign sha_iv[4] = 32'h510e527f; sha_iv[5] = 32'h9b05688c;
    assign sha_iv[6] = 32'h1f83d9ab; sha_iv[7] = 32'h5be0cd19;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
            sha_valid <= 0;
            iter_cnt <= '0;
            T <= '0;
            U <= '0;
        end else case (state)
            IDLE: if (start) begin
                state <= HMAC_INNER1;
                iter_cnt <= 0;
                T <= '0;
            end

            HMAC_INNER1: begin
                sha_h_in <= sha_iv;
                for (int i = 0; i < 8; i++) sha_msg[i] <= ipad_key[255-i*32-:32];
                for (int i = 0; i < 8; i++) sha_msg[i+8] <= salt[255-i*32-:32];
                sha_valid <= 1;
                state <= HMAC_INNER2;
            end
            HMAC_INNER2: begin
                sha_valid <= 0;
                if (sha_done) begin
                    for (int i = 0; i < 8; i++) ipad_hash[i*32+:32] <= sha_h_out[i];
                    state <= HMAC_OUTER1;
                end
            end

            HMAC_OUTER1: begin
                sha_h_in <= sha_iv;
                for (int i = 0; i < 8; i++) sha_msg[i] <= opad_key[255-i*32-:32];
                for (int i = 0; i < 8; i++) sha_msg[i+8] <= ipad_hash[255-i*32-:32];
                sha_valid <= 1;
                state <= HMAC_OUTER2;
            end
            HMAC_OUTER2: begin
                sha_valid <= 0;
                if (sha_done) begin
                    U <= {sha_h_out[0], sha_h_out[1], sha_h_out[2], sha_h_out[3],
                          sha_h_out[4], sha_h_out[5], sha_h_out[6], sha_h_out[7]};
                    state <= XOR_RESULT;
                end
            end

            XOR_RESULT: begin
                T <= T ^ U;
                if (iter_cnt == ITERATIONS - 1) state <= DONE;
                else begin
                    iter_cnt <= iter_cnt + 1;
                    state <= HMAC_INNER1;
                end
            end

            DONE: state <= IDLE;
        endcase
    end

    assign dk = T;
    assign ready = (state == IDLE);

endmodule
