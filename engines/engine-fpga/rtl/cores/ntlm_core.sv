// ============================================================
// NTLM Pipelined Core — MD4 hash + UTF16-LE encoding
// Fully pipelined: 1 hash/cycle, 49-cycle latency
// ============================================================

module ntlm_core (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        valid,
    output logic        ready,
    input  logic [7:0]  msg_bytes [127:0],  // Up to 128-byte password
    input  logic [7:0]  msg_len,            // Password length in bytes
    output logic [31:0] h_out     [3:0],    // MD4 digest
    output logic        done
);

    // MD4 K constants per round
    function automatic [31:0] k(input [5:0] r);
        case (r[5:4])
            0: return 32'h00000000;
            1: return 32'h5a827999;
            2: return 32'h6ed9eba1;
        endcase
    endfunction

    // Shift amounts per round
    function automatic [4:0] s(input [5:0] r);
        case (r[5:4])
            0: return {1'b0, 5'd3 + r[1:0] * 5'd3};           // 3, 7, 11, 19
            1: return {1'b0, 5'd3 + r[1:0] * 5'd2};           // 3, 5, 9, 13
            2: return {1'b0, 5'd3 + r[1:0] * 5'd2};           // 3, 9, 11, 15
        endcase
    endfunction

    // g index per round (word selection)
    function automatic [3:0] g(input [5:0] r);
        case (r[5:4])
            0: return r[3:0];
            1: return (r[1:0] * 4 + r[3:2]) % 16;
            2: return (r[1:0] * 8 + r[3:2] * 2) % 16 + (r[3:2] == 0 ? 0 : 1);
        endcase
    endfunction

    // UTF16-LE encoded message words (16 x 32-bit)
    logic [31:0] msg_word [15:0];
    always_comb begin
        for (int i = 0; i < 16; i++) begin
            logic [7:0] b0, b1, b2, b3;
            int idx = i * 4;
            b0 = (idx < msg_len)    ? msg_bytes[idx]    : 8'h00;
            b1 = (idx+1 < msg_len)  ? msg_bytes[idx+1]  : 8'h00;
            b2 = (idx+2 < msg_len)  ? msg_bytes[idx+2]  : 8'h00;
            b3 = (idx+3 < msg_len)  ? msg_bytes[idx+3]  : 8'h00;
            msg_word[i] = {b3, b2, b1, b0};
        end
    end

    // Pipeline registers (49 stages: 48 rounds + 1 final addition)
    logic [31:0] a_pipe [49:0];
    logic [31:0] b_pipe [49:0];
    logic [31:0] c_pipe [49:0];
    logic [31:0] d_pipe [49:0];
    logic        valid_pipe [49:0];

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < 50; i++) begin
                a_pipe[i] <= '0; b_pipe[i] <= '0; c_pipe[i] <= '0; d_pipe[i] <= '0;
                valid_pipe[i] <= '0;
            end
        end else begin
            a_pipe[0] <= 32'h67452301;
            b_pipe[0] <= 32'hefcdab89;
            c_pipe[0] <= 32'h98badcfe;
            d_pipe[0] <= 32'h10325476;
            valid_pipe[0] <= valid;

            // Rounds 0-47 (3 rounds of 16)
            for (int r = 0; r < 48; r++) begin
                logic [31:0] f, temp;
                logic [3:0] g_idx;
                g_idx = g(r[5:0]);

                case (r[5:4])
                    0: f = (b_pipe[r] & c_pipe[r]) | (~b_pipe[r] & d_pipe[r]);
                    1: f = (b_pipe[r] & c_pipe[r]) | (b_pipe[r] & d_pipe[r]) | (c_pipe[r] & d_pipe[r]);
                    2: f = b_pipe[r] ^ c_pipe[r] ^ d_pipe[r];
                endcase

                temp = a_pipe[r] + f + msg_word[g_idx] + k(r[5:0]);
                case (s(r[5:0]))
                    5'd3:  temp = {temp[28:0], temp[31:29]};
                    5'd5:  temp = {temp[26:0], temp[31:27]};
                    5'd7:  temp = {temp[24:0], temp[31:25]};
                    5'd9:  temp = {temp[22:0], temp[31:23]};
                    5'd11: temp = {temp[20:0], temp[31:21]};
                    5'd13: temp = {temp[18:0], temp[31:19]};
                    5'd15: temp = {temp[16:0], temp[31:17]};
                    5'd19: temp = {temp[12:0], temp[31:13]};
                    default: temp = {temp[28:0], temp[31:29]};
                endcase

                a_pipe[r+1] <= d_pipe[r];
                b_pipe[r+1] <= temp;
                c_pipe[r+1] <= b_pipe[r];
                d_pipe[r+1] <= c_pipe[r];
                valid_pipe[r+1] <= valid_pipe[r];
            end

            // Stage 48: final addition
            a_pipe[48] <= a_pipe[47] + 32'h67452301;
            b_pipe[48] <= b_pipe[47] + 32'hefcdab89;
            c_pipe[48] <= c_pipe[47] + 32'h98badcfe;
            d_pipe[48] <= d_pipe[47] + 32'h10325476;
            valid_pipe[48] <= valid_pipe[47];
        end
    end

    assign h_out[0] = a_pipe[48];
    assign h_out[1] = b_pipe[48];
    assign h_out[2] = c_pipe[48];
    assign h_out[3] = d_pipe[48];
    assign done = valid_pipe[48];
    assign ready = 1'b1;

endmodule
