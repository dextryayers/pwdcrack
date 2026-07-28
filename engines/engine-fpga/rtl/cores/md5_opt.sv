// ============================================================
// MD5 Optimized Core — 64-step fully unrolled, pipelined
// Same interface as md5_core but with 81-cycle latency
// for full message expansion (same as sha1_opt pattern)
// ============================================================

module md5_opt (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        valid,
    output logic        ready,
    input  logic [31:0] msg_word [15:0],
    input  logic [31:0] h_in      [3:0],
    output logic [31:0] h_out     [3:0],
    output logic        done
);

    logic [31:0] K [0:63];
    always_comb begin
        K[ 0] = 32'hd76aa478; K[ 1] = 32'he8c7b756; K[ 2] = 32'h242070db; K[ 3] = 32'hc1bdceee;
        K[ 4] = 32'hf57c0faf; K[ 5] = 32'h4787c62a; K[ 6] = 32'ha8304613; K[ 7] = 32'hfd469501;
        K[ 8] = 32'h698098d8; K[ 9] = 32'h8b44f7af; K[10] = 32'hffff5bb1; K[11] = 32'h895cd7be;
        K[12] = 32'h6b901122; K[13] = 32'hfd987193; K[14] = 32'ha679438e; K[15] = 32'h49b40821;
        K[16] = 32'hf61e2562; K[17] = 32'hc040b340; K[18] = 32'h265e5a51; K[19] = 32'he9b6c7aa;
        K[20] = 32'hd62f105d; K[21] = 32'h02441453; K[22] = 32'hd8a1e681; K[23] = 32'he7d3fbc8;
        K[24] = 32'h21e1cde6; K[25] = 32'hc33707d6; K[26] = 32'hf4d50d87; K[27] = 32'h455a14ed;
        K[28] = 32'ha9e3e905; K[29] = 32'hfcefa3f8; K[30] = 32'h676f02d9; K[31] = 32'h8d2a4c8a;
        K[32] = 32'hfffa3942; K[33] = 32'h8771f681; K[34] = 32'h6d9d6122; K[35] = 32'hfde5380c;
        K[36] = 32'ha4beea44; K[37] = 32'h4bdecfa9; K[38] = 32'hf6bb4b60; K[39] = 32'hbebfbc70;
        K[40] = 32'h289b7ec6; K[41] = 32'heaa127fa; K[42] = 32'hd4ef3085; K[43] = 32'h04881d05;
        K[44] = 32'hd9d4d039; K[45] = 32'he6db99e5; K[46] = 32'h1fa27cf8; K[47] = 32'hc4ac5665;
        K[48] = 32'hf4292244; K[49] = 32'h432aff97; K[50] = 32'hab9423a7; K[51] = 32'hfc93a039;
        K[52] = 32'h655b59c3; K[53] = 32'h8f0ccc92; K[54] = 32'hffeff47d; K[55] = 32'h85845dd1;
        K[56] = 32'h6fa87e4f; K[57] = 32'hfe2ce6e0; K[58] = 32'ha3014314; K[59] = 32'h4e0811a1;
        K[60] = 32'hf7537e82; K[61] = 32'hbd3af235; K[62] = 32'h2ad7d2bb; K[63] = 32'heb86d391;
    end

    function automatic logic [4:0] shift(input [5:0] r);
        case ({r[5:4], r[1:0]})
            6'b00_00: return 5'd7;  6'b00_01: return 5'd12;
            6'b00_10: return 5'd17; 6'b00_11: return 5'd22;
            6'b01_00: return 5'd5;  6'b01_01: return 5'd9;
            6'b01_10: return 5'd14; 6'b01_11: return 5'd20;
            6'b10_00: return 5'd4;  6'b10_01: return 5'd11;
            6'b10_10: return 5'd16; 6'b10_11: return 5'd23;
            6'b11_00: return 5'd6;  6'b11_01: return 5'd10;
            6'b11_10: return 5'd15; 6'b11_11: return 5'd21;
            default:  return 5'd7;
        endcase
    endfunction

    function automatic logic [3:0] g_idx(input [5:0] r);
        case (r[5:4])
            0: return r[3:0];
            1: return (5 * r[3:0] + 1) % 16;
            2: return (3 * r[3:0] + 5) % 16;
            3: return (7 * r[3:0]) % 16;
        endcase
    endfunction

    logic [31:0] a_pipe [65:0];
    logic [31:0] b_pipe [65:0];
    logic [31:0] c_pipe [65:0];
    logic [31:0] d_pipe [65:0];
    logic        valid_pipe [65:0];

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < 66; i++) begin
                a_pipe[i] <= '0; b_pipe[i] <= '0;
                c_pipe[i] <= '0; d_pipe[i] <= '0;
                valid_pipe[i] <= '0;
            end
        end else begin
            a_pipe[0] <= h_in[0]; b_pipe[0] <= h_in[1];
            c_pipe[0] <= h_in[2]; d_pipe[0] <= h_in[3];
            valid_pipe[0] <= valid;

            for (int r = 0; r < 64; r++) begin
                logic [31:0] f, temp;
                logic [3:0] g;
                g = g_idx(r[5:0]);

                case (r[5:4])
                    0: f = (b_pipe[r] & c_pipe[r]) | (~b_pipe[r] & d_pipe[r]);
                    1: f = (d_pipe[r] & b_pipe[r]) | (~d_pipe[r] & c_pipe[r]);
                    2: f = b_pipe[r] ^ c_pipe[r] ^ d_pipe[r];
                    3: f = c_pipe[r] ^ (b_pipe[r] | ~d_pipe[r]);
                endcase

                temp = a_pipe[r] + f + msg_word[g] + K[r];
                temp = {temp << shift(r[5:0]), temp >> (32 - shift(r[5:0]))};
                temp = temp + b_pipe[r];

                a_pipe[r+1] <= d_pipe[r];
                b_pipe[r+1] <= temp;
                c_pipe[r+1] <= b_pipe[r];
                d_pipe[r+1] <= c_pipe[r];
                valid_pipe[r+1] <= valid_pipe[r];
            end

            a_pipe[64] <= a_pipe[63] + h_in[0];
            b_pipe[64] <= b_pipe[63] + h_in[1];
            c_pipe[64] <= c_pipe[63] + h_in[2];
            d_pipe[64] <= d_pipe[63] + h_in[3];
            valid_pipe[64] <= valid_pipe[63];
        end
    end

    assign h_out[0] = a_pipe[64]; assign h_out[1] = b_pipe[64];
    assign h_out[2] = c_pipe[64]; assign h_out[3] = d_pipe[64];
    assign done = valid_pipe[64];
    assign ready = 1'b1;

endmodule
