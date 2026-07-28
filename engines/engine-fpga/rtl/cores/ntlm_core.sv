// ============================================================
// NTLM Core — ASCII to UTF16-LE converter + MD4 hash
// NTLMv1 = MD4(UTF16-LE(password))
// Fully pipelined: 49-cycle latency
// ============================================================

module ntlm_core (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        valid,
    output logic        ready,
    input  logic [7:0]  ascii_in  [55:0],
    input  logic [5:0]  pass_len,
    output logic [31:0] digest [3:0],
    output logic        done
);

    // UTF16-LE conversion + padding
    logic [31:0] msg_word [15:0];
    logic [31:0] h_in [3:0];
    logic        md4_valid, md4_done, md4_ready;
    logic [31:0] md4_h_out [3:0];

    // MD4 IV
    logic [31:0] iv [3:0];
    assign iv[0] = 32'h67452301; assign iv[1] = 32'hefcdab89;
    assign iv[2] = 32'h98badcfe; assign iv[3] = 32'h10325476;

    // Build UTF16-LE block from ASCII input
    always_comb begin
        for (int i = 0; i < 16; i++) begin
            logic [7:0] lo, hi;
            int byte_idx = i * 2;
            if (byte_idx < pass_len) lo = ascii_in[byte_idx]; else lo = 8'h80;
            if (byte_idx + 1 < pass_len) hi = ascii_in[byte_idx + 1]; else hi = 8'h00;
            msg_word[i] = {hi, lo};
        end
        // MD4 length encoding (bit count in bits)
        msg_word[14] = pass_len * 16;  // pass_len * 2 bytes * 8 bits
        msg_word[15] = 32'h00000000;
    end

    assign h_in = iv;

    // Instantiate MD4 core (reuse existing md5_core-inspired pattern with MD4 constants)
    // We use inline MD4 logic here
    logic [31:0] K [0:2];
    always_comb begin
        K[0] = 32'h00000000; K[1] = 32'h5a827999; K[2] = 32'h6ed9eba1;
    end

    function automatic logic [4:0] s_md4(input [5:0] r);
        case ({r[5:4], r[1:0]})
            6'b00_00: return 5'd3;  6'b00_01: return 5'd7;
            6'b00_10: return 5'd11; 6'b00_11: return 5'd19;
            6'b01_00: return 5'd3;  6'b01_01: return 5'd5;
            6'b01_10: return 5'd9;  6'b01_11: return 5'd13;
            6'b10_00: return 5'd3;  6'b10_01: return 5'd9;
            6'b10_10: return 5'd11; 6'b10_11: return 5'd15;
            default:  return 5'd3;
        endcase
    endfunction

    function automatic logic [3:0] g_md4(input [5:0] r);
        case (r[5:4])
            0: return r[3:0];
            1: return (r[1:0] * 4 + r[3:2]);
            2: begin
                unique case (r[3:0])
                    4'd0:  return 4'd0;  4'd1:  return 4'd8;
                    4'd2:  return 4'd4;  4'd3:  return 4'd12;
                    4'd4:  return 4'd2;  4'd5:  return 4'd10;
                    4'd6:  return 4'd6;  4'd7:  return 4'd14;
                    4'd8:  return 4'd1;  4'd9:  return 4'd9;
                    4'd10: return 4'd5;  4'd11: return 4'd13;
                    4'd12: return 4'd3;  4'd13: return 4'd11;
                    4'd14: return 4'd7;  4'd15: return 4'd15;
                endcase
            end
        endcase
    endfunction

    logic [31:0] a_pipe [49:0];
    logic [31:0] b_pipe [49:0];
    logic [31:0] c_pipe [49:0];
    logic [31:0] d_pipe [49:0];
    logic        valid_pipe [49:0];
    logic        start_md4;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < 50; i++) begin
                a_pipe[i] <= '0; b_pipe[i] <= '0;
                c_pipe[i] <= '0; d_pipe[i] <= '0;
                valid_pipe[i] <= '0;
            end
            start_md4 <= 0;
        end else begin
            start_md4 <= valid;

            if (start_md4) begin
                a_pipe[0] <= h_in[0]; b_pipe[0] <= h_in[1];
                c_pipe[0] <= h_in[2]; d_pipe[0] <= h_in[3];
                valid_pipe[0] <= 1;
            end else
                valid_pipe[0] <= 0;

            for (int r = 0; r < 48; r++) begin
                logic [31:0] f, temp;
                logic [3:0] g;
                g = g_md4(r[5:0]);

                case (r[5:4])
                    0: f = (b_pipe[r] & c_pipe[r]) | (~b_pipe[r] & d_pipe[r]);
                    1: f = (b_pipe[r] & c_pipe[r]) | (b_pipe[r] & d_pipe[r]) | (c_pipe[r] & d_pipe[r]);
                    2: f = b_pipe[r] ^ c_pipe[r] ^ d_pipe[r];
                endcase

                temp = a_pipe[r] + f + msg_word[g] + K[r[5:4]];
                case (s_md4(r[5:0]))
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

            a_pipe[48] <= a_pipe[47] + h_in[0];
            b_pipe[48] <= b_pipe[47] + h_in[1];
            c_pipe[48] <= c_pipe[47] + h_in[2];
            d_pipe[48] <= d_pipe[47] + h_in[3];
            valid_pipe[48] <= valid_pipe[47];
        end
    end

    assign digest[0] = a_pipe[48]; assign digest[1] = b_pipe[48];
    assign digest[2] = c_pipe[48]; assign digest[3] = d_pipe[48];
    assign done = valid_pipe[48];
    assign ready = 1'b1;

endmodule
