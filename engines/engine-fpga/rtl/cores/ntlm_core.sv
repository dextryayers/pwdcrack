// ============================================================
// NTLM Pipelined Core — MD4 hash only
// Input: UTF16-LE pre-encoded bytes (password encoded by host)
// NTLM = MD4(UTF16-LE(password)), host sends already-encoded bytes
// Fully pipelined: 1 hash/cycle, 49-cycle latency
// ============================================================
//
// Usage:
//   Host must UTF16-LE encode the password before sending.
//   Example: password "abc" → {0x61,0x00,0x62,0x00,0x63,0x00}
//   msg_len = password_length × 2
//   msg_bytes contains the MD4 message block ready for hashing
//   (including MD4 padding applied by host)
//
// For passwords ≤ 55 ASCII chars (110 UTF16-LE bytes):
//   msg_len = 110, msg_bytes has UTF16-LE data + MD4 padding + length
//   h_in values are MD4 IV (if single-block) or chaining (if multi-block)

module ntlm_core (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        valid,
    output logic        ready,
    input  logic [31:0] msg_word [15:0],  // 16 × 32-bit MD4 message block
    input  logic [31:0] h_in     [3:0],   // MD4 IV (0x67452301, ...)
    output logic [31:0] h_out    [3:0],   // MD4 digest
    output logic        done
);

    // MD4 round constants
    // Round 1: K = 0x00000000 (no constant added)
    // Round 2: K = 0x5a827999 (floor(2^32 × sqrt(2)))
    // Round 3: K = 0x6ed9eba1 (floor(2^32 × sqrt(3)))
    logic [31:0] K [0:2];
    always_comb begin
        K[0] = 32'h00000000;
        K[1] = 32'h5a827999;
        K[2] = 32'h6ed9eba1;
    end

    // Shift amounts per round (RFC 1320)
    function automatic [4:0] s(input [5:0] r);
        case ({r[5:4], r[1:0]})
            6'b00_00: return 5'd3;
            6'b00_01: return 5'd7;
            6'b00_10: return 5'd11;
            6'b00_11: return 5'd19;
            6'b01_00: return 5'd3;
            6'b01_01: return 5'd5;
            6'b01_10: return 5'd9;
            6'b01_11: return 5'd13;
            6'b10_00: return 5'd3;
            6'b10_01: return 5'd9;
            6'b10_10: return 5'd11;
            6'b10_11: return 5'd15;
            default:  return 5'd3;
        endcase
    endfunction

    // g index per round — selects which message word to use
    // Per RFC 1320 MD4 specification:
    // Round 1 (r=0..15):  k = i
    // Round 2 (r=16..31): k = [0,4,8,12,1,5,9,13,2,6,10,14,3,7,11,15]
    // Round 3 (r=32..47): k = [0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15]
    function automatic [3:0] g(input [5:0] r);
        case (r[5:4])
            0: return r[3:0];
            1: return (r[1:0] * 4 + r[3:2]);  // k = (i%4)*4 + i/4
            2: begin
                unique case (r[3:0])
                    4'd0:  return 4'd0;
                    4'd1:  return 4'd8;
                    4'd2:  return 4'd4;
                    4'd3:  return 4'd12;
                    4'd4:  return 4'd2;
                    4'd5:  return 4'd10;
                    4'd6:  return 4'd6;
                    4'd7:  return 4'd14;
                    4'd8:  return 4'd1;
                    4'd9:  return 4'd9;
                    4'd10: return 4'd5;
                    4'd11: return 4'd13;
                    4'd12: return 4'd3;
                    4'd13: return 4'd11;
                    4'd14: return 4'd7;
                    4'd15: return 4'd15;
                endcase
            end
        endcase
    endfunction

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
            a_pipe[0] <= h_in[0];
            b_pipe[0] <= h_in[1];
            c_pipe[0] <= h_in[2];
            d_pipe[0] <= h_in[3];
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

                temp = a_pipe[r] + f + msg_word[g_idx] + K[r[5:4]];
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

            // Stage 48: final addition with original IV
            a_pipe[48] <= a_pipe[47] + h_in[0];
            b_pipe[48] <= b_pipe[47] + h_in[1];
            c_pipe[48] <= c_pipe[47] + h_in[2];
            d_pipe[48] <= d_pipe[47] + h_in[3];
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
