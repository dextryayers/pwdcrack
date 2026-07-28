// ============================================================
// RIPEMD-128 Core — 64-step dual-line processing
// 16-word message block
// ============================================================

module ripemd128_core (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        start,
    input  logic [31:0] msg [15:0],
    output logic [31:0] digest [3:0],
    output logic        ready
);

    logic [31:0] h [3:0];
    logic [31:0] a, b, c, d, aa, bb, cc, dd;
    logic [31:0] K [4:0], Kp [4:0];
    logic [3:0]  r_sel [64];
    logic [3:0]  rp_sel [64];
    logic [4:0]  rot [64], rotp [64];
    logic        busy;
    logic [6:0]  step;

    assign ready = ~busy;

    always_comb begin
        K[0] = 32'h00000000; K[1] = 32'h5a827999; K[2] = 32'h6ed9eba1;
        K[3] = 32'h8f1bbcdc; K[4] = 32'ha953fd4e;
        Kp[0] = 32'h50a28be6; Kp[1] = 32'h5c4dd124; Kp[2] = 32'h6d703ef3;
        Kp[3] = 32'h7a6d76e9; Kp[4] = 32'h00000000;

        // Round selectors
        for (int i = 0; i < 16; i++) begin
            r_sel[i] = i; rp_sel[i] = 4'(4'd7 + 4'(i * 4'd3)) % 4'd16;
            rot[i] = 5'd11; rot[i+16] = 5'd14; rot[i+32] = 5'd15; rot[i+48] = 5'd12;
            rotp[i] = 5'd14; rotp[i+16] = 5'd11; rotp[i+32] = 5'd13; rotp[i+48] = 5'd15;
        end
        for (int i = 16; i < 32; i++) begin
            r_sel[i] = 4'((4'd7 * i) % 4'd16);
            rp_sel[i] = 4'(4'd7 + (4'd3 * (i % 4'd16))) % 4'd16;
        end
        for (int i = 32; i < 48; i++) begin
            r_sel[i] = 4'((4'd3 * i + 4'd5) % 4'd16);
            rp_sel[i] = 4'((4'd7 * i) % 4'd16);
        end
        for (int i = 48; i < 64; i++) begin
            r_sel[i] = 4'((4'd7 * i) % 4'd16);
            rp_sel[i] = 4'((4'd3 * i + 4'd5) % 4'd16);
        end
    end

    function automatic logic [31:0] f1(input logic [31:0] x, y, z);
        return x ^ y ^ z;
    endfunction
    function automatic logic [31:0] f2(input logic [31:0] x, y, z);
        return (x & y) | (~x & z);
    endfunction
    function automatic logic [31:0] f3(input logic [31:0] x, y, z);
        return (x | ~y) ^ z;
    endfunction
    function automatic logic [31:0] f4(input logic [31:0] x, y, z);
        return (x & z) | (y & ~z);
    endfunction
    function automatic logic [31:0] fp1(input logic [31:0] x, y, z);
        return x ^ y ^ z;
    endfunction
    function automatic logic [31:0] fp2(input logic [31:0] x, y, z);
        return (x & y) | (~x & z);
    endfunction
    function automatic logic [31:0] fp3(input logic [31:0] x, y, z);
        return (x | ~y) ^ z;
    endfunction
    function automatic logic [31:0] fp4(input logic [31:0] x, y, z);
        return (x & z) | (y & ~z);
    endfunction

    function automatic logic [31:0] rol(input logic [31:0] x, input [4:0] n);
        return {x[31-n:0], x[31:32-n]};
    endfunction

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy <= 0; step <= 0;
        end else if (start && !busy) begin
            h[0] <= 32'h67452301; h[1] <= 32'hefcdab89;
            h[2] <= 32'h98badcfe; h[3] <= 32'h10325476;
            a <= 32'h67452301; b <= 32'hefcdab89;
            c <= 32'h98badcfe; d <= 32'h10325476;
            aa <= 32'h67452301; bb <= 32'hefcdab89;
            cc <= 32'h98badcfe; dd <= 32'h10325476;
            busy <= 1; step <= 0;
        end else if (busy) begin
            if (step < 64) begin
                logic [31:0] f, fp, t, tp;
                case (step[6:5])
                    0: begin f = f1(b,c,d); fp = fp4(bb,cc,dd); end
                    1: begin f = f2(b,c,d); fp = fp3(bb,cc,dd); end
                    2: begin f = f3(b,c,d); fp = fp2(bb,cc,dd); end
                    3: begin f = f4(b,c,d); fp = fp1(bb,cc,dd); end
                endcase

                t = a + f + msg[r_sel[step]] + K[step[6:5]];
                tp = aa + fp + msg[rp_sel[step]] + Kp[step[6:5]];
                t = rol(t, rot[step]); tp = rol(tp, rotp[step]);

                a <= d; d <= c; c <= b; b <= t;
                aa <= dd; dd <= cc; cc <= bb; bb <= tp;
                step <= step + 1;
            end else begin
                h[0] <= h[0] + b + cc; h[1] <= h[1] + c + dd;
                h[2] <= h[2] + d + aa; h[3] <= h[3] + a + bb;
                busy <= 0;
            end
        end
    end

    assign digest = h;

endmodule
