// ============================================================
// RIPEMD-160 Core — dual-line 80-step processing
// 16-word message block, 160-bit digest
// ============================================================

module ripemd160_core (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        start,
    input  logic [31:0] msg [15:0],
    output logic [31:0] digest [4:0],
    output logic        ready
);

    logic [31:0] h [4:0];
    logic [31:0] a, b, c, d, e, aa, bb, cc, dd, ee;
    logic        busy;
    logic [6:0]  step;

    assign ready = ~busy;

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
    function automatic logic [31:0] f5(input logic [31:0] x, y, z);
        return x ^ (y | ~z);
    endfunction

    function automatic logic [31:0] rol(input logic [31:0] x, input [4:0] n);
        return {x[31-n:0], x[31:32-n]};
    endfunction

    // Round selectors
    function automatic logic [3:0] r_sel(input [6:0] s);
        case (s[6:5])
            0: return s[3:0];
            1: return (4'd7 * s[3:0] + 4'd3) % 4'd16;
            2: return (4'd3 * s[3:0] + 4'd5) % 4'd16;
            3: return (4'd7 * s[3:0]) % 4'd16;
        endcase
    endfunction

    function automatic logic [3:0] rp_sel(input [6:0] s);
        case (s[6:5])
            0: return (4'd2 * s[3:0] + 4'd7) % 4'd16;
            1: return (4'd7 * s[3:0] + 4'd2) % 4'd16;
            2: return (4'd3 * s[3:0] + 4'd7) % 4'd16;
            3: return (4'd7 * s[3:0]) % 4'd16;
        endcase
    endfunction

    logic [4:0] rshift [80], rpshift [80];

    always_comb begin
        rshift[0]=11; rshift[1]=14; rshift[2]=15; rshift[3]=12; rshift[4]=5; rshift[5]=8;
        rshift[6]=7; rshift[7]=9; rshift[8]=11; rshift[9]=13; rshift[10]=14; rshift[11]=15;
        rshift[12]=6; rshift[13]=7; rshift[14]=9; rshift[15]=8; rshift[16]=7; rshift[17]=6;
        rshift[18]=8; rshift[19]=13; rshift[20]=11; rshift[21]=9; rshift[22]=7; rshift[23]=15;
        rshift[24]=7; rshift[25]=12; rshift[26]=15; rshift[27]=9; rshift[28]=11; rshift[29]=7;
        rshift[30]=13; rshift[31]=12; rshift[32]=11; rshift[33]=13; rshift[34]=6; rshift[35]=7;
        rshift[36]=14; rshift[37]=9; rshift[38]=13; rshift[39]=15; rshift[40]=14; rshift[41]=8;
        rshift[42]=13; rshift[43]=6; rshift[44]=5; rshift[45]=12; rshift[46]=7; rshift[47]=5;
        rshift[48]=11; rshift[49]=12; rshift[50]=14; rshift[51]=15; rshift[52]=14; rshift[53]=15;
        rshift[54]=9; rshift[55]=8; rshift[56]=9; rshift[57]=14; rshift[58]=5; rshift[59]=6;
        rshift[60]=8; rshift[61]=6; rshift[62]=5; rshift[63]=12; rshift[64]=9; rshift[65]=15;
        rshift[66]=5; rshift[67]=11; rshift[68]=6; rshift[69]=8; rshift[70]=13; rshift[71]=12;
        rshift[72]=5; rshift[73]=12; rshift[74]=13; rshift[75]=14; rshift[76]=11; rshift[77]=8;
        rshift[78]=5; rshift[79]=6;

        for (int i = 0; i < 80; i++)
            rpshift[i] = rshift[79-i];
    end

    logic [31:0] K [4:0], Kp [4:0];
    always_comb begin
        K[0] = 32'h00000000; K[1] = 32'h5a827999; K[2] = 32'h6ed9eba1;
        K[3] = 32'h8f1bbcdc; K[4] = 32'ha953fd4e;
        Kp[0] = 32'h50a28be6; Kp[1] = 32'h5c4dd124; Kp[2] = 32'h6d703ef3;
        Kp[3] = 32'h7a6d76e9; Kp[4] = 32'h00000000;
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy <= 0; step <= 0;
        end else if (start && !busy) begin
            h[0] <= 32'h67452301; h[1] <= 32'hefcdab89;
            h[2] <= 32'h98badcfe; h[3] <= 32'h10325476; h[4] <= 32'hc3d2e1f0;
            a <= 32'h67452301; b <= 32'hefcdab89; c <= 32'h98badcfe;
            d <= 32'h10325476; e <= 32'hc3d2e1f0;
            aa <= 32'h67452301; bb <= 32'hefcdab89; cc <= 32'h98badcfe;
            dd <= 32'h10325476; ee <= 32'hc3d2e1f0;
            busy <= 1; step <= 0;
        end else if (busy) begin
            if (step < 80) begin
                logic [31:0] f, fp, t, tp;
                case (step[6:5])
                    0: begin f = f1(b,c,d); fp = fp5(bb,cc,dd); end
                    1: begin f = f2(b,c,d); fp = fp4(bb,cc,dd); end
                    2: begin f = f3(b,c,d); fp = fp3(bb,cc,dd); end
                    3: begin f = f4(b,c,d); fp = fp2(bb,cc,dd); end
                    4: begin f = f5(b,c,d); fp = fp1(bb,cc,dd); end
                endcase

                t = rol(a + f + msg[r_sel(step)] + K[step[6:5]], rshift[step]) + e;
                tp = rol(aa + fp + msg[rp_sel(step)] + Kp[step[6:5]], rpshift[step]) + ee;

                a <= e; e <= d; d <= c; c <= b; b <= t;
                aa <= ee; ee <= dd; dd <= cc; cc <= bb; bb <= tp;
                step <= step + 1;
            end else begin
                h[0] <= h[0] + b + cc; h[1] <= h[1] + c + dd;
                h[2] <= h[2] + d + ee; h[3] <= h[3] + e + aa;
                h[4] <= h[4] + a + bb;
                busy <= 0;
            end
        end
    end

    assign digest = h;

endmodule
