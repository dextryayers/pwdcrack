// SHA-512 pipelined core — 80-cycle latency, 1024-bit block
module sha512_core (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        start,
    input  logic [63:0] w [0:15],
    output logic [63:0] digest [0:7],
    output logic        ready
);

    logic [63:0] h [0:7];
    logic [63:0] a, b, c, d, e, f, g, hh;
    logic [63:0] w_ext [0:79];
    logic [6:0]  round;
    logic        busy;

    assign ready = ~busy;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy <= 1'b0;
            round <= '0;
        end else if (start && !busy) begin
            busy <= 1'b1;
            round <= '0;
            h[0] <= 64'h6a09e667f3bcc908; h[1] <= 64'hbb67ae8584caa73b;
            h[2] <= 64'h3c6ef372fe94f82b; h[3] <= 64'ha54ff53a5f1d36f1;
            h[4] <= 64'h510e527fade682d1; h[5] <= 64'h9b05688c2b3e6c1f;
            h[6] <= 64'h1f83d9abfb41bd6b; h[7] <= 64'h5be0cd19137e2179;
            for (int i = 0; i < 16; i++) w_ext[i] <= w[i];
            for (int i = 16; i < 80; i++) begin
                logic [63:0] s0, s1;
                s0 = ({w_ext[i-15][0:0], w_ext[i-15][63:1]} ^
                      {w_ext[i-15][7:0], w_ext[i-15][63:8]} ^
                      {w_ext[i-15][63:7], w_ext[i-15][62:0]});
                s1 = ({w_ext[i-2][18:0], w_ext[i-2][63:19]} ^
                      {w_ext[i-2][60:0], w_ext[i-2][63:61]} ^
                      {w_ext[i-2][63:10], w_ext[i-2][9:0]});
                w_ext[i] <= w_ext[i-16] + s0 + w_ext[i-7] + s1;
            end
        end else if (busy) begin
            if (round == 0) begin
                a <= h[0]; b <= h[1]; c <= h[2]; d <= h[3];
                e <= h[4]; f <= h[5]; g <= h[6]; hh <= h[7];
            end
            if (round < 80) begin
                logic [63:0] S1, ch, temp1, S0, maj, temp2;
                S1 = ({e[13:0], e[63:14]} ^ {e[17:0], e[63:18]} ^ {e[40:0], e[63:41]});
                ch = (e & f) ^ (~e & g);
                temp1 = hh + S1 + ch + w_ext[round];
                S0 = ({a[27:0], a[63:28]} ^ {a[33:0], a[63:34]} ^ {a[38:0], a[63:39]});
                maj = (a & b) ^ (a & c) ^ (b & c);
                temp2 = S0 + maj;
                hh <= g; g <= f; f <= e; e <= d + temp1;
                d <= c; c <= b; b <= a; a <= temp1 + temp2;
                round <= round + 1;
            end else begin
                h[0] <= h[0] + a; h[1] <= h[1] + b;
                h[2] <= h[2] + c; h[3] <= h[3] + d;
                h[4] <= h[4] + e; h[5] <= h[5] + f;
                h[6] <= h[6] + g; h[7] <= h[7] + hh;
                busy <= 1'b0;
            end
        end
    end

    assign digest = h;

endmodule
