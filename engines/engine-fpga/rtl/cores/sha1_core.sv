// SHA-1 pipelined core — 80-cycle latency
// Implements FIPS 180-4 SHA-1 hash function
module sha1_core (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        start,
    input  logic [31:0] w [0:15],  // message block (512 bits)
    output logic [31:0] digest [0:4],
    output logic        ready
);

    logic [31:0] h [0:4];
    logic [31:0] a, b, c, d, e;
    logic [31:0] w_ext [0:79];
    logic [5:0]  round;
    logic        busy;

    assign ready = ~busy;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy <= 1'b0;
            round <= '0;
        end else if (start && !busy) begin
            busy <= 1'b1;
            round <= '0;
            h[0] <= 32'h67452301;
            h[1] <= 32'hEFCDAB89;
            h[2] <= 32'h98BADCFE;
            h[3] <= 32'h10325476;
            h[4] <= 32'hC3D2E1F0;
            for (int i = 0; i < 16; i++) begin
                w_ext[i] <= w[i];
            end
            for (int i = 16; i < 80; i++) begin
                w_ext[i] <= {w_ext[i-3][30:0], w_ext[i-3][31]} ^
                            {w_ext[i-8][30:0], w_ext[i-8][31]} ^
                            {w_ext[i-14][30:0], w_ext[i-14][31]} ^
                            {w_ext[i-16][30:0], w_ext[i-16][31]};
            end
        end else if (busy) begin
            if (round == 0) begin
                a <= h[0]; b <= h[1]; c <= h[2]; d <= h[3]; e <= h[4];
            end
            if (round < 80) begin
                logic [31:0] f, k, temp;
                if (round < 20) begin
                    f <= (b & c) | (~b & d);
                    k <= 32'h5A827999;
                end else if (round < 40) begin
                    f <= b ^ c ^ d;
                    k <= 32'h6ED9EBA1;
                end else if (round < 60) begin
                    f <= (b & c) | (b & d) | (c & d);
                    k <= 32'h8F1BBCDC;
                end else begin
                    f <= b ^ c ^ d;
                    k <= 32'hCA62C1D6;
                end
                temp <= ({a[26:0], a[31:27]}) + f + e + k + w_ext[round];
                e <= d;
                d <= c;
                c <= {b[1:0], b[31:2]};
                b <= a;
                a <= temp;
                round <= round + 1;
            end else begin
                h[0] <= h[0] + a;
                h[1] <= h[1] + b;
                h[2] <= h[2] + c;
                h[3] <= h[3] + d;
                h[4] <= h[4] + e;
                busy <= 1'b0;
            end
        end
    end

    assign digest = h;

endmodule
