// ============================================================
// SHA-1 Optimized Core — full 80-step unrolled pipeline
// Pre-computed K constants, valid/ready handshake
// ============================================================

module sha1_opt (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        valid,
    output logic        ready,
    input  logic [31:0] msg_word [15:0],
    input  logic [31:0] h_in      [4:0],
    output logic [31:0] h_out     [4:0],
    output logic        done
);

    logic [31:0] a_pipe [81:0];
    logic [31:0] b_pipe [81:0];
    logic [31:0] c_pipe [81:0];
    logic [31:0] d_pipe [81:0];
    logic [31:0] e_pipe [81:0];
    logic        valid_pipe [81:0];

    logic [31:0] W_pipe [81:0][15:0];

    logic [31:0] K [3:0];
    always_comb begin
        K[0] = 32'h5A827999; K[1] = 32'h6ED9EBA1;
        K[2] = 32'h8F1BBCDC; K[3] = 32'hCA62C1D6;
    end

    always_comb begin
        for (int i = 0; i < 16; i++) W_pipe[0][i] = msg_word[i];
    end

    function automatic logic [31:0] f_round(input logic [31:0] b, c, d, input [1:0] sel);
        case (sel)
            0: return (b & c) | (~b & d);
            1: return b ^ c ^ d;
            2: return (b & c) | (b & d) | (c & d);
            3: return b ^ c ^ d;
        endcase
    endfunction

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < 82; i++) begin
                a_pipe[i] <= '0; b_pipe[i] <= '0; c_pipe[i] <= '0;
                d_pipe[i] <= '0; e_pipe[i] <= '0; valid_pipe[i] <= '0;
                for (int j = 0; j < 16; j++) W_pipe[i][j] <= '0;
            end
        end else begin
            a_pipe[0] <= h_in[0]; b_pipe[0] <= h_in[1]; c_pipe[0] <= h_in[2];
            d_pipe[0] <= h_in[3]; e_pipe[0] <= h_in[4];
            valid_pipe[0] <= valid;

            for (int r = 0; r < 80; r++) begin
                logic [31:0] w;
                if (r < 16)
                    w = W_pipe[r][r];
                else begin
                    w = {W_pipe[r][13][30:0], W_pipe[r][13][31]} ^
                        {W_pipe[r][8][30:0],  W_pipe[r][8][31]} ^
                        {W_pipe[r][2][30:0],  W_pipe[r][2][31]} ^
                        {W_pipe[r][15][30:0], W_pipe[r][15][31]};
                    w = {w[30:0], w[31]};
                    if (r >= 16) begin
                        for (int i = 0; i < 15; i++)
                            W_pipe[r+1][i] <= W_pipe[r][i+1];
                        W_pipe[r+1][15] <= w;
                    end
                end

                if (r < 16) begin
                    for (int i = 0; i < 16; i++)
                        W_pipe[r+1][i] <= W_pipe[r][i];
                end

                logic [31:0] f, temp;
                f = f_round(b_pipe[r], c_pipe[r], d_pipe[r], r[7:6]);
                temp = ({a_pipe[r][26:0], a_pipe[r][31:27]}) + f + e_pipe[r] + K[r[7:6]] + w;

                a_pipe[r+1] <= temp;
                b_pipe[r+1] <= a_pipe[r];
                c_pipe[r+1] <= {b_pipe[r][1:0], b_pipe[r][31:2]};
                d_pipe[r+1] <= c_pipe[r];
                e_pipe[r+1] <= d_pipe[r];
                valid_pipe[r+1] <= valid_pipe[r];
            end

            a_pipe[80] <= a_pipe[79] + h_in[0];
            b_pipe[80] <= b_pipe[79] + h_in[1];
            c_pipe[80] <= c_pipe[79] + h_in[2];
            d_pipe[80] <= d_pipe[79] + h_in[3];
            e_pipe[80] <= e_pipe[79] + h_in[4];
            valid_pipe[80] <= valid_pipe[79];
        end
    end

    assign h_out[0] = a_pipe[80]; assign h_out[1] = b_pipe[80];
    assign h_out[2] = c_pipe[80]; assign h_out[3] = d_pipe[80];
    assign h_out[4] = e_pipe[80];
    assign done = valid_pipe[80];
    assign ready = 1'b1;

endmodule
