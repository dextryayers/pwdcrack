// ============================================================
// Parallel CRC Accelerator — 3-stage pipelined
// WIDTH: 32 (CRC-32) or 64 (CRC-64)
// POLY: configurable polynomial
// Processes 8 bytes (64 bits) per cycle
// ============================================================

module crc_accelerator #(
    parameter WIDTH = 32,
    parameter logic [WIDTH-1:0] POLY = (WIDTH == 32) ? 32'h04C11DB7 : 64'h000000000000001B
) (
    input  logic            clk,
    input  logic            rst_n,
    input  logic            valid,
    output logic            ready,
    input  logic [63:0]     data_in,
    output logic [WIDTH-1:0] crc_out,
    output logic            done
);

    localparam int STAGES = 3;

    logic [WIDTH-1:0] crc_pipe [STAGES:0];
    logic             valid_pipe [STAGES:0];

    function automatic logic [WIDTH-1:0] crc_comb(input logic [WIDTH-1:0] crc, input logic [63:0] data);
        logic [WIDTH-1:0] new_crc = crc;
        for (int i = 0; i < 64; i++) begin
            logic msb = new_crc[WIDTH-1] ^ data[63-i];
            new_crc = {new_crc[WIDTH-2:0], 1'b0};
            if (msb) new_crc = new_crc ^ POLY;
        end
        return new_crc;
    endfunction

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i <= STAGES; i++) begin
                crc_pipe[i] <= '0;
                valid_pipe[i] <= '0;
            end
        end else begin
            valid_pipe[0] <= valid;
            crc_pipe[0] <= crc_comb('1, data_in);

            for (int s = 1; s <= STAGES; s++) begin
                crc_pipe[s] <= crc_pipe[s-1];
                valid_pipe[s] <= valid_pipe[s-1];
            end
        end
    end

    assign crc_out = crc_pipe[STAGES] ^ {WIDTH{1'b1}};
    assign done = valid_pipe[STAGES];
    assign ready = 1'b1;

endmodule
