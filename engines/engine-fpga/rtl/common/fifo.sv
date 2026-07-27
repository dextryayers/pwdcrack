// ============================================================
// Synchronous FIFO — valid/ready handshake
// ============================================================

module fifo #(
    parameter DATA_WIDTH = 32,
    parameter DEPTH = 16
)(
    input  logic                clk,
    input  logic                rst_n,

    // Write interface
    input  logic                wr_valid,
    output logic                wr_ready,
    input  logic [DATA_WIDTH-1:0] wr_data,

    // Read interface
    output logic                rd_valid,
    input  logic                rd_ready,
    output logic [DATA_WIDTH-1:0] rd_data
);

    localparam PTR_WIDTH = $clog2(DEPTH);

    logic [DATA_WIDTH-1:0] mem [0:DEPTH-1];
    logic [PTR_WIDTH:0]    wr_ptr, rd_ptr;

    assign wr_ready = (wr_ptr - rd_ptr) < DEPTH;
    assign rd_valid = (wr_ptr != rd_ptr);
    assign rd_data  = mem[rd_ptr[PTR_WIDTH-1:0]];

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            wr_ptr <= '0;
            rd_ptr <= '0;
        end else begin
            if (wr_valid && wr_ready) begin
                mem[wr_ptr[PTR_WIDTH-1:0]] <= wr_data;
                wr_ptr <= wr_ptr + 1;
            end
            if (rd_valid && rd_ready) begin
                rd_ptr <= rd_ptr + 1;
            end
        end
    end

endmodule
