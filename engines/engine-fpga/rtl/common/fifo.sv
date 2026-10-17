// ============================================================================
// STATUS: NOT VERIFIED. Not instantiated in `rtl/top.sv`, not in any testbench.
//
// Nothing in this file has been shown to produce a correct digest for any
// input. P8.2.10 requires the design to contain only verified blocks, and an
// unverified core in a bitstream is a core whose digest is a plausible wrong
// answer, which for a cracker is worse than no core at all.
//
// What it would take to bring this one in:
//
//   1. a testbench in `rtl/sim/`, using the generated vectors;
//   2. the core renamed to the `<algorithm>_core` convention and given the
//      interface every other core uses: `valid`, `ready`, `msg_blk`,
//      `state_in`, `digest_out`, `done`, word 0 in the least significant
//      bits, described in `rtl/README.md`;
//   3. an entry in scripts/gen-rtl-vectors.py, so the vectors come from an
//      oracle rather than from memory.
//
// See docs/PHASE8_STATUS.md for the state of every core and
// docs/PHASE8_STATUS.md#unverified for what each of these needs.
//
// Why: a utility block, not a hash core, not instantiated by `rtl/top.sv`
// and not covered by any testbench.
// ============================================================================

// ============================================================
// Synchronous FIFO - valid/ready handshake
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
