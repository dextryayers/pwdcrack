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
// Generic Pipeline Stage - valid/ready handshake register
// ============================================================

module pipeline_stage #(
    parameter DATA_WIDTH = 32
)(
    input  logic                clk,
    input  logic                rst_n,

    input  logic                in_valid,
    output logic                in_ready,
    input  logic [DATA_WIDTH-1:0] in_data,

    output logic                out_valid,
    input  logic                out_ready,
    output logic [DATA_WIDTH-1:0] out_data
);

    logic [DATA_WIDTH-1:0] data_reg;
    logic                  valid_reg, next_valid;

    assign next_valid = in_valid || (valid_reg && !out_ready);
    assign in_ready   = !valid_reg || (valid_reg && out_ready);
    assign out_valid  = valid_reg;
    assign out_data   = data_reg;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            valid_reg <= '0;
            data_reg  <= '0;
        end else begin
            valid_reg <= next_valid;
            if (in_valid && in_ready) begin
                data_reg <= in_data;
            end
        end
    end

endmodule
