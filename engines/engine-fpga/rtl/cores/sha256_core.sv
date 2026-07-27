// ============================================================
// SHA-256 Pipelined Core — 1 hash/cycle after 64-cycle latency
// ============================================================

module sha256_core (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        valid,
    output logic        ready,
    input  logic [31:0] msg_word  [15:0],
    input  logic [31:0] h_in      [7:0],
    output logic [31:0] h_out     [7:0],
    output logic        done
);

    // 64 rounds of SHA-256 compression
    // Fully pipelined with 64 stages

endmodule
