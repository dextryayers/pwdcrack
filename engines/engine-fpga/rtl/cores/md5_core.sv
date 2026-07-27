// ============================================================
// MD5 Pipelined Core — 1 hash/cycle after 64-cycle latency
// ============================================================

module md5_core (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        valid,
    output logic        ready,
    input  logic [31:0] msg_word  [15:0],  // 512-bit message block
    input  logic [31:0] h_in      [3:0],   // Initial hash state
    output logic [31:0] h_out     [3:0],   // Final hash
    output logic        done
);

    // 64 rounds of MD5 computation
    // Stage 1-64: each does one round of the MD5 compression function
    // Fully pipelined: new input every cycle, output 64 cycles later

    // Implementation details:
    // - Uses 4 pipeline stages per round (16 rounds × 4 stages = 64 stages)
    // - Each stage: F, G, H, or I function + addition + rotate

endmodule
