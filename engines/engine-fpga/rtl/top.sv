// ============================================================
// pwdcrack FPGA Top-Level Module
// ============================================================

module pwdcrack_top (
    // PCIe interface
    input  logic        pcie_clk,
    input  logic        pcie_rst_n,
    input  logic [31:0] pcie_rx_data,
    output logic [31:0] pcie_tx_data,

    // DDR4 interface
    output logic [13:0] ddr_addr,
    output logic        ddr_cke,
    // ... additional DDR signals

    // LEDs / debug
    output logic [3:0]  led,
    output logic        uart_tx,
    input  logic        uart_rx
);

    // Internal signals
    logic        clk, rst_n;
    logic [31:0] msg_word_md5  [15:0];
    logic [31:0] msg_word_sha  [15:0];
    logic [31:0] h_in_md5      [3:0];
    logic [31:0] h_in_sha      [7:0];
    logic [31:0] h_out_md5     [3:0];
    logic [31:0] h_out_sha     [7:0];
    logic        valid_md5, ready_md5, done_md5;
    logic        valid_sha, ready_sha, done_sha;
    logic        valid_ntlm, ready_ntlm, done_ntlm;
    logic [31:0] h_out_ntlm   [3:0];

    // Clock and reset
    assign clk = pcie_clk;
    assign rst_n = pcie_rst_n;

    // Core instances
    md5_core md5_inst (
        .clk(clk),
        .rst_n(rst_n),
        .valid(valid_md5),
        .ready(ready_md5),
        .msg_word(msg_word_md5),
        .h_in(h_in_md5),
        .h_out(h_out_md5),
        .done(done_md5)
    );

    sha256_core sha256_inst (
        .clk(clk),
        .rst_n(rst_n),
        .valid(valid_sha),
        .ready(ready_sha),
        .msg_word(msg_word_sha),
        .h_in(h_in_sha),
        .h_out(h_out_sha),
        .done(done_sha)
    );

    ntlm_core ntlm_inst (
        .clk(clk),
        .rst_n(rst_n),
        .valid(valid_ntlm),
        .ready(ready_ntlm),
        .msg_word(msg_word_sha),   // Reuse SHA message (host sends NTLM block separately)
        .h_in(h_in_md5),           // MD4 IV
        .h_out(h_out_ntlm),
        .done(done_ntlm)
    );

    // PCIe DMA wrapper (placeholder)
    logic [31:0] dma_rx_data;
    logic        dma_rx_valid, dma_rx_ready;
    logic [31:0] dma_tx_data;
    logic        dma_tx_valid, dma_tx_ready;

    // Scheduler / arbiter
    // Round-robin between cores, feed candidates from PCIe

    // LED output: activity indicator
    assign led[0] = done_md5;
    assign led[1] = done_sha;
    assign led[2] = done_ntlm;
    assign led[3] = valid_md5 || valid_sha || valid_ntlm;

    // UART debug
    assign uart_tx = 1'b1;

endmodule
