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

    // Core instances
    md5_core    md5_inst    (.*);
    sha256_core sha256_inst (.*);

    // AXI4 interconnect + scheduler
    // PCIe DMA wrapper
    // Clock crossing + reset synchronization

endmodule
