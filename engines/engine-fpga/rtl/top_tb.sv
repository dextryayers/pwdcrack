// ============================================================
// Top-level FPGA Testbench
// ============================================================

module top_tb;

    logic        pcie_clk, pcie_rst_n;
    logic [31:0] pcie_rx_data, pcie_tx_data;
    logic [13:0] ddr_addr;
    logic        ddr_cke;
    logic [3:0]  led;
    logic        uart_tx, uart_rx;

    pwdcrack_top dut (.*);

    always #5 pcie_clk = ~pcie_clk;

    initial begin
        $display("=== FPGA Top-Level Test ===");
        pcie_clk = 0;
        pcie_rst_n = 0;
        pcie_rx_data = '0;
        uart_rx = 1;

        #20 pcie_rst_n = 1;

        // Send simple command over PCIe (placeholder)
        #100;

        $display("LEDs: %b (MD5=%b, SHA256=%b, NTLM=%b, active=%b)",
                 led, led[0], led[1], led[2], led[3]);

        #1000;
        $finish;
    end

endmodule
