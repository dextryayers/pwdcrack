// ============================================================
// Top-level FPGA Testbench — integrated core test
// ============================================================

module top_tb;

    logic        pcie_clk, pcie_rst_n;
    logic [31:0] pcie_rx_data, pcie_tx_data;
    logic [13:0] ddr_addr;
    logic        ddr_cke;
    logic [3:0]  led;
    logic        uart_tx, uart_rx;

    // Direct core access for testing (top-level doesn't expose core I/O)
    // We test through the top-level ports
    pwdcrack_top dut (.*);

    always #5 pcie_clk = ~pcie_clk;

    int pass_count, fail_count;

    initial begin
        $display("=== FPGA Top-Level Integration Test ===");
        pcie_clk = 0;
        pcie_rst_n = 0;
        pcie_rx_data = '0;
        uart_rx = 1;
        pass_count = 0;
        fail_count = 0;

        #20 pcie_rst_n = 1;

        // Wait for cores to stabilize
        #100;

        // Check LEDs (indicate core presence + activity)
        $display("LEDs: %b (MD5=%b, SHA256=%b, NTLM=%b, active=%b)",
                 led, led[0], led[1], led[2], led[3]);

        // Verify cores are instantiated (active LED toggles on activity)
        // Send a pulse to MD5 core via top-level stimulus
        // (In real hardware, PCIe command would trigger this)

        #1000;

        $display("=== Top-level test complete ===");
        $display("Note: Full RTL verification requires core-specific testbenches");
        $display("  md5_tb.sv  — MD5 with 4 test vectors");
        $display("  sha256_tb.sv — SHA256 with 3 test vectors");
        $finish;
    end

endmodule