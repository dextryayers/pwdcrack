// ============================================================
// BLAKE2s-256 Testbench — "abc" vector
// ============================================================

module tb_blake2s_core;

    logic        clk, rst_n, start;
    logic [31:0] msg [15:0];
    logic [31:0] digest [7:0];
    logic        ready;

    blake2s_core dut (.*);

    always #5 clk = ~clk;

    initial begin
        $display("=== BLAKE2s-256 Test ===");
        clk = 0; rst_n = 0; start = 0;
        for (int i = 0; i < 16; i++) msg[i] = 0;

        #10 rst_n = 1;
        #10;

        // BLAKE2s("abc") with 24-bit output — full output
        // BLAKE2s-256("abc") = 508c5e8c327c14e2e1a72ba34eeb452f...
        msg[0] = 32'h61626380; msg[1] = 32'h00000000;
        msg[2] = 32'h00000000; msg[3] = 32'h00000000;
        msg[4] = 32'h00000000; msg[5] = 32'h00000000;
        msg[6] = 32'h00000000; msg[7] = 32'h00000000;
        msg[8] = 32'h00000000; msg[9] = 32'h00000000;
        msg[10] = 32'h00000000; msg[11] = 32'h00000000;
        msg[12] = 32'h00000000; msg[13] = 32'h00000000;
        msg[14] = 32'h00000018; msg[15] = 32'h00000000;

        @(posedge clk);
        start = 1;
        @(posedge clk);
        start = 0;

        wait(ready);
        #5;

        // Expected: 508c5e8c327c14e2e1a72ba34eeb452f...
        if (digest[0] === 32'h508c5e8c && digest[1] === 32'h327c14e2) begin
            $display("  PASS: BLAKE2s('abc')");
            $display("  Digest: %08x%08x%08x%08x%08x%08x%08x%08x",
                     digest[0], digest[1], digest[2], digest[3],
                     digest[4], digest[5], digest[6], digest[7]);
        end else begin
            $display("  FAIL: BLAKE2s('abc')");
            $display("  Got:      %08x%08x%08x%08x%08x%08x%08x%08x",
                     digest[0], digest[1], digest[2], digest[3],
                     digest[4], digest[5], digest[6], digest[7]);
        end

        $finish;
    end

endmodule
