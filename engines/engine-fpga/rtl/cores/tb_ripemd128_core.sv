// ============================================================
// RIPEMD-128 Testbench — test vectors
// ============================================================

module tb_ripemd128_core;

    logic        clk, rst_n, start, ready;
    logic [31:0] msg [15:0];
    logic [31:0] digest [3:0];

    ripemd128_core dut (.*);

    always #5 clk = ~clk;

    int test_num, pass_count, fail_count;

    task test_vector(
        input [31:0] m [15:0],
        input [31:0] expected [3:0],
        input string name
    );
        @(posedge clk);
        for (int i = 0; i < 16; i++) msg[i] <= m[i];
        start <= 1;
        @(posedge clk);
        start <= 0;
        wait(ready);
        #5;

        if (digest[0] === expected[0] && digest[1] === expected[1] &&
            digest[2] === expected[2] && digest[3] === expected[3]) begin
            $display("  PASS [%0d]: %s", test_num, name);
            pass_count++;
        end else begin
            $display("  FAIL [%0d]: %s", test_num, name);
            $display("    Got:      %08x%08x%08x%08x", digest[0], digest[1], digest[2], digest[3]);
            $display("    Expected: %08x%08x%08x%08x", expected[0], expected[1], expected[2], expected[3]);
            fail_count++;
        end
        test_num++;
    endtask

    initial begin
        $display("=== RIPEMD-128 Test ===");
        clk = 0; rst_n = 0; start = 0;
        for (int i = 0; i < 16; i++) msg[i] = 0;
        test_num = 0; pass_count = 0; fail_count = 0;

        #20 rst_n = 1;

        // RIPEMD-128("") = cdf26213a1dc8a47faea7348d3f1b4d6
        test_vector(
            '{default: '0},
            '{32'hcdf26213, 32'ha1dc8a47, 32'hfaea7348, 32'hd3f1b4d6},
            "RIPEMD128('')"
        );

        // RIPEMD-128("abc") = 0c5b8e46ee6e2f7c8a5da02b151df7b2
        test_vector(
            '{32'h61626380, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000018, 32'h00000000},
            '{32'h0c5b8e46, 32'hee6e2f7c, 32'h8a5da02b, 32'h151df7b2},
            "RIPEMD128('abc')"
        );

        #100;
        $display("=== Results: %0d pass, %0d fail out of %0d ===", pass_count, fail_count, test_num);
        $finish;
    end

endmodule
