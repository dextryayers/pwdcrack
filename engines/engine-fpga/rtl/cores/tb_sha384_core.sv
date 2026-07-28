// ============================================================
// SHA-384 Testbench — test vectors
// ============================================================

module tb_sha384_core;

    logic        clk, rst_n, start, ready;
    logic [63:0] w [0:15];
    logic [63:0] digest [0:5];

    sha384_core dut (.*);

    always #5 clk = ~clk;

    int test_num, pass_count, fail_count;

    task test_vector(
        input [63:0] m [0:15],
        input [63:0] expected [0:5],
        input string name
    );
        @(posedge clk);
        for (int i = 0; i < 16; i++) w[i] <= m[i];
        start <= 1;
        @(posedge clk);
        start <= 0;
        wait(ready);
        #5;

        bit match = 1;
        for (int i = 0; i < 6; i++)
            if (digest[i] !== expected[i]) match = 0;

        if (match) begin
            $display("  PASS [%0d]: %s", test_num, name);
            pass_count++;
        end else begin
            $display("  FAIL [%0d]: %s", test_num, name);
            $write("    Got:      ");
            for (int i = 0; i < 6; i++) $write("%016x", digest[i]);
            $write("\n    Expected: ");
            for (int i = 0; i < 6; i++) $write("%016x", expected[i]);
            $display("");
            fail_count++;
        end
        test_num++;
    endtask

    initial begin
        $display("=== SHA-384 Test ===");
        clk = 0; rst_n = 0; start = 0;
        for (int i = 0; i < 16; i++) w[i] = 0;
        test_num = 0; pass_count = 0; fail_count = 0;

        #20 rst_n = 1;

        // SHA-384("") = 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
        test_vector(
            '{default: '0},
            '{64'h38b060a751ac9638, 64'h4cd9327eb1b1e36a, 64'h21fdb71114be0743,
              64'h4c0cc7bf63f6e1da, 64'h274edebfe76f65fb, 64'hd51ad2f14898b95b},
            "SHA384('')"
        );

        // SHA-384("abc") = cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
        test_vector(
            '{64'h6162638000000000, 64'h0000000000000000, 64'h0000000000000000,
              64'h0000000000000000, 64'h0000000000000000, 64'h0000000000000000,
              64'h0000000000000000, 64'h0000000000000000, 64'h0000000000000000,
              64'h0000000000000000, 64'h0000000000000000, 64'h0000000000000000,
              64'h0000000000000000, 64'h0000000000000000, 64'h0000000000000018, 64'h0000000000000000},
            '{64'hcb00753f45a35e8b, 64'hb5a03d699ac65007, 64'h272c32ab0eded163,
              64'h1a8b605a43ff5bed, 64'h8086072ba1e7cc23, 64'h58baeca134c825a7},
            "SHA384('abc')"
        );

        #100;
        $display("=== Results: %0d pass, %0d fail out of %0d ===", pass_count, fail_count, test_num);
        $finish;
    end

endmodule
