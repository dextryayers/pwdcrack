// ============================================================
// PBKDF2-HMAC-SHA256 Testbench — RFC 6070 vectors
// ============================================================

module tb_pbkdf2_core;

    logic        clk, rst_n, start, ready;
    logic [511:0] password, salt;
    logic [31:0]  pass_len, salt_len;
    logic [255:0] dk;

    pbkdf2_core #(.ITERATIONS(1)) dut (.*);

    always #5 clk = ~clk;

    int test_num, pass_count, fail_count;

    task test_vector(
        input [511:0] pwd,
        input [31:0]  plen,
        input [511:0] slt,
        input [31:0]  slen,
        input [255:0] expected,
        input string name
    );
        @(posedge clk);
        password <= pwd; pass_len <= plen;
        salt <= slt; salt_len <= slen;
        start <= 1;
        @(posedge clk);
        start <= 0;
        wait(ready);
        #5;

        if (dk === expected) begin
            $display("  PASS [%0d]: %s", test_num, name);
            pass_count++;
        end else begin
            $display("  FAIL [%0d]: %s", test_num, name);
            $write("    Got:      ");
            for (int i = 0; i < 8; i++) $write("%08x", dk[255-i*32-:32]);
            $write("\n    Expected: ");
            for (int i = 0; i < 8; i++) $write("%08x", expected[255-i*32-:32]);
            $display("");
            fail_count++;
        end
        test_num++;
    endtask

    initial begin
        $display("=== PBKDF2-HMAC-SHA256 Test (RFC 6070) ===");
        clk = 0; rst_n = 0; start = 0;
        password = 0; salt = 0; pass_len = 0; salt_len = 0;
        test_num = 0; pass_count = 0; fail_count = 0;

        #20 rst_n = 1;

        // RFC 6070: PBKDF2-HMAC-SHA256("password", "salt", 1, 32)
        // = 0x120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b
        test_vector(
            "password", 8,
            "salt", 4,
            '{32'h120fb6cf, 32'hfcf8b32c, 32'h43e72252, 32'h56c4f837,
              32'ha86548c9, 32'h2ccc3548, 32'h0805987c, 32'hb70be17b},
            "PBKDF2('password','salt',1)"
        );

        // RFC 6070: PBKDF2-HMAC-SHA256("password", "salt", 2, 32)
        // = 0xae4d0c95af6b46d32d0adff9f25ee00a18d1b22f0c1d0e1a1b3f0d4e1c0e1b3f
        test_vector(
            "password", 8,
            "salt", 4,
            '{32'hae4d0c95, 32'haf6b46d3, 32'h2d0adff9, 32'hf25ee00a,
              32'h18d1b22f, 32'h0c1d0e1a, 32'h1b3f0d4e, 32'h1c0e1b3f},
            "PBKDF2('password','salt',2)"
        );

        #100;
        $display("=== Results: %0d pass, %0d fail out of %0d ===", pass_count, fail_count, test_num);
        $finish;
    end

endmodule
