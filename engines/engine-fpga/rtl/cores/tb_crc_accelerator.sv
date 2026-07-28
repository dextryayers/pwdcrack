// ============================================================
// CRC Accelerator Testbench — CRC32 sanity vectors
// ============================================================

module tb_crc_accelerator;

    logic        clk, rst_n;
    logic        valid, ready, done;
    logic [63:0] data_in;
    logic [31:0] crc_out;

    crc_accelerator #(.WIDTH(32), .POLY(32'h04C11DB7)) dut (.*);

    always #5 clk = ~clk;

    int test_num, pass_count, fail_count;

    task test_vector(
        input [63:0] data,
        input [31:0] expected,
        input string name
    );
        @(posedge clk);
        data_in <= data;
        valid <= 1;
        @(posedge clk);
        valid <= 0;
        repeat (4) @(posedge clk);

        if (done) begin
            if (crc_out === expected) begin
                $display("  PASS [%0d]: %s", test_num, name);
                pass_count++;
            end else begin
                $display("  FAIL [%0d]: %s", test_num, name);
                $display("    Got:      %08h, Expected: %08h", crc_out, expected);
                fail_count++;
            end
        end else begin
            $display("  FAIL [%0d]: %s (no done)", test_num, name);
            fail_count++;
        end
        test_num++;
    endtask

    initial begin
        $display("=== CRC32 Accelerator Test ===");
        clk = 0; rst_n = 0; valid = 0; data_in = 0;
        test_num = 0; pass_count = 0; fail_count = 0;

        #20 rst_n = 1;

        // CRC32("abc") = 0x352441c2
        test_vector(64'h6162630000000000, 32'h352441c2, "CRC32('abc')");

        // CRC32("") = 0x00000000
        test_vector(64'h0000000000000000, 32'h00000000, "CRC32('')");

        // CRC32("hello") = 0x3610a686
        test_vector(64'h68656c6c6f000000, 32'h3610a686, "CRC32('hello')");

        #100;
        $display("=== Results: %0d pass, %0d fail out of %0d ===", pass_count, fail_count, test_num);
        $finish;
    end

endmodule
