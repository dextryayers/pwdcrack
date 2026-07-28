// ============================================================
// MD5 Core Testbench — comprehensive test vectors
// ============================================================

module md5_tb;

    logic        clk, rst_n;
    logic        valid, ready, done;
    logic [31:0] msg_word [15:0];
    logic [31:0] h_in     [3:0];
    logic [31:0] h_out    [3:0];

    md5_core dut (.*);

    always #5 clk = ~clk;

    // Expected results
    logic [31:0] exp_hash [3:0];
    int          test_num;
    int          pass_count, fail_count;

    task test_vector(
        input [31:0] m [15:0],
        input [31:0] iv [3:0],
        input [31:0] expected [3:0],
        input string name
    );
        @(posedge clk);
        for (int i = 0; i < 16; i++) msg_word[i] <= m[i];
        h_in[0] <= iv[0]; h_in[1] <= iv[1]; h_in[2] <= iv[2]; h_in[3] <= iv[3];
        valid <= 1;
        @(posedge clk);
        valid <= 0;

        // Wait 65 cycles for pipeline
        repeat (66) @(posedge clk);

        if (done) begin
            if (h_out[0] === expected[0] && h_out[1] === expected[1] &&
                h_out[2] === expected[2] && h_out[3] === expected[3]) begin
                $display("  PASS [%0d]: %s", test_num, name);
                pass_count++;
            end else begin
                $display("  FAIL [%0d]: %s", test_num, name);
                $display("    Got:      %08x%08x%08x%08x", h_out[0], h_out[1], h_out[2], h_out[3]);
                $display("    Expected: %08x%08x%08x%08x", expected[0], expected[1], expected[2], expected[3]);
                fail_count++;
            end
        end else begin
            $display("  FAIL [%0d]: %s (no done signal)", test_num, name);
            fail_count++;
        end
        test_num++;
    endtask

    initial begin
        $display("=== MD5 Core Comprehensive Test ===");
        clk = 0;
        rst_n = 0;
        valid = 0;
        msg_word = '{default: '0};
        h_in = '{default: '0};
        test_num = 0;
        pass_count = 0;
        fail_count = 0;

        #20 rst_n = 1;

        // MD5 IV
        logic [31:0] iv [3:0];
        iv[0] = 32'h67452301;
        iv[1] = 32'hefcdab89;
        iv[2] = 32'h98badcfe;
        iv[3] = 32'h10325476;

        // Test 1: MD5("") = d41d8cd98f00b204e9800998ecf8427e
        test_vector(
            '{default: '0},
            iv,
            '{32'hd41d8cd9, 32'h8f00b204, 32'he9800998, 32'hecf8427e},
            "MD5('')"
        );

        // Test 2: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        // Block: [0x61626380, 0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0, 24] (24 bits = 0x18000000 LE)
        test_vector(
            '{32'h61626380, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000018, 32'h00000000},
            iv,
            '{32'h90015098, 32'h3cd24fb0, 32'hd6963f7d, 32'h28e17f72},
            "MD5('abc')"
        );

        // Test 3: MD5("message digest") = f96b697d7cb7938d525a2f31aaf161d0
        // Block: "message digest" (14 bytes) + 0x80 + zeros + len(112 bits = 0x70000000 LE)
        test_vector(
            '{32'h7373656d, 32'h65676120, 32'h74657364, 32'h80,
              32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00700000, 32'h00000000},
            iv,
            '{32'hf96b697d, 32'h7cb7938d, 32'h525a2f31, 32'haaf161d0},
            "MD5('message digest')"
        );

        // Test 4: MD5 with single char
        test_vector(
            '{32'h61800000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000008, 32'h00000000},
            iv,
            '{32'h0cc175b9, 32'hc0f1b6a8, 32'h31c399e2, 32'h69772661},
            "MD5('a')"
        );

        #100;

        $display("=== Results: %0d pass, %0d fail out of %0d ===", pass_count, fail_count, test_num);
        $finish;
    end

endmodule