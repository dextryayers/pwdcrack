// ============================================================
// SHA-256 Core Testbench — comprehensive test vectors
// ============================================================

module sha256_tb;

    logic        clk, rst_n;
    logic        valid, ready, done;
    logic [31:0] msg_word [15:0];
    logic [31:0] h_in     [7:0];
    logic [31:0] h_out    [7:0];

    sha256_core dut (.*);

    always #5 clk = ~clk;

    // SHA-256 IV
    logic [31:0] iv [7:0];

    int test_num, pass_count, fail_count;

    task test_vector(
        input [31:0] m [15:0],
        input [31:0] expected [7:0],
        input string name
    );
        @(posedge clk);
        for (int i = 0; i < 16; i++) msg_word[i] <= m[i];
        for (int i = 0; i < 8; i++) h_in[i] <= iv[i];
        valid <= 1;
        @(posedge clk);
        valid <= 0;

        repeat (66) @(posedge clk);

        if (done) begin
            bit match = 1;
            for (int i = 0; i < 8; i++)
                if (h_out[i] !== expected[i]) match = 0;
            if (match) begin
                $display("  PASS [%0d]: %s", test_num, name);
                pass_count++;
            end else begin
                $display("  FAIL [%0d]: %s", test_num, name);
                $write("    Got:      ");
                for (int i = 0; i < 8; i++) $write("%08x", h_out[i]);
                $write("\n    Expected: ");
                for (int i = 0; i < 8; i++) $write("%08x", expected[i]);
                $display("");
                fail_count++;
            end
        end else begin
            $display("  FAIL [%0d]: %s (no done)", test_num, name);
            fail_count++;
        end
        test_num++;
    endtask

    initial begin
        $display("=== SHA-256 Core Comprehensive Test ===");
        clk = 0; rst_n = 0; valid = 0;
        msg_word = '{default: '0}; h_in = '{default: '0};
        test_num = 0; pass_count = 0; fail_count = 0;

        iv[0] = 32'h6a09e667; iv[1] = 32'hbb67ae85;
        iv[2] = 32'h3c6ef372; iv[3] = 32'ha54ff53a;
        iv[4] = 32'h510e527f; iv[5] = 32'h9b05688c;
        iv[6] = 32'h1f83d9ab; iv[7] = 32'h5be0cd19;

        #20 rst_n = 1;

        // Test 1: SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        test_vector(
            '{default: '0},
            '{32'he3b0c442, 32'h98fc1c14, 32'h9afbf4c8, 32'h996fb924,
              32'h27ae41e4, 32'h649b934c, 32'ha495991b, 32'h7852b855},
            "SHA256('')"
        );

        // Test 2: SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        test_vector(
            '{32'h61626380, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000018, 32'h00000000},
            '{32'hba7816bf, 32'h8f01cfea, 32'h414140de, 32'h5dae2223,
              32'hb00361a3, 32'h96177a9c, 32'hb410ff61, 32'hf20015ad},
            "SHA256('abc')"
        );

        // Test 3: SHA256("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
        // This is the NIST-required multi-block test (448 bits = 56 bytes, 1 block)
        logic [31:0] long_msg [15:0];
        long_msg[0]  = 32'h61626364; long_msg[1]  = 32'h62636465;
        long_msg[2]  = 32'h63646566; long_msg[3]  = 32'h64656667;
        long_msg[4]  = 32'h65666768; long_msg[5]  = 32'h66676869;
        long_msg[6]  = 32'h6768696a; long_msg[7]  = 32'h68696a6b;
        long_msg[8]  = 32'h696a6b6c; long_msg[9]  = 32'h6a6b6c6d;
        long_msg[10] = 32'h6b6c6d6e; long_msg[11] = 32'h6c6d6e6f;
        long_msg[12] = 32'h6d6e6f70; long_msg[13] = 32'h6e6f7071;
        long_msg[14] = 32'h80000000; long_msg[15] = 32'h00000000;

        // This needs a second block. For now test single-block only.
        // Single block test: SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        test_vector(
            '{32'h68656c6c, 32'h6f800000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000000, 32'h00000000,
              32'h00000000, 32'h00000000, 32'h00000028, 32'h00000000},
            '{32'h2cf24dba, 32'h5fb0a30e, 32'h26e83b2a, 32'hc5b9e29e,
              32'h1b161e5c, 32'h1fa7425e, 32'h73043362, 32'h938b9824},
            "SHA256('hello')"
        );

        #100;

        $display("=== Results: %0d pass, %0d fail out of %0d ===", pass_count, fail_count, test_num);
        $finish;
    end

endmodule