// ============================================================
// SHA-256 Core Testbench
// ============================================================

module sha256_tb;

    logic        clk, rst_n;
    logic        valid, ready, done;
    logic [31:0] msg_word [15:0];
    logic [31:0] h_in     [7:0];
    logic [31:0] h_out    [7:0];

    sha256_core dut (.*);

    always #5 clk = ~clk;

    initial begin
        $display("=== SHA-256 Core Test ===");
        clk = 0;
        rst_n = 0;
        valid = 0;
        h_in = '{32'h6a09e667, 32'hbb67ae85, 32'h3c6ef372, 32'ha54ff53a,
                 32'h510e527f, 32'h9b05688c, 32'h1f83d9ab, 32'h5be0cd19};
        msg_word = '{default: '0};

        #20 rst_n = 1;

        // Test vector: SHA256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        @(posedge clk);
        valid = 1;
        @(posedge clk);
        valid = 0;

        #330;

        if (done) begin
            $display("SHA256(''): %08x%08x%08x%08x%08x%08x%08x%08x",
                     h_out[0], h_out[1], h_out[2], h_out[3],
                     h_out[4], h_out[5], h_out[6], h_out[7]);
            $display("Expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        end

        // Test vector: SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        msg_word[0] = 32'h61626380;
        @(posedge clk);
        valid = 1;
        @(posedge clk);
        valid = 0;

        #330;

        if (done) begin
            $display("SHA256('abc'): %08x%08x%08x%08x%08x%08x%08x%08x",
                     h_out[0], h_out[1], h_out[2], h_out[3],
                     h_out[4], h_out[5], h_out[6], h_out[7]);
            $display("Expected: ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        end

        #100;
        $finish;
    end

endmodule
