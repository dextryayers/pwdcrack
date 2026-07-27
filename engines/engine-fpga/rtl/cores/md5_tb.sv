// ============================================================
// MD5 Core Testbench
// ============================================================

module md5_tb;

    logic        clk, rst_n;
    logic        valid, ready, done;
    logic [31:0] msg_word [15:0];
    logic [31:0] h_in     [3:0];
    logic [31:0] h_out    [3:0];

    md5_core dut (.*);

    // Clock generation
    always #5 clk = ~clk;

    initial begin
        $display("=== MD5 Core Test ===");
        clk = 0;
        rst_n = 0;
        valid = 0;
        h_in = '{32'h67452301, 32'hefcdab89, 32'h98badcfe, 32'h10325476};
        msg_word = '{default: '0};

        #20 rst_n = 1;

        // Test vector: MD5("") = d41d8cd98f00b204e9800998ecf8427e
        @(posedge clk);
        valid = 1;
        @(posedge clk);
        valid = 0;

        #330; // Wait 65 cycles

        if (done) begin
            $display("MD5(''): %08x%08x%08x%08x", h_out[0], h_out[1], h_out[2], h_out[3]);
            $display("Expected: d41d8cd98f00b204e9800998ecf8427e");
        end

        // Test vector: MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
        msg_word[0] = 32'h61626380;
        @(posedge clk);
        valid = 1;
        @(posedge clk);
        valid = 0;

        #330;

        if (done) begin
            $display("MD5('abc'): %08x%08x%08x%08x", h_out[0], h_out[1], h_out[2], h_out[3]);
            $display("Expected: 900150983cd24fb0d6963f7d28e17f72");
        end

        #100;
        $finish;
    end

endmodule
