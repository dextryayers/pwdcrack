// SHA-1 testbench
module sha1_tb;
    logic clk, rst_n, start;
    logic [31:0] w [0:15];
    logic [31:0] digest [0:4];
    logic ready;

    sha1_core dut (.*);

    always #5 clk = ~clk;

    initial begin
        clk = 0; rst_n = 0; start = 0;
        #10 rst_n = 1;

        // Test vector: SHA1("abc")
        w[0] = 32'h61626380;
        for (int i = 1; i < 15; i++) w[i] = 0;
        w[15] = 32'h00000018;

        @(posedge clk);
        start = 1;
        @(posedge clk);
        start = 0;

        wait(ready);
        #5;
        assert(digest[0] == 32'ha9993e36) else $error("SHA1 abc failed");
        assert(digest[1] == 32'h4706816a) else $error("SHA1 abc failed");

        // Test vector: SHA1("")
        #10;
        w[0] = 32'h80000000;
        for (int i = 1; i < 15; i++) w[i] = 0;
        w[15] = 0;

        @(posedge clk);
        start = 1;
        @(posedge clk);
        start = 0;

        wait(ready);
        #5;
        assert(digest[0] == 32'hda39a3ee) else $error("SHA1 empty failed");
        $display("SHA-1 core: all tests passed");
        $finish;
    end
endmodule
