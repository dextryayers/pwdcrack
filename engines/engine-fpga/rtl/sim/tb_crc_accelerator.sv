// CRC-32 core testbench.
//
// # What this establishes
//
// `crc32_accel` computes the same CRC-32 as zlib and as the host's
// `protocol::crc32`. That agreement is the point: the host puts a CRC in every
// packet and checks every packet against it, so a core whose CRC differs by a
// single bit does not fail loudly, it fails by rejecting everything.
//
// The vectors include the empty message, whose CRC is 0x00000000, every byte
// value in sequence, and a run of bytes from 255 downwards. The previous
// testbench for this core asserted CRC32("abc") == 0x352441c2 against a core
// that computed the MPEG-2 CRC and could not produce it.

`include "tb_common.svh"

module tb_crc_accelerator;

    logic        clk = 1'b0;
    logic        rst_n = 1'b0;
    logic        crc_init = 1'b0;
    logic        valid = 1'b0;
    logic        byte_last = 1'b0;
    logic [7:0]  data_in = 8'h00;
    logic [31:0] crc_out;
    logic        done;

    `TB_COUNTERS

    crc32_accel dut (.*);

    always #5 clk = ~clk;

    `TB_REPORT("crc32_accel")
    `TB_CHECK_CRC

    localparam integer WAIT = 60;

    initial begin
        $display("=== crc32_accel, IEEE 802.3, vectors generated from zlib ===");

        crc_init  = 1'b0;
        valid     = 1'b0;
        byte_last = 1'b0;
        data_in   = 8'h00;

        repeat (2) @(posedge clk);
        rst_n = 1'b1;
        @(posedge clk);

        `include "vectors/crc32.svh"

        tb_report("crc32_accel");
    end

endmodule