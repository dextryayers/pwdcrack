// CRC-32, IEEE 802.3 reflected form: polynomial 0xEDB88320, initial value
// 0xFFFFFFFF, final XOR 0xFFFFFFFF.
//
// STATUS: VERIFIED against every vector in `rtl/sim/vectors/crc32.svh`, which
// scripts/gen-rtl-vectors.py emits from zlib. The host computes the same
// function in engines/engine-fpga/src/protocol.rs and the two must agree
// exactly: a CRC that differs by one bit rejects every packet with no clue as
// to why, which is the failure the previous version of this file had.
//
// # What was wrong before
//
// This core implemented CRC-32 with the non reflected polynomial 0x04C11DB7,
// the one from the MPEG-2 specification, in an MSB first shift register. That is
// a real CRC and a correct one, and it is not the CRC that CRC-32 means. Its own
// testbench asserted CRC32("abc") == 0x352441c2, which is the IEEE value, so the
// file asserted a value it could not produce.
//
// The Rust host had the opposite problem: a byte wise CRC that started from 0
// and omitted the final XOR, so the host computed 0xca6598d0 for the same input
// where the standard says 0x352441c2. The two were wrong in different
// directions, which is the worst case, because neither one could be checked
// against the other and both looked plausible.
//
// # Why byte at a time
//
// The host needs the CRC of a packet whose length is not known until the last
// byte has been sent. A core that consumed eight bytes per cycle would need to
// know the length in advance to tell whether the final word is padded. One byte
// per cycle costs nothing here: this is a protocol helper that runs for twenty
// bytes once per packet, not the hot path of anything.
//
// # Interface
//
// `crc_init` starts a new message, so the register is reloaded with the initial
// value on the byte it accompanies. `byte_last` marks the byte being processed
// as the final one, and applies the final XOR exactly once.
//
// A zero length message is `crc_init` and `byte_last` with `valid` LOW: no byte
// is consumed and the result is 0x00000000, the standard CRC of the empty
// string. That combination is otherwise unreachable, so nothing else can be
// confused with it, and it is tested because it is the value a caller computes
// for an empty buffer and will compare against.
//
// The other cores in `rtl/cores` have `valid`, `ready` and `done`; this one has
// no `ready` because it can never refuse a byte. The testbench task in
// tb_common.svh drives the three signals it does have.

module crc32_accel (
    input  logic        clk,
    input  logic        rst_n,
    // Start a new message with this byte.
    input  logic        crc_init,
    input  logic        valid,
    // This is the last byte of the message.
    input  logic        byte_last,
    input  logic [7:0]  data_in,
    output logic [31:0] crc_out,
    output logic        done
);

    logic [31:0] crc_reg;
    logic [31:0] crc_out_r;
    logic        done_r;

    // One reflected CRC step: eight shifts, each optionally XORed with the
    // reversed polynomial.
    function automatic [31:0] crc_step(input [31:0] crc, input [7:0] b);
        logic [31:0] c;
        begin
            c = crc;
            for (int i = 0; i < 8; i = i + 1)
                c = (c[0] ^ b[i]) ? ((c >> 1) ^ 32'hEDB88320) : (c >> 1);
            crc_step = c;
        end
    endfunction

    initial begin
        crc_reg  = 32'hFFFFFFFF;
        crc_out_r = 32'h0;
        done_r   = 1'b0;
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            crc_reg  <= 32'hFFFFFFFF;
            crc_out_r <= 32'h0;
            done_r   <= 1'b0;
        end else begin
            done_r <= 1'b0;

            // Zero length message: no byte, no final XOR to apply, just the
            // standard answer for nothing.
            if (crc_init && byte_last && !valid) begin
                crc_reg   <= 32'hFFFFFFFF;
                crc_out_r <= 32'h00000000;
                done_r    <= 1'b1;
            end else if (valid) begin
                crc_reg <= crc_step(crc_init ? 32'hFFFFFFFF : crc_reg, data_in);
                if (byte_last) begin
                    // The final XOR happens here, once, at the end of the
                    // message, not on every byte.
                    crc_out_r <= crc_step(crc_init ? 32'hFFFFFFFF : crc_reg,
                                          data_in) ^ 32'hFFFFFFFF;
                    done_r <= 1'b1;
                end
            end
        end
    end

    assign crc_out = crc_out_r;
    assign done    = done_r;

endmodule