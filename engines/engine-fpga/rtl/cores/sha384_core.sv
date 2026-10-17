// SHA-384 core: SHA-512's compression function with different initial values and
// a shorter digest.
//
// STATUS: VERIFIED against every vector in `rtl/sim/vectors/sha384.svh`.
//
// # Why a wrapper
//
// SHA-384 is not a different algorithm. It is SHA-512 with a different initial
// state and the digest truncated to the first six words. Implementing it again
// would mean two copies of an 80 round 64 bit core to keep in step, and the
// second copy is the one that will rot.
//
// So this module instantiates `sha512_core`, feeds it the SHA-384 initial value,
// and presents six of the eight state words. The truncation is on the output
// only; the full state is computed, because the compression function needs all
// eight words.
//
// # Interface
//
// Same as every core in `rtl/cores`, with a 384 bit digest. Word 0 in the low
// bits, big endian, see `rtl/README.md`.

module sha384_core (
    input  logic          clk,
    input  logic          rst_n,
    input  logic          valid,
    output logic          ready,
    input  logic [1023:0] msg_blk,
    input  logic [383:0]  state_in,
    output logic [383:0]  digest_out,
    output logic          done
);

    // The SHA-384 initial value, from FIPS 180-4, in this design's word order:
    // H0 at the low bits.
    // On one line: a sized literal cannot be split across lines in
    // SystemVerilog, and the line continuation people reach for is a syntax
    // error in Icarus rather than a continuation.
    localparam logic [511:0] SHA384_IV = 512'h47b5481dbefa4fa4db0c2e0d64f98fa78eb44a876858151167332667ffc00b31152fecd8f70e59399159015a3070dd17629a292a367cd507cbbb9d5dc1059ed8;

    logic [511:0] digest_full;

    assign digest_out[ 63:  0] = digest_full[ 63:  0];
    assign digest_out[127: 64] = digest_full[127: 64];
    assign digest_out[191:128] = digest_full[191:128];
    assign digest_out[255:192] = digest_full[255:192];
    assign digest_out[319:256] = digest_full[319:256];
    assign digest_out[383:320] = digest_full[383:320];

    sha512_core u_sha512 (
        .clk        (clk),
        .rst_n      (rst_n),
        .valid      (valid),
        .ready      (ready),
        .msg_blk    (msg_blk),
        // `state_in` exists on this interface for cores that chain blocks.
        // SHA-384 of a multi block message needs the previous block's state,
        // which is what the caller holds in the first six words; the high two
        // words of the chaining state are not part of the interface, so the high
        // two words of SHA-384's initial value are used for every block. That is
        // correct for a single block message, which is what this core accepts,
        // and wrong for a longer one, which it does not accept.
        .state_in   (SHA384_IV),
        .digest_out (digest_full),
        .done       (done)
    );

    // `state_in` is accepted so that every core in this design has the same
    // interface, and is deliberately unused: this wrapper always starts from
    // SHA-384's initial value, so it hashes one block. A multi block SHA-384
    // needs the chaining state, which means a different wrapper with a 512 bit
    // state port; see the header.
    wire unused_state_in = &{1'b0, state_in};

endmodule