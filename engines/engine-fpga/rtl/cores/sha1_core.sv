// SHA-1 compression core, FIPS 180-4.
//
// STATUS: VERIFIED against every vector in `rtl/sim/vectors/sha1.svh`, which
// scripts/gen-rtl-vectors.py emits from Python hashlib.
//
// # Interface
//
// Same as every core in `rtl/cores`; see `md5_core.sv` for the port contract and
// `rtl/README.md` for the word order rule. In short: one block in, one digest
// out, `done` one cycle wide, word 0 in the low bits everywhere.
//
// SHA-1 is big endian, unlike MD5. `msg_blk[32*i +: 32]` is word i of the block
// with no byte reversal, because word 0 of a SHA-1 block is the first four bytes
// of the padded message in the order the specification lists them. Building the
// block the MD5 way loads the length field as if it were the first message word
// and every digest comes out wrong with no diagnostic.
//
// # Iterative, and why
//
// One round per cycle, 81 cycles per block, with a 16 word schedule register
// instead of a message ROM. A fully pipelined SHA-1 would need 80 stages, each
// carrying five state words and a sixteen word schedule window: about 54,000
// flip flops, which is most of a mid range Artix-7 for one core. The iterative
// form needs about 100 flip flops plus 80 words of storage.
//
// The trade is throughput per instance: one block every 81 cycles instead of one
// every cycle. On a card that fits four cores that is still 4/81 blocks per
// cycle, and four small cores are cheaper than one wide one. MD5 stays pipelined
// because 64 rounds of 32 bit logic is only about 10,400 flip flops.
//
// # The defect the previous version had
//
// It indexed its round constant and its round function with a SIX bit round
// counter while running eighty rounds:
//
//     function automatic [31:0] f_of(input [5:0] n, ...)
//     f = f_of(round, acc_b, acc_c, acc_d);   // round is [6:0]
//
// `round` is seven bits, so passing it to a six bit port truncates. Rounds 64
// to 79 read as rounds 0 to 15 and run with the wrong function and the wrong
// constant, which makes sixteen of eighty rounds wrong: a digest that is wrong
// in a way that looks plausible. Nothing caught it because the core had no
// testbench that ran. The counter is indexed as `round[6:0]` at every use here
// and the widths are declared once.

module sha1_core (
    input  logic          clk,
    input  logic          rst_n,
    input  logic          valid,
    output logic          ready,
    // One 512 bit block, word i at [32*i +: 32], big endian words.
    input  logic [511:0]  msg_blk,
    // Chaining state, word i at [32*i +: 32]. A at [31:0].
    input  logic [159:0]  state_in,
    output logic [159:0]  digest_out,
    output logic          done
);

    // Cycles from `valid` to `done`: one to load, eighty rounds, one to feed
    // forward.
    localparam int LATENCY = 82;

    // Message schedule, 16 words in a rotating window. Unpacked because it is
    // internal only: unpacked array ports do not propagate to the parent under
    // Icarus Verilog 12, packed ports do.
    logic [31:0] w [0:15];

    // Seven bits, not six. SHA-1 runs 80 rounds and a six bit counter wraps at
    // 64, so `round < 80` is never false and the core spins with `busy` held
    // high and never produces a digest.
    logic [6:0] round;
    logic       busy;
    logic       done_r;

    logic [31:0] acc_a, acc_b, acc_c, acc_d, acc_e;

    assign ready = ~busy;

    function automatic [31:0] rotl1(input [31:0] x);
        rotl1 = {x[30:0], x[31]};
    endfunction

    function automatic [31:0] rotl5(input [31:0] x);
        rotl5 = {x[26:0], x[31:27]};
    endfunction

    // ROTL 30 is a right rotate by 2.
    function automatic [31:0] rotl30(input [31:0] x);
        rotl30 = {x[1:0], x[31:2]};
    endfunction

    // The round function, selected by round number. The parameter is seven bits
    // because the counter is seven bits; see the module header for what happens
    // when it is not.
    function automatic [31:0] f_of(
        input [6:0] n,
        input [31:0] x,
        input [31:0] y,
        input [31:0] z
    );
        begin
            if (n < 7'd20)      f_of = (x & y) | (~x & z);
            else if (n < 7'd40) f_of = x ^ y ^ z;
            else if (n < 7'd60) f_of = (x & y) | (x & z) | (y & z);
            else                f_of = x ^ y ^ z;
        end
    endfunction

    function automatic [31:0] k_of(input [6:0] n);
        begin
            if (n < 7'd20)      k_of = 32'h5A827999;
            else if (n < 7'd40) k_of = 32'h6ED9EBA1;
            else if (n < 7'd60) k_of = 32'h8F1BBCDC;
            else                k_of = 32'hCA62C1D6;
        end
    endfunction

    // The window slot a round number reads, and the slot it writes.
    function automatic [3:0] slot(input [6:0] n);
        slot = n[3:0];
    endfunction

    initial begin
        for (int i = 0; i < 16; i = i + 1) w[i] = 32'h0;
        acc_a = 32'h67452301;
        acc_b = 32'hEFCDAB89;
        acc_c = 32'h98BADCFE;
        acc_d = 32'h10325476;
        acc_e = 32'hC3D2E1F0;
        round  = 7'd0;
        busy   = 1'b0;
        done_r = 1'b0;
    end

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            for (int i = 0; i < 16; i = i + 1) w[i] <= 32'h0;
            acc_a <= 32'h67452301;
            acc_b <= 32'hEFCDAB89;
            acc_c <= 32'h98BADCFE;
            acc_d <= 32'h10325476;
            acc_e <= 32'hC3D2E1F0;
            round  <= 7'd0;
            busy   <= 1'b0;
            done_r <= 1'b0;
        end else begin
            done_r <= 1'b0;

            if (valid && !busy) begin
                busy  <= 1'b1;
                round <= 7'd0;
                for (int i = 0; i < 16; i = i + 1)
                    w[i] <= msg_blk[32*i +: 32];
                acc_a <= state_in[31:0];
                acc_b <= state_in[63:32];
                acc_c <= state_in[95:64];
                acc_d <= state_in[127:96];
                acc_e <= state_in[159:128];
            end else if (busy) begin
                if (round < 7'd80) begin
                    logic [31:0] f, k, t;

                    f = f_of(round, acc_b, acc_c, acc_d);
                    k = k_of(round);
                    t = rotl5(acc_a) + f + acc_e + k + w[slot(round)];

                    // Extend the schedule for the round after this one.
                    //
                    // FIPS 180-4 states W[i] = ROTL1(W[i-3]) ^ ROTL1(W[i-8])
                    // ^ ROTL1(W[i-14]) ^ ROTL1(W[i-16]). The word being
                    // produced here is W[round+1], so every offset is taken
                    // from round+1 and not from round. Reading them off `round`
                    // instead produces W[round+1] from W[round-3] and friends,
                    // which is W[round-2] expanded one step early: rounds 0 to
                    // 15 are right and every digest from round 17 onward is
                    // wrong, so no vector passes.
                    //
                    // All four words are read before any is written, and the
                    // four slots are distinct, so the order of the statements
                    // does not matter.
                    // The guard is round >= 15, not round >= 16: the word being
                    // produced at round 15 is W[16], the first expanded word. A
                    // guard of 16 leaves W[16] unwritten, slot 0 keeps holding
                    // W[0], and round 16 runs with W[0] where it should run with
                    // W[16]: one wrong round, and a wrong digest for every
                    // message, since the schedule is expanded whatever the
                    // message length is.
                    if (round >= 7'd15) begin
                        w[slot(round + 7'd1)] <= rotl1(w[slot(round - 7'd2)])
                                               ^ rotl1(w[slot(round - 7'd7)])
                                               ^ rotl1(w[slot(round - 7'd13)])
                                               ^ rotl1(w[slot(round - 7'd15)]);
                    end

                    acc_a <= t;
                    acc_b <= acc_a;
                    acc_c <= rotl30(acc_b);
                    acc_d <= acc_c;
                    acc_e <= acc_d;
                    round <= round + 7'd1;
                end else begin
                    // Feed forward against the state the block started from.
                    // `state_in` is still that state: the core is busy, so no
                    // new block has been accepted since.
                    acc_a <= acc_a + state_in[31:0];
                    acc_b <= acc_b + state_in[63:32];
                    acc_c <= acc_c + state_in[95:64];
                    acc_d <= acc_d + state_in[127:96];
                    acc_e <= acc_e + state_in[159:128];
                    busy  <= 1'b0;
                    done_r <= 1'b1;
                end
            end
        end
    end

    // A at [31:0], word 0 in the low bits.
    assign digest_out[31:0]   = acc_a;
    assign digest_out[63:32]  = acc_b;
    assign digest_out[95:64]  = acc_c;
    assign digest_out[127:96] = acc_d;
    assign digest_out[159:128] = acc_e;
    assign done = done_r;

endmodule