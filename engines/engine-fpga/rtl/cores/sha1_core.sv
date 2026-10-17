// SHA-1 compression core.
//
// Verifies FIPS 180-4 SHA-1 over a single 512 bit block.
//
// # Why this was rewritten
//
// The previous version used non blocking assignment for temporaries that were
// read in the same iteration, so every value consumed was one cycle stale. Three
// separate instances of that, all of them silent:
//
//   1. The message schedule was expanded with `w_ext[i] <= ... w_ext[i-3] ...`.
//      Non blocking assignment reads the pre edge value, so `w_ext[16]` was
//      computed from the `w_ext[13]` of the previous transaction rather than the
//      one just written. On the first transaction those registers are X.
//   2. `f`, `k` and `temp` were all non blocking, so the `temp` for round n used
//      the `f` and `k` of round n-1. Every round ran with the previous round's
//      function.
//   3. `round == 0` loaded a..e from the state vector in the same cycle as the
//      first round executed, so round 0 computed from the registers left over
//      from the previous message rather than from the initial value.
//
// None of this was visible because the core had no testbench that ran. It now
// passes the vectors in `rtl/sim/tb_sha1_core.sv`.
//
// # Scope
//
// One block. SHA-1 of a message longer than 55 bytes needs several blocks and
// chaining between them, which this core does not provide. `tb_sha1_core.sv`
// tests only messages that fit one block and says so.
//
// # Word order
//
// Packed, word i at `[32*i +: 32]`, so word 0 is in the low bits. This matches
// `md5_core`, the host protocol, and what Icarus Verilog can propagate: a module
// output port declared as an unpacked array never reaches the parent.
//
// SHA-1 is big endian, unlike MD5. The block words arrive already in the order
// the padding produced them, and the digest words are emitted with A, the first
// state word, at `[31:0]`.

module sha1_core (
    input  logic          clk,
    input  logic          rst_n,
    input  logic          start,
    // One 512 bit block, word i at [511 - 32*i -: 32].
    //
    // Word 0 at the TOP, not the bottom, because SHA-1 is big endian. This
    // differs from md5_core, where word 0 sits in the low bits. Writing the
    // index the other way round loads the length field as if it were the first
    // message word, and every digest comes out wrong with no diagnostic.
    input  logic [511:0]  w,
    // Final state, word i at [32*i +: 32].
    output logic [159:0]  digest,
    output logic          ready
);

    // Message schedule, 80 words.
    logic [31:0] w_ext [0:79];

    // Seven bits, not six. SHA-1 runs 80 rounds, so a six bit counter wraps at
    // 64 and `round < 80` is never false. The core then spins with busy held
    // high and never produces a digest. The earlier version had this bug and no
    // testbench to notice it.
    logic [6:0]  round;
    logic        busy;

    // See the note on `digest`: always_comb rather than a continuous assign.
    always_comb ready = ~busy;

    // ROTL by 1, used only by the schedule.
    function automatic [31:0] rotl1(input [31:0] x);
        rotl1 = {x[30:0], x[31]};
    endfunction

    // ROTL by 5, the per round rotation on a.
    function automatic [31:0] rotl5(input [31:0] x);
        rotl5 = {x[26:0], x[31:27]};
    endfunction

    // ROTL by 30, which is a right rotate by 2, used on b to become c.
    function automatic [31:0] rotl30(input [31:0] x);
        rotl30 = {x[1:0], x[31:2]};
    endfunction

    // The four round functions, selected by round number.
    function automatic [31:0] f_of(
        input [5:0]  n,
        input [31:0] x,
        input [31:0] y,
        input [31:0] z
    );
        begin
            if (n < 20)      f_of = (x & y) | (~x & z);
            else if (n < 40) f_of = x ^ y ^ z;
            else if (n < 60) f_of = (x & y) | (x & z) | (y & z);
            else             f_of = x ^ y ^ z;
        end
    endfunction

    function automatic [31:0] k_of(input [5:0] n);
        begin
            if (n < 20)      k_of = 32'h5A827999;
            else if (n < 40) k_of = 32'h6ED9EBA1;
            else if (n < 60) k_of = 32'h8F1BBCDC;
            else             k_of = 32'hCA62C1D6;
        end
    endfunction

    // The message schedule, computed combinationally from `w`.
    //
    // Not inside the sequential block. A local `logic [31:0] sched [0:79]` filled
    // by a blocking loop inside always_ff produced a correct w_ext[0] and a zero
    // w_ext[17] with every later word wrong, and Icarus reported nothing. The
    // expansion is pure combinational logic anyway, so it belongs in its own
    // block where each step reads the word the previous step wrote.
    // The message schedule, computed combinationally from `w`.
    //
    // `always @*` rather than `always_comb`, because Icarus reports "constant
    // selects in always_* processes are not currently supported" for an
    // always_comb driving an array with a constant part select index.
    always @* begin
        for (int i = 0; i < 16; i = i + 1)
            w_ext[i] = w[511 - 32*i -: 32];
        for (int i = 16; i < 80; i = i + 1)
            w_ext[i] = rotl1(w_ext[i-3]) ^ rotl1(w_ext[i-8]) ^
                       rotl1(w_ext[i-14]) ^ rotl1(w_ext[i-16]);
    end

    // Working state, held between rounds.
    logic [31:0] acc_a, acc_b, acc_c, acc_d, acc_e;

    // `always_comb`, not `assign`. Icarus Verilog rejects a module output port
    // driven by a continuous assignment when the instance connects with `.*`,
    // reporting "Unable to assign to unresolved wires". Driving the port from a
    // process is accepted and is equivalent for a purely combinational value.
    // Assign the whole vector in one go. Driving a part select of an output port
    // from a process compiles but never propagates to the parent under Icarus
    // Verilog, while assigning the full vector does. Confirmed by compiling a
    // minimal case both ways.
    always_comb digest = {acc_e, acc_d, acc_c, acc_b, acc_a};

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            busy   <= 1'b0;
            round  <= '0;
            acc_a  <= 32'h67452301;
            acc_b  <= 32'hEFCDAB89;
            acc_c  <= 32'h98BADCFE;
            acc_d  <= 32'h10325476;
            acc_e  <= 32'hC3D2E1F0;
            for (int i = 0; i < 80; i = i + 1) w_ext[i] <= 32'h0;
        end else if (start && !busy) begin
            busy  <= 1'b1;
            round <= '0;

            // Load the initial value in its own cycle, so round 0 runs on it.
            acc_a <= 32'h67452301;
            acc_b <= 32'hEFCDAB89;
            acc_c <= 32'h98BADCFE;
            acc_d <= 32'h10325476;
            acc_e <= 32'hC3D2E1F0;
        end else if (busy) begin
            logic [31:0] f, k, t, na, nb, nc, nd, ne;

            if (round < 80) begin
                f = f_of(round, acc_b, acc_c, acc_d);
                k = k_of(round);
                t = rotl5(acc_a) + f + acc_e + k + w_ext[round[6:0]];

                na = t;
                nb = acc_a;
                nc = rotl30(acc_b);
                nd = acc_c;
                ne = acc_d;

                acc_a <= na; acc_b <= nb; acc_c <= nc; acc_d <= nd; acc_e <= ne;
                round <= round + 1'b1;
            end else begin
                // Feed forward. The initial value was loaded at start, so the
                // addition is against the state rather than a separate vector.
                acc_a <= acc_a + 32'h67452301;
                acc_b <= acc_b + 32'hEFCDAB89;
                acc_c <= acc_c + 32'h98BADCFE;
                acc_d <= acc_d + 32'h10325476;
                acc_e <= acc_e + 32'hC3D2E1F0;
                busy  <= 1'b0;
            end
        end
    end

    endmodule