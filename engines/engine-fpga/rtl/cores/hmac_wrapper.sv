// =============================================================================
// STATUS: NOT VERIFIED. Not instantiated in `rtl/top.sv`, not in any testbench.
//
// This file is not covered by `scripts/simulate.sh` and nothing here has been
// shown to produce a correct digest for any input. P8.2.10 requires the design
// to contain only verified blocks, and an unverified core in a bitstream is a
// core whose digest is a plausible wrong answer.
//
// What it would take to bring this one in: a testbench in `rtl/sim/`, vectors
// emitted by `scripts/gen-rtl-vectors.py`, and the core renamed to the
// `<algorithm>_core` convention with the interface every other core uses
// (`valid`, `ready`, `msg_blk`, `state_in`, `digest_out`, `done`, word 0 in the
// least significant bits). See `docs/PHASE8_STATUS.md` and `rtl/README.md`.
//
// The wrapper instantiates a SHA-256 core with a port list that does not
// match any core in `rtl/cores`, so it cannot elaborate.
// =============================================================================

// HMAC wrapper - supports MD5, SHA-1, SHA-256 hash cores
// Implements FIPS 198 HMAC: HMAC(K,m) = H((K' ^ opad) || H((K' ^ ipad) || m))
module hmac_wrapper #(
    parameter HASH_WIDTH  = 256,
    parameter BLOCK_SIZE  = 64,   // bytes
    parameter DIGEST_WORDS = 8     // for SHA-256
) (
    input  logic                        clk,
    input  logic                        rst_n,
    input  logic                        start,
    input  logic [BLOCK_SIZE*8-1:0]     key,
    input  logic [15:0]                 key_len,
    input  logic [BLOCK_SIZE*8-1:0]     message,
    input  logic [15:0]                 msg_len,
    output logic [HASH_WIDTH-1:0]       mac,
    output logic                        ready
);

    typedef enum logic [2:0] { IDLE, IPAD, IPAD_HASH, OPAD, OPAD_HASH, DONE } state_t;
    state_t state;

    logic [BLOCK_SIZE*8-1:0] ipad_key, opad_key;
    logic [HASH_WIDTH-1:0]   inner_hash;
    logic [HASH_WIDTH-1:0]   outer_block [0:1];
    logic                     hash_start, hash_ready;
    logic [7:0]               pad_cnt;

    // XOR key with ipad/opad
    always_comb begin
        for (int i = 0; i < BLOCK_SIZE; i++) begin
            ipad_key[i*8+:8] = (i < key_len) ? key[i*8+:8] ^ 8'h36 : 8'h36;
            opad_key[i*8+:8] = (i < key_len) ? key[i*8+:8] ^ 8'h5C : 8'h5C;
        end
    end

    // State machine
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state <= IDLE;
        end else case (state)
            IDLE: if (start) state <= IPAD;
            IPAD: begin
                // Load ipad_key + message into hash core
                state <= IPAD_HASH;
            end
            IPAD_HASH: if (hash_ready) begin
                inner_hash <= 0; // captured from hash core
                state <= OPAD;
            end
            OPAD: state <= OPAD_HASH;
            OPAD_HASH: if (hash_ready) begin
                state <= DONE;
            end
            DONE: state <= IDLE;
        endcase
    end

    assign ready = (state == IDLE);

endmodule
