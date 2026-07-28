// ============================================================
// pwdcrack FPGA Top-Level Module — rev 2 with SHA-1, SHA-512, BLAKE2b, HMAC
// ============================================================

module pwdcrack_top (
    input  logic        pcie_clk,
    input  logic        pcie_rst_n,
    input  logic [31:0] pcie_rx_data,
    output logic [31:0] pcie_tx_data,
    output logic [13:0] ddr_addr,
    output logic        ddr_cke,
    output logic [3:0]  led,
    output logic        uart_tx,
    input  logic        uart_rx
);

    logic        clk, rst_n;
    assign clk = pcie_clk;
    assign rst_n = pcie_rst_n;

    // ── MD5 ──
    logic [31:0] md5_w [0:15];
    logic [31:0] md5_digest [0:3];
    logic        md5_start, md5_ready;
    md5_core md5_inst (.*, .w(md5_w), .digest(md5_digest), .start(md5_start), .ready(md5_ready));

    // ── SHA-1 (new) ──
    logic [31:0] sha1_w [0:15];
    logic [31:0] sha1_digest [0:4];
    logic        sha1_start, sha1_ready;
    sha1_core sha1_inst (.*, .w(sha1_w), .digest(sha1_digest), .start(sha1_start), .ready(sha1_ready));

    // ── SHA-256 ──
    logic [31:0] sha256_w [0:15];
    logic [31:0] sha256_digest [0:7];
    logic        sha256_start, sha256_ready;
    sha256_core sha256_inst (.*, .w(sha256_w), .digest(sha256_digest), .start(sha256_start), .ready(sha256_ready));

    // ── SHA-512 (new) ──
    logic [63:0] sha512_w [0:15];
    logic [63:0] sha512_digest [0:7];
    logic        sha512_start, sha512_ready;
    sha512_core sha512_inst (.*, .w(sha512_w), .digest(sha512_digest), .start(sha512_start), .ready(sha512_ready));

    // ── NTLM (MD4) ──
    logic [31:0] ntlm_w [0:15];
    logic [31:0] ntlm_digest [0:3];
    logic        ntlm_start, ntlm_ready;
    ntlm_core ntlm_inst (.*, .w(ntlm_w), .digest(ntlm_digest), .start(ntlm_start), .ready(ntlm_ready));

    // ── HMAC-MD5 (new) ──
    logic [127:0] hmac_md5_mac;
    logic         hmac_md5_start, hmac_md5_ready;
    hmac_wrapper #(.HASH_WIDTH(128), .BLOCK_SIZE(64), .DIGEST_WORDS(4))
        hmac_md5_inst (.*,
            .start(hmac_md5_start), .ready(hmac_md5_ready),
            .mac(hmac_md5_mac)
        );

    // ── PCIe DMA ──
    logic [31:0] dma_rx_data;
    logic        dma_rx_valid, dma_rx_ready;
    logic [31:0] dma_tx_data;
    logic        dma_tx_valid, dma_tx_ready;

    // ── LEDs ──
    assign led[0] = md5_ready;
    assign led[1] = sha1_ready | sha256_ready;
    assign led[2] = sha512_ready | ntlm_ready;
    assign led[3] = md5_start | sha1_start | sha256_start | sha512_start | ntlm_start;

    assign uart_tx = 1'b1;

endmodule
