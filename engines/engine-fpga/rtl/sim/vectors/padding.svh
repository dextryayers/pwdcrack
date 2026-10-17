// GENERATED FILE. DO NOT EDIT.
// Padded blocks for MD4, MD5 and SHA-256 style padding, word 0 in the
// least significant bits. Oracle: struct.pack, cross checked against
// the digest of the same message by the core vector files.

        check_block_words(md5_padded_block(""),
            512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080,
            "");

        check_block_words(md5_padded_block("y"),
            512'h00000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008079,
            "y");

        check_block_words(md5_padded_block("yyy"),
            512'h00000000000000180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080797979,
            "yyy");

        check_block_words(md5_padded_block("yyyyyyyyyyyyyy"),
            512'h00000000000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000807979797979797979797979797979,
            "yyyyyyyyyyyyyy");

        check_block_words(md5_padded_block("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"),
            512'h00000000000001b88079797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
            "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy");

        md5_pad_blocks("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", b0, b1, blocks);
        if (blocks != 2) `TB_FAIL_NOTE("56 bytes", "expected 2 blocks");
        check_block_words(b0,
            512'h00000000000000807979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
            "56 bytes, block 0");
        check_block_words(b1,
            512'h00000000000001c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000,
            "56 bytes, block 1");

        md5_pad_blocks("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", b0, b1, blocks);
        if (blocks != 2) `TB_FAIL_NOTE("64 bytes", "expected 2 blocks");
        check_block_words(b0,
            512'h79797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
            "64 bytes, block 0");
        check_block_words(b1,
            512'h00000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080,
            "64 bytes, block 1");

        md5_pad_blocks("yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", b0, b1, blocks);
        if (blocks != 2) `TB_FAIL_NOTE("119 bytes", "expected 2 blocks");
        check_block_words(b0,
            512'h79797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
            "119 bytes, block 0");
        check_block_words(b1,
            512'h00000000000003b88079797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
            "119 bytes, block 1");

        // blocks and digests agree, so the padding helpers in
        // tb_common.svh are verified against the same bytes the
        // core testbenches feed to the cores.
