// GENERATED FILE. DO NOT EDIT.
// CRC-32, IEEE 802.3 reflected form: polynomial 0xEDB88320, initial
// value 0xFFFFFFFF, final XOR 0xFFFFFFFF. The host computes the same
// function in engines/engine-fpga/src/protocol.rs, and the two must
// agree exactly or every packet is rejected by the device.
// Oracle: zlib.crc32.

        // CRC-32 of "<empty>", 0 bytes
        check_crc_empty(32'h00000000, "crc32(<empty>)", WAIT);

        // CRC-32 of "a", 1 byte
        check_crc(512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000061,
                 1,
                 32'he8b7be43,
                 "crc32(a)", WAIT);

        // CRC-32 of "abc", 3 bytes
        check_crc(512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000636261,
                 3,
                 32'h352441c2,
                 "crc32(abc)", WAIT);

        // CRC-32 of "123456789", 9 bytes
        check_crc(512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000393837363534333231,
                 9,
                 32'hcbf43926,
                 "crc32(123456789)", WAIT);

        // CRC-32 of "The quick brown fox jumps over the lazy dog", 43 bytes
        check_crc(512'h000000000000000000000000000000000000000000676f6420797a616c20656874207265766f2073706d756a20786f66206e776f7262206b6369757120656854,
                 43,
                 32'h414fa339,
                 "crc32(The quick brown fox jumps over the lazy dog)", WAIT);

        // CRC-32 of "pwdcrack fpga payload", 21 bytes
        check_crc(512'h0000000000000000000000000000000000000000000000000000000000000000000000000000000000000064616f6c7961702061677066206b63617263647770,
                 21,
                 32'habc794c8,
                 "crc32(pwdcrack fpga payload)", WAIT);

        // CRC-32 of "64 raw bytes, 0x00..0x3f", 64 bytes
        check_crc(512'h3f3e3d3c3b3a393837363534333231302f2e2d2c2b2a292827262524232221201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100,
                 64,
                 32'h100ece8c,
                 "crc32(64 raw bytes, 0x00..0x3f)", WAIT);

        // CRC-32 of "64 raw bytes, 0xff..0xc0", 64 bytes
        check_crc(512'hc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff,
                 64,
                 32'h6ae22a00,
                 "crc32(64 raw bytes, 0xff..0xc0)", WAIT);

        // 8 vectors, all generated.
