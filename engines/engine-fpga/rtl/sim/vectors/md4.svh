// GENERATED FILE. DO NOT EDIT.
// MD4 (RFC 1320): single block vectors.
// Digest oracle: pure Python MD4, held against OpenSSL.
// Padding oracle: struct.pack in scripts/gen-rtl-vectors.py.
//
// Every block and every digest below is emitted, not transcribed. A
// testbench that builds its own block from the message reintroduces the
// part select with an arithmetic base that this simulator miscompiles;
// see the header of scripts/gen-rtl-vectors.py.

        // boundary corpus: "<empty>", 0 bytes
        check_core(512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080,
                   128'h76543210fedcba9889abcdef01234567,
                   128'hc089c0e0d7593cb731e96ad1e0cfd631,
                   "md4(<empty>)", WAIT);

        // boundary corpus: "y", 1 byte
        check_core(512'h00000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008079,
                   128'h76543210fedcba9889abcdef01234567,
                   128'h4d9f0f299ff0830337780e23565244ae,
                   "md4(y)", WAIT);

        // boundary corpus: "yyy", 3 bytes
        check_core(512'h00000000000000180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080797979,
                   128'h76543210fedcba9889abcdef01234567,
                   128'h7d8610bbc7c9e2a5b6b43e0f69a29eef,
                   "md4(yyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyy", 14 bytes
        check_core(512'h00000000000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000807979797979797979797979797979,
                   128'h76543210fedcba9889abcdef01234567,
                   128'h38cf83c50662d2ab0b08f809412f76b1,
                   "md4(yyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyy", 27 bytes
        check_core(512'h00000000000000d80000000000000000000000000000000000000000000000000000000080797979797979797979797979797979797979797979797979797979,
                   128'h76543210fedcba9889abcdef01234567,
                   128'haf799982b9cb8a17995634e8c908fbd2,
                   "md4(yyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 43 bytes
        check_core(512'h00000000000001580000000000000000000000008079797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
                   128'h76543210fedcba9889abcdef01234567,
                   128'had778cdd1bb7710d184dc0281274152d,
                   "md4(yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 54 bytes
        check_core(512'h00000000000001b00080797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
                   128'h76543210fedcba9889abcdef01234567,
                   128'hc6a3bb7c80cfc37c407349569873652b,
                   "md4(yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 55 bytes
        check_core(512'h00000000000001b88079797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
                   128'h76543210fedcba9889abcdef01234567,
                   128'h377d1bf13023d8f1db4b888c08795973,
                   "md4(yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "a", 1 byte
        check_core(512'h00000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008061,
                   128'h76543210fedcba9889abcdef01234567,
                   128'h24fbd6dbfb055e24463ee31db32ce5bd,
                   "md4(a)", WAIT);

        // boundary corpus: "abc", 3 bytes
        check_core(512'h00000000000000180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080636261,
                   128'h76543210fedcba9889abcdef01234567,
                   128'h9d72a67ae80ac15f52d821af7a0148a4,
                   "md4(abc)", WAIT);

        // boundary corpus: "message digest", 14 bytes
        check_core(512'h0000000000000070000000000000000000000000000000000000000000000000000000000000000000000000000000000080747365676964206567617373656d,
                   128'h76543210fedcba9889abcdef01234567,
                   128'h4b01c7e106488718e89f5464810a13d9,
                   "md4(message digest)", WAIT);

        // boundary corpus: "abcdefghijklmnopqrstuvwxyz", 26 bytes
        check_core(512'h00000000000000d00000000000000000000000000000000000000000000000000000000000807a797877767574737271706f6e6d6c6b6a696867666564636261,
                   128'h76543210fedcba9889abcdef01234567,
                   128'ha92d41df63eda8eecdbba58a301c9ed7,
                   "md4(abcdefghijklmnopqrstuvwxyz)", WAIT);

        // boundary corpus: "The quick brown fox jumps over the lazy dog", 43 bytes
        check_core(512'h000000000000015800000000000000000000000080676f6420797a616c20656874207265766f2073706d756a20786f66206e776f7262206b6369757120656854,
                   128'h76543210fedcba9889abcdef01234567,
                   128'h90aeaeab6247195c1811a86ba469ee1b,
                   "md4(The quick brown fox jumps over the lazy dog)", WAIT);

        // boundary corpus: "Passw0rd!", 9 bytes
        check_core(512'h00000000000000480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080216472307773736150,
                   128'h76543210fedcba9889abcdef01234567,
                   128'h8c0ee1384999eb72a55be6babd432840,
                   "md4(Passw0rd!)", WAIT);

        // boundary corpus: "quote\"and\\backslash", 19 bytes
        check_core(512'h0000000000000098000000000000000000000000000000000000000000000000000000000000000000000000806873616c736b6361625c646e612265746f7571,
                   128'h76543210fedcba9889abcdef01234567,
                   128'hc895d4d06336f5883f624e57dd66a3b1,
                   "md4(quote\"and\\backslash)", WAIT);

        // boundary corpus: "14 raw bytes, 0x74..0x73", 14 bytes
        check_core(512'h000000000000007000000000000000000000000000000000000000000000000000000000000000000000000000000000008073656361707320646e6109626174,
                   128'h76543210fedcba9889abcdef01234567,
                   128'h8554fd739572ee824d13c2aa185990d2,
                   "md4(14 raw bytes, 0x74..0x73)", WAIT);

        // 16 vectors, all generated.
