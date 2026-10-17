// GENERATED FILE. DO NOT EDIT.
// RIPEMD-160: single block vectors.
// Digest oracle: hashlib ripemd160.
// Padding oracle: struct.pack in scripts/gen-rtl-vectors.py.
//
// Every block and every digest below is emitted, not transcribed. A
// testbench that builds its own block from the message reintroduces the
// part select with an arithmetic base that this simulator miscompiles;
// see the header of scripts/gen-rtl-vectors.py.

        // boundary corpus: "<empty>", 0 bytes
        check_core(512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h318d25b248f5e87e9708286154fce9c5a585119c,
                   "ripemd160(<empty>)", WAIT);

        // boundary corpus: "y", 1 byte
        check_core(512'h00000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008079,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h538d131217eeaa71bc3dd29fe1426b1fc681ce2a,
                   "ripemd160(y)", WAIT);

        // boundary corpus: "yyy", 3 bytes
        check_core(512'h00000000000000180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'ha1fa3ed7edc60137ef9b3626b87b5f9be740d1b3,
                   "ripemd160(yyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyy", 14 bytes
        check_core(512'h00000000000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000807979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'ha3c84f728444a11bfa807a26cd7ff37012769dd1,
                   "ripemd160(yyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyy", 27 bytes
        check_core(512'h00000000000000d80000000000000000000000000000000000000000000000000000000080797979797979797979797979797979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h90b29b774a05b232eee7295a5eb8c2d724fd83b4,
                   "ripemd160(yyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 43 bytes
        check_core(512'h00000000000001580000000000000000000000008079797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h0f8e7f20bd25d783e84524cec3f8dc30b542edd4,
                   "ripemd160(yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 54 bytes
        check_core(512'h00000000000001b00080797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h2475ee6e76aee627fa54f2a51935a713b201a6f1,
                   "ripemd160(yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 55 bytes
        check_core(512'h00000000000001b88079797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h68c2fc9469f759db7fe10efdb6cdacef0c907c96,
                   "ripemd160(yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "a", 1 byte
        check_core(512'h00000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008061,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'hfe7f465a83dcf4e67b34aedae93e6b252d9ddc0b,
                   "ripemd160(a)", WAIT);

        // boundary corpus: "abc", 3 bytes
        check_core(512'h00000000000000180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080636261,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'hfc0b5af187b0c6988e4a049b7a985de0f708b28e,
                   "ripemd160(abc)", WAIT);

        // boundary corpus: "message digest", 14 bytes
        check_core(512'h0000000000000070000000000000000000000000000000000000000000000000000000000000000000000000000000000080747365676964206567617373656d,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h365f5921fa5fa823b181b872e5fad249ef89065d,
                   "ripemd160(message digest)", WAIT);

        // boundary corpus: "abcdefghijklmnopqrstuvwxyz", 26 bytes
        check_core(512'h00000000000000d00000000000000000000000000000000000000000000000000000000000807a797877767574737271706f6e6d6c6b6a696867666564636261,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'hbc8d70b365289d5bebdcbb561b2c699c10271cf7,
                   "ripemd160(abcdefghijklmnopqrstuvwxyz)", WAIT);

        // boundary corpus: "The quick brown fox jumps over the lazy dog", 43 bytes
        check_core(512'h000000000000015800000000000000000000000080676f6420797a616c20656874207265766f2073706d756a20786f66206e776f7262206b6369757120656854,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h3bddf91c67ad719596d4edd7d97bb78df632f337,
                   "ripemd160(The quick brown fox jumps over the lazy dog)", WAIT);

        // boundary corpus: "Passw0rd!", 9 bytes
        check_core(512'h00000000000000480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080216472307773736150,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h64ef73879e93ca696cb4792a7806b5527369ff86,
                   "ripemd160(Passw0rd!)", WAIT);

        // boundary corpus: "quote\"and\\backslash", 19 bytes
        check_core(512'h0000000000000098000000000000000000000000000000000000000000000000000000000000000000000000806873616c736b6361625c646e612265746f7571,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h511bb4dc46c1b51d57f18a220ef40a87189b72b6,
                   "ripemd160(quote\"and\\backslash)", WAIT);

        // boundary corpus: "14 raw bytes, 0x74..0x73", 14 bytes
        check_core(512'h000000000000007000000000000000000000000000000000000000000000000000000000000000000000000000000000008073656361707320646e6109626174,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h6b003e20fe72a77a86f005911e43fd0be0d28fc9,
                   "ripemd160(14 raw bytes, 0x74..0x73)", WAIT);

        // 16 vectors, all generated.
