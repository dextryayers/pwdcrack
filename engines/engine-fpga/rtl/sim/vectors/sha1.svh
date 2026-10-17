// GENERATED FILE. DO NOT EDIT.
// SHA-1 (FIPS 180-4): single block vectors.
// Digest oracle: hashlib.sha1.
// Padding oracle: struct.pack in scripts/gen-rtl-vectors.py.
//
// Every block and every digest below is emitted, not transcribed. A
// testbench that builds its own block from the message reintroduces the
// part select with an arithmetic base that this simulator miscompiles;
// see the header of scripts/gen-rtl-vectors.py.

        // boundary corpus: "<empty>", 0 bytes
        check_core(512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'hafd80709956018903255bfef5e6b4b0dda39a3ee,
                   "sha1(<empty>)", WAIT);

        // boundary corpus: "y", 1 byte
        check_core(512'h00000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000079800000,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h2a39974ae4b4d4c7298d96242977c76195cb0bfd,
                   "sha1(y)", WAIT);

        // boundary corpus: "yyy", 3 bytes
        check_core(512'h00000000180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000079797980,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'ha231779c0987b98f91d85b9a2b2d5f6718615471,
                   "sha1(yyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyy", 14 bytes
        check_core(512'h00000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000079798000797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h0b6014f386325964f9b8404740ab2d749a55864f,
                   "sha1(yyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyy", 27 bytes
        check_core(512'h00000000d80000000000000000000000000000000000000000000000000000000000000079797980797979797979797979797979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'hf31c464a4aebf3b1f6f6630e3484149cf77a1cb7,
                   "sha1(yyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 43 bytes
        check_core(512'h00000000580100000000000000000000000000007979798079797979797979797979797979797979797979797979797979797979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h5313c32e28624b01e0646cc78788e70fea1b943c,
                   "sha1(yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 54 bytes
        check_core(512'h00000000b00100007979800079797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h4d7138571f4f136db57cdb75df0f6d506af1fbd1,
                   "sha1(yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 55 bytes
        check_core(512'h00000000b80100007979798079797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'hf78225bbd129390bd9870c1697bc2a23f3c8b47e,
                   "sha1(yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "a", 1 byte
        check_core(512'h00000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000061800000,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h377667b8b9eaeaeae15d1ddcfaa5a7fc86f7e437,
                   "sha1(a)", WAIT);

        // boundary corpus: "abc", 3 bytes
        check_core(512'h00000000180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000061626380,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h9cd0d89d7850c26cba3e25714706816aa9993e36,
                   "sha1(abc)", WAIT);

        // boundary corpus: "message digest", 14 bytes
        check_core(512'h0000000070000000000000000000000000000000000000000000000000000000000000000000000000000000000000007374800064696765616765206d657373,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h1d16aae30a47231c4d5fa029da8be899c12252ce,
                   "sha1(message digest)", WAIT);

        // boundary corpus: "abcdefghijklmnopqrstuvwxyz", 26 bytes
        check_core(512'h00000000d000000000000000000000000000000000000000000000000000000000000000797a800075767778717273746d6e6f70696a6b6c6566676861626364,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h240d3a89f2a19d84ca04ce378cf9657032d10c7b,
                   "sha1(abcdefghijklmnopqrstuvwxyz)", WAIT);

        // boundary corpus: "The quick brown fox jumps over the lazy dog", 43 bytes
        check_core(512'h0000000058010000000000000000000000000000646f6780617a79206865206c6572207473206f766a756d70666f78206f776e206b2062727175696354686520,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h1b93eb12bb76e739ed849ee17a2d28fc2fd4e1c6,
                   "sha1(The quick brown fox jumps over the lazy dog)", WAIT);

        // boundary corpus: "Passw0rd!", 9 bytes
        check_core(512'h00000000480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000218000007730726450617373,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h494beb0de3c3acd2160f9f60e7b0bf9df4a69973,
                   "sha1(Passw0rd!)", WAIT);

        // boundary corpus: "quote\"and\\backslash", 19 bytes
        check_core(512'h000000009800000000000000000000000000000000000000000000000000000000000000000000000000000061736880636b736c645c62616522616e71756f74,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'hdcea7612424b726ab1d85fe79d4084ceafa2de98,
                   "sha1(quote"and\backslash)", WAIT);

        // boundary corpus: "14 raw bytes, 0x74..0x73", 14 bytes
        check_core(512'h0000000070000000000000000000000000000000000000000000000000000000000000000000000000000000000000006573800073706163616e642074616209,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'ha7fc20710720598f29617d865f7d3edb1517ae11,
                   "sha1(14 raw bytes, 0x74..0x73)", WAIT);

        // 16 vectors, all generated.
