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
        check_core(512'h00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'hb2258d317ee8f54861280897c5e9fc549c1185a5,
                   "ripemd160(<empty>)", WAIT);

        // boundary corpus: "y", 1 byte
        check_core(512'h00000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000079800000,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h12138d5371aaee179fd23dbc1f6b42e12ace81c6,
                   "ripemd160(y)", WAIT);

        // boundary corpus: "yyy", 3 bytes
        check_core(512'h00000000180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000079797980,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'hd73efaa13701c6ed26369bef9b5f7bb8b3d140e7,
                   "ripemd160(yyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyy", 14 bytes
        check_core(512'h00000000700000000000000000000000000000000000000000000000000000000000000000000000000000000000000079798000797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h724fc8a31ba14484267a80fa70f37fcdd19d7612,
                   "ripemd160(yyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyy", 27 bytes
        check_core(512'h00000000d80000000000000000000000000000000000000000000000000000000000000079797980797979797979797979797979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h779bb29032b2054a5a29e7eed7c2b85eb483fd24,
                   "ripemd160(yyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 43 bytes
        check_core(512'h00000000580100000000000000000000000000007979798079797979797979797979797979797979797979797979797979797979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h207f8e0f83d725bdce2445e830dcf8c3d4ed42b5,
                   "ripemd160(yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 54 bytes
        check_core(512'h00000000b00100007979800079797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h6eee752427e6ae76a5f254fa13a73519f1a601b2,
                   "ripemd160(yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy", 55 bytes
        check_core(512'h00000000b80100007979798079797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979797979,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h94fcc268db59f769fd0ee17fefaccdb6967c900c,
                   "ripemd160(yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy)", WAIT);

        // boundary corpus: "a", 1 byte
        check_core(512'h00000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000061800000,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h5a467ffee6f4dc83daae347b256b3ee90bdc9d2d,
                   "ripemd160(a)", WAIT);

        // boundary corpus: "abc", 3 bytes
        check_core(512'h00000000180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000061626380,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'hf15a0bfc98c6b0879b044a8ee05d987a8eb208f7,
                   "ripemd160(abc)", WAIT);

        // boundary corpus: "message digest", 14 bytes
        check_core(512'h0000000070000000000000000000000000000000000000000000000000000000000000000000000000000000000000007374800064696765616765206d657373,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h21595f3623a85ffa72b881b149d2fae55d0689ef,
                   "ripemd160(message digest)", WAIT);

        // boundary corpus: "abcdefghijklmnopqrstuvwxyz", 26 bytes
        check_core(512'h00000000d000000000000000000000000000000000000000000000000000000000000000797a800075767778717273746d6e6f70696a6b6c6566676861626364,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'hb3708dbc5b9d286556bbdceb9c692c1bf71c2710,
                   "ripemd160(abcdefghijklmnopqrstuvwxyz)", WAIT);

        // boundary corpus: "The quick brown fox jumps over the lazy dog", 43 bytes
        check_core(512'h0000000058010000000000000000000000000000646f6780617a79206865206c6572207473206f766a756d70666f78206f776e206b2062727175696354686520,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h1cf9dd3b9571ad67d7edd4968db77bd937f332f6,
                   "ripemd160(The quick brown fox jumps over the lazy dog)", WAIT);

        // boundary corpus: "Passw0rd!", 9 bytes
        check_core(512'h00000000480000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000218000007730726450617373,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h8773ef6469ca939e2a79b46c52b5067886ff6973,
                   "ripemd160(Passw0rd!)", WAIT);

        // boundary corpus: "quote\"and\\backslash", 19 bytes
        check_core(512'h000000009800000000000000000000000000000000000000000000000000000000000000000000000000000061736880636b736c645c62616522616e71756f74,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'hdcb41b511db5c146228af157870af40eb6729b18,
                   "ripemd160(quote"and\backslash)", WAIT);

        // boundary corpus: "14 raw bytes, 0x74..0x73", 14 bytes
        check_core(512'h0000000070000000000000000000000000000000000000000000000000000000000000000000000000000000000000006573800073706163616e642074616209,
                   160'hc3d2e1f01032547698badcfeefcdab8967452301,
                   160'h203e006b7aa772fe9105f0860bfd431ec98fd2e0,
                   "ripemd160(14 raw bytes, 0x74..0x73)", WAIT);

        // 16 vectors, all generated.
