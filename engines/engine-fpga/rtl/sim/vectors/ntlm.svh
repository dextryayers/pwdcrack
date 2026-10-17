// GENERATED FILE. DO NOT EDIT.
// NTLMv1: MD4 over UTF-16-LE.
// Digest oracle: MD4 over UTF-16-LE, the MD4 held against RFC 1320.
//
// The block itself is not emitted here. ntlm_core builds the UTF-16-LE
// block from the ASCII password on the device, so the device side of
// that conversion is what this file tests.

        // NTLM of "<empty>", 0 characters
        check_ntlm("", 128'hc089c0e0d7593cb731e96ad1e0cfd631, "ntlm(<empty>)", WAIT);

        // NTLM of "a", 1 character
        check_ntlm("a", 128'h0499727cc468c7aaecc2e28191b06c18, "ntlm(a)", WAIT);

        // NTLM of "abc", 3 characters
        check_ntlm("abc", 128'h535e88d552b41cef66ecd06882a3fbe0, "ntlm(abc)", WAIT);

        // NTLM of "password", 8 characters
        check_ntlm("password", 128'h6c58b730d8bd06ad17b18feeeaf74688, "ntlm(password)", WAIT);

        // NTLM of "Passw0rd!", 9 characters
        check_ntlm("Passw0rd!", 128'h891897dc2dba957006fee883965c52fc, "ntlm(Passw0rd!)", WAIT);

        // NTLM of "12345", 5 characters
        check_ntlm("12345", 128'h5f3d140f495ce44199753dcd0f99217a, "ntlm(12345)", WAIT);

        // NTLM of "P@ssw0rd123", 11 characters
        check_ntlm("P@ssw0rd123", 128'hfd94af5430bb89e4685789f8cf1a5589, "ntlm(P@ssw0rd123)", WAIT);

        // 10 vectors, all generated.
