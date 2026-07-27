// MD5 compute shader — 64 passwords per workgroup
// Each invocation verifies one password against the target hash
// Fully unrolled rounds for constant-time execution

struct Candidate {
    password: array<u32, 16>,   // 64 bytes per password, padded
    len: u32,
}

struct HashResult {
    found: u32,     // 1 if match, 0 otherwise
    idx: u32,       // original index
    digest: vec4<u32>,  // MD5 digest
}

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<HashResult>;
@group(0) @binding(2) var<uniform> target: vec4<u32>;
@group(0) @binding(3) var<uniform> count: u32;

const S: array<u32, 64> = array(
    7u, 12u, 17u, 22u,  7u, 12u, 17u, 22u,  7u, 12u, 17u, 22u,  7u, 12u, 17u, 22u,
    5u,  9u, 14u, 20u,  5u,  9u, 14u, 20u,  5u,  9u, 14u, 20u,  5u,  9u, 14u, 20u,
    4u, 11u, 16u, 23u,  4u, 11u, 16u, 23u,  4u, 11u, 16u, 23u,  4u, 11u, 16u, 23u,
    6u, 10u, 15u, 21u,  6u, 10u, 15u, 21u,  6u, 10u, 15u, 21u,  6u, 10u, 15u, 21u,
);

const K: array<u32, 64> = array(
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
);

fn left_rotate(x: u32, c: u32) -> u32 {
    return (x << c) | (x >> (32u - c));
}

fn md5_round(a: u32, b: u32, c: u32, d: u32, k: u32, s: u32, t: u32, f: u32) -> u32 {
    return b + left_rotate(a + f + k + t, s);
}

fn md5_verify(password: array<u32, 16>, len: u32, target_digest: vec4<u32>) -> u32 {
    var a: u32 = 0x67452301u;
    var b: u32 = 0xefcdab89u;
    var c: u32 = 0x98badcfeu;
    var d: u32 = 0x10325476u;

    // Message padding
    var M: array<u32, 16> = password;
    let bit_len: u32 = len * 8u;
    let byte_idx: u32 = len / 4u;
    let byte_off: u32 = len % 4u;

    // Set padding bit
    let mask: u32 = 0xffffffffu << (byte_off * 8u);
    M[byte_idx] = (M[byte_idx] & mask) | (0x80u << (byte_off * 8u));

    if len < 56u {
        M[14u] = bit_len;
    }
    // For simplicity, handle only len < 56 case. Full version handles 2-block.

    // Round 0-15: F function
    var AA = a; var BB = b; var CC = c; var DD = d;
    var F: u32;

    // Unrolled 64 rounds
    // Round 0
    F = (BB & CC) | ((~BB) & DD);
    AA = BB + left_rotate(AA + F + K[0] + M[0], S[0]);
    // Round 1
    F = (AA & BB) | ((~AA) & CC);
    DD = AA + left_rotate(DD + F + K[1] + M[1], S[1]);
    // Round 2
    F = (DD & AA) | ((~DD) & BB);
    CC = DD + left_rotate(CC + F + K[2] + M[2], S[2]);
    // Round 3
    F = (CC & DD) | ((~CC) & AA);
    BB = CC + left_rotate(BB + F + K[3] + M[3], S[3]);

    // Round 4
    F = (BB & CC) | ((~BB) & DD);
    AA = BB + left_rotate(AA + F + K[4] + M[4], S[4]);
    // Round 5
    F = (AA & BB) | ((~AA) & CC);
    DD = AA + left_rotate(DD + F + K[5] + M[5], S[5]);
    // Round 6
    F = (DD & AA) | ((~DD) & BB);
    CC = DD + left_rotate(CC + F + K[6] + M[6], S[6]);
    // Round 7
    F = (CC & DD) | ((~CC) & AA);
    BB = CC + left_rotate(BB + F + K[7] + M[7], S[7]);

    // Round 8
    F = (BB & CC) | ((~BB) & DD);
    AA = BB + left_rotate(AA + F + K[8] + M[8], S[8]);
    // Round 9
    F = (AA & BB) | ((~AA) & CC);
    DD = AA + left_rotate(DD + F + K[9] + M[9], S[9]);
    // Round 10
    F = (DD & AA) | ((~DD) & BB);
    CC = DD + left_rotate(CC + F + K[10] + M[10], S[10]);
    // Round 11
    F = (CC & DD) | ((~CC) & AA);
    BB = CC + left_rotate(BB + F + K[11] + M[11], S[11]);

    // Round 12
    F = (BB & CC) | ((~BB) & DD);
    AA = BB + left_rotate(AA + F + K[12] + M[12], S[12]);
    // Round 13
    F = (AA & BB) | ((~AA) & CC);
    DD = AA + left_rotate(DD + F + K[13] + M[13], S[13]);
    // Round 14
    F = (DD & AA) | ((~DD) & BB);
    CC = DD + left_rotate(CC + F + K[14] + M[14], S[14]);
    // Round 15
    F = (CC & DD) | ((~CC) & AA);
    BB = CC + left_rotate(BB + F + K[15] + M[15], S[15]);

    // Round 16-31: G function
    // Round 16
    F = (BB & DD) | (CC & (~DD));
    AA = BB + left_rotate(AA + F + K[16] + M[1], S[16]);
    // Round 17
    F = (AA & CC) | (BB & (~CC));
    DD = AA + left_rotate(DD + F + K[17] + M[6], S[17]);
    // Round 18
    F = (DD & BB) | (AA & (~BB));
    CC = DD + left_rotate(CC + F + K[18] + M[11], S[18]);
    // Round 19
    F = (CC & AA) | (DD & (~AA));
    BB = CC + left_rotate(BB + F + K[19] + M[0], S[19]);

    // Round 20
    F = (BB & DD) | (CC & (~DD));
    AA = BB + left_rotate(AA + F + K[20] + M[5], S[20]);
    // Round 21
    F = (AA & CC) | (BB & (~CC));
    DD = AA + left_rotate(DD + F + K[21] + M[10], S[21]);
    // Round 22
    F = (DD & BB) | (AA & (~BB));
    CC = DD + left_rotate(CC + F + K[22] + M[15], S[22]);
    // Round 23
    F = (CC & AA) | (DD & (~AA));
    BB = CC + left_rotate(BB + F + K[23] + M[4], S[23]);

    // Round 24
    F = (BB & DD) | (CC & (~DD));
    AA = BB + left_rotate(AA + F + K[24] + M[9], S[24]);
    // Round 25
    F = (AA & CC) | (BB & (~CC));
    DD = AA + left_rotate(DD + F + K[25] + M[14], S[25]);
    // Round 26
    F = (DD & BB) | (AA & (~BB));
    CC = DD + left_rotate(CC + F + K[26] + M[3], S[26]);
    // Round 27
    F = (CC & AA) | (DD & (~AA));
    BB = CC + left_rotate(BB + F + K[27] + M[8], S[27]);

    // Round 28
    F = (BB & DD) | (CC & (~DD));
    AA = BB + left_rotate(AA + F + K[28] + M[13], S[28]);
    // Round 29
    F = (AA & CC) | (BB & (~CC));
    DD = AA + left_rotate(DD + F + K[29] + M[2], S[29]);
    // Round 30
    F = (DD & BB) | (AA & (~BB));
    CC = DD + left_rotate(CC + F + K[30] + M[7], S[30]);
    // Round 31
    F = (CC & AA) | (DD & (~AA));
    BB = CC + left_rotate(BB + F + K[31] + M[12], S[31]);

    // Round 32-47: H function (XOR)
    // Round 32
    F = BB ^ CC ^ DD;
    AA = BB + left_rotate(AA + F + K[32] + M[5], S[32]);
    // Round 33
    F = AA ^ BB ^ CC;
    DD = AA + left_rotate(DD + F + K[33] + M[8], S[33]);
    // Round 34
    F = DD ^ AA ^ BB;
    CC = DD + left_rotate(CC + F + K[34] + M[11], S[34]);
    // Round 35
    F = CC ^ DD ^ AA;
    BB = CC + left_rotate(BB + F + K[35] + M[14], S[35]);

    // Round 36
    F = BB ^ CC ^ DD;
    AA = BB + left_rotate(AA + F + K[36] + M[1], S[36]);
    // Round 37
    F = AA ^ BB ^ CC;
    DD = AA + left_rotate(DD + F + K[37] + M[4], S[37]);
    // Round 38
    F = DD ^ AA ^ BB;
    CC = DD + left_rotate(CC + F + K[38] + M[7], S[38]);
    // Round 39
    F = CC ^ DD ^ AA;
    BB = CC + left_rotate(BB + F + K[39] + M[10], S[39]);

    // Round 40
    F = BB ^ CC ^ DD;
    AA = BB + left_rotate(AA + F + K[40] + M[13], S[40]);
    // Round 41
    F = AA ^ BB ^ CC;
    DD = AA + left_rotate(DD + F + K[41] + M[0], S[41]);
    // Round 42
    F = DD ^ AA ^ BB;
    CC = DD + left_rotate(CC + F + K[42] + M[3], S[42]);
    // Round 43
    F = CC ^ DD ^ AA;
    BB = CC + left_rotate(BB + F + K[43] + M[6], S[43]);

    // Round 44
    F = BB ^ CC ^ DD;
    AA = BB + left_rotate(AA + F + K[44] + M[9], S[44]);
    // Round 45
    F = AA ^ BB ^ CC;
    DD = AA + left_rotate(DD + F + K[45] + M[12], S[45]);
    // Round 46
    F = DD ^ AA ^ BB;
    CC = DD + left_rotate(CC + F + K[46] + M[15], S[46]);
    // Round 47
    F = CC ^ DD ^ AA;
    BB = CC + left_rotate(BB + F + K[47] + M[2], S[47]);

    // Round 48-63: I function
    // Round 48
    F = CC ^ (BB | (~DD));
    AA = BB + left_rotate(AA + F + K[48] + M[0], S[48]);
    // Round 49
    F = BB ^ (AA | (~CC));
    DD = AA + left_rotate(DD + F + K[49] + M[7], S[49]);
    // Round 50
    F = AA ^ (DD | (~BB));
    CC = DD + left_rotate(CC + F + K[50] + M[14], S[50]);
    // Round 51
    F = DD ^ (CC | (~AA));
    BB = CC + left_rotate(BB + F + K[51] + M[5], S[51]);

    // Round 52
    F = CC ^ (BB | (~DD));
    AA = BB + left_rotate(AA + F + K[52] + M[12], S[52]);
    // Round 53
    F = BB ^ (AA | (~CC));
    DD = AA + left_rotate(DD + F + K[53] + M[3], S[53]);
    // Round 54
    F = AA ^ (DD | (~BB));
    CC = DD + left_rotate(CC + F + K[54] + M[10], S[54]);
    // Round 55
    F = DD ^ (CC | (~AA));
    BB = CC + left_rotate(BB + F + K[55] + M[1], S[55]);

    // Round 56
    F = CC ^ (BB | (~DD));
    AA = BB + left_rotate(AA + F + K[56] + M[8], S[56]);
    // Round 57
    F = BB ^ (AA | (~CC));
    DD = AA + left_rotate(DD + F + K[57] + M[15], S[57]);
    // Round 58
    F = AA ^ (DD | (~BB));
    CC = DD + left_rotate(CC + F + K[58] + M[6], S[58]);
    // Round 59
    F = DD ^ (CC | (~AA));
    BB = CC + left_rotate(BB + F + K[59] + M[13], S[59]);

    // Round 60
    F = CC ^ (BB | (~DD));
    AA = BB + left_rotate(AA + F + K[60] + M[4], S[60]);
    // Round 61
    F = BB ^ (AA | (~CC));
    DD = AA + left_rotate(DD + F + K[61] + M[11], S[61]);
    // Round 62
    F = AA ^ (DD | (~BB));
    CC = DD + left_rotate(CC + F + K[62] + M[2], S[62]);
    // Round 63
    F = DD ^ (CC | (~AA));
    BB = CC + left_rotate(BB + F + K[63] + M[9], S[63]);

    let digest = vec4(a + AA, b + BB, c + CC, d + DD);
    if digest == target_digest {
        return 1u;
    }
    return 0u;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if idx >= count { return; }

    let cand = candidates[idx];
    let found = md5_verify(cand.password, cand.len, target);
    results[idx] = HashResult(found, idx, vec4(0u));
}
