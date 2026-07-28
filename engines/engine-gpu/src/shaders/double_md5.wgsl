// Double MD5: MD5(MD5(password))

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

fn rol(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }

fn md5_f(i: u32, b: u32, c: u32, d: u32) -> u32 {
    if (i < 16u) { return (b & c) | ((~b) & d); }
    else if (i < 32u) { return (b & d) | (c & (~d)); }
    else if (i < 48u) { return b ^ c ^ d; }
    else { return c ^ (b | (~d)); }
}

fn md5_g(i: u32) -> u32 {
    if (i < 16u) { return i; }
    else if (i < 32u) { return (5u * i + 1u) & 15u; }
    else if (i < 48u) { return (3u * i + 5u) & 15u; }
    else { return (7u * i) & 15u; }
}

const K: array<u32, 64> = array(
    0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
    0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
    0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
    0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
    0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
    0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
    0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
    0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u,
);
const S: array<u32, 64> = array(
    7u,12u,17u,22u,7u,12u,17u,22u,7u,12u,17u,22u,7u,12u,17u,22u,
    5u,9u,14u,20u,5u,9u,14u,20u,5u,9u,14u,20u,5u,9u,14u,20u,
    4u,11u,16u,23u,4u,11u,16u,23u,4u,11u,16u,23u,4u,11u,16u,23u,
    6u,10u,15u,21u,6u,10u,15u,21u,6u,10u,15u,21u,6u,10u,15u,21u,
);

fn md5_hash(msg: array<u32, 16>, len: u32) -> array<u32, 4> {
    var M: array<u32, 16> = msg;
    let bit_len = len * 8u;
    let byte_off = len % 4u;
    let word_idx2 = len / 4u;
    let mask = 0xffffffffu << (byte_off * 8u);
    M[word_idx2] = (M[word_idx2] & mask) | (0x80u << (byte_off * 8u));
    if (len < 56u) { M[14u] = bit_len; }

    var a = 0x67452301u; var b = 0xefcdab89u;
    var c = 0x98badcfeu; var d = 0x10325476u;

    for (var i: u32 = 0u; i < 64u; i++) {
        let f = md5_f(i, b, c, d);
        let g = md5_g(i);
        let temp = d;
        d = c; c = b; b = b + rol(a + f + K[i] + M[g], S[i]);
        a = temp;
    }

    var result: array<u32, 4>;
    result[0] = 0x67452301u + a; result[1] = 0xefcdab89u + b;
    result[2] = 0x98badcfeu + c; result[3] = 0x10325476u + d;
    return result;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if (idx >= config.pcount) { return; }

    var pw: array<u8, 64>;
    let base = idx * 16u;
    for (var i: u32 = 0u; i < 64u; i++) {
        pw[i] = u8((input[base + i / 4u] >> ((i % 4u) * 8u)) & 0xffu);
    }
    var len: u32 = 0u;
    for (var i: u32 = 0u; i < 64u; i++) { if (pw[i] == 0u) { len = i; break; } }
    if (len == 0u && pw[0] != 0u) { len = 64u; }

    var msg: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { msg[i] = 0u; }
    for (var i: u32 = 0u; i < len; i++) {
        let word_idx = i / 4u;
        let byte_idx = i % 4u;
        msg[word_idx] |= u32(pw[i]) << (byte_idx * 8u);
    }

    let first = md5_hash(msg, len);

    var second_msg: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { second_msg[i] = 0u; }
    for (var i: u32 = 0u; i < 4u; i++) { second_msg[i] = first[i]; }

    let second = md5_hash(second_msg, 16u);

    let out_base = idx * 4u;
    output[out_base] = second[0]; output[out_base + 1u] = second[1];
    output[out_base + 2u] = second[2]; output[out_base + 3u] = second[3];
}
