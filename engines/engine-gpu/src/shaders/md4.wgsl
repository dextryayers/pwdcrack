// MD4, one candidate per invocation. NTLM uses this same kernel over UTF-16LE
// input; the host does the encoding and the pipeline is registered as "ntlm".
//
// Layout: see md5.wgsl.

struct Candidate {
    data: array<u32, 16>,
    len: u32,
}

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<u32>;
@group(0) @binding(2) var<storage, read> expected: array<u32, 16>;
@group(0) @binding(3) var<uniform> count: u32;

// Message word order and rotation amounts per round, RFC 1320 section 3.4.
const O2: array<u32, 16> = array(
    0u, 4u, 8u, 12u, 1u, 5u, 9u, 13u, 2u, 6u, 10u, 14u, 3u, 7u, 11u, 15u,
);
const O3: array<u32, 16> = array(
    0u, 8u, 4u, 12u, 2u, 10u, 6u, 14u, 1u, 9u, 5u, 13u, 3u, 11u, 7u, 15u,
);
const S1: array<u32, 4> = array(3u, 7u, 11u, 19u);
const S2: array<u32, 4> = array(3u, 5u, 9u, 13u);
const S3: array<u32, 4> = array(3u, 9u, 11u, 15u);

fn rotl(x: u32, c: u32) -> u32 {
    return (x << c) | (x >> (32u - c));
}

fn f(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) | ((~x) & z);
}

fn g(x: u32, y: u32, z: u32) -> u32 {
    return (x & y) | (x & z) | (y & z);
}

fn h(x: u32, y: u32, z: u32) -> u32 {
    return x ^ y ^ z;
}

fn compress(st: ptr<function, array<u32, 4>>, m: array<u32, 16>) {
    var a = (*st)[0];
    var b = (*st)[1];
    var c = (*st)[2];
    var d = (*st)[3];

    for (var j = 0u; j < 16u; j = j + 4u) {
        a = rotl(a + f(b, c, d) + m[j], S1[0]);
        d = rotl(d + f(a, b, c) + m[j + 1u], S1[1]);
        c = rotl(c + f(d, a, b) + m[j + 2u], S1[2]);
        b = rotl(b + f(c, d, a) + m[j + 3u], S1[3]);
    }
    for (var j = 0u; j < 16u; j = j + 4u) {
        a = rotl(a + g(b, c, d) + m[O2[j]] + 0x5a827999u, S2[0]);
        d = rotl(d + g(a, b, c) + m[O2[j + 1u]] + 0x5a827999u, S2[1]);
        c = rotl(c + g(d, a, b) + m[O2[j + 2u]] + 0x5a827999u, S2[2]);
        b = rotl(b + g(c, d, a) + m[O2[j + 3u]] + 0x5a827999u, S2[3]);
    }
    for (var j = 0u; j < 16u; j = j + 4u) {
        a = rotl(a + h(b, c, d) + m[O3[j]] + 0x6ed9eba1u, S3[0]);
        d = rotl(d + h(a, b, c) + m[O3[j + 1u]] + 0x6ed9eba1u, S3[1]);
        c = rotl(c + h(d, a, b) + m[O3[j + 2u]] + 0x6ed9eba1u, S3[2]);
        b = rotl(b + h(c, d, a) + m[O3[j + 3u]] + 0x6ed9eba1u, S3[3]);
    }

    (*st)[0] = (*st)[0] + a;
    (*st)[1] = (*st)[1] + b;
    (*st)[2] = (*st)[2] + c;
    (*st)[3] = (*st)[3] + d;
}

fn compare(st: array<u32, 4>) -> bool {
    return st[0] == expected[0] && st[1] == expected[1]
        && st[2] == expected[2] && st[3] == expected[3];
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if (idx >= count) {
        return;
    }

    let c = candidates[idx];

    var w: array<u32, 32>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        w[i] = c.data[i];
    }
    for (var i = 16u; i < 32u; i = i + 1u) {
        w[i] = 0u;
    }
    let byte_index = c.len / 4u;
    let byte_offset = c.len % 4u;
    let keep = (1u << (byte_offset * 8u)) - 1u;
    w[byte_index] = (w[byte_index] & keep) | (0x80u << (byte_offset * 8u));
    // MD5 family length field: 64 bit little endian, so the low word goes in
    // word 14 of the block and the high word in word 15.
    if (c.len < 56u) {
        w[14] = c.len * 8u;
    }
    w[30] = c.len * 8u;

    var st = array<u32, 4>(0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u);

    var m: array<u32, 16>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        m[i] = w[i];
    }
    compress(&st, m);

    if (c.len >= 56u) {
        for (var i = 0u; i < 16u; i = i + 1u) {
            m[i] = w[16u + i];
        }
        compress(&st, m);
    }

    results[idx] = select(0u, 1u, compare(st));
}
