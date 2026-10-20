// SHA-1, one candidate per invocation. FIPS 180-4 section 6.1.
//
// Layout: see md5.wgsl. Message words are byte swapped to big endian before the
// schedule, and the state is byte swapped before comparison, because the target
// buffer holds digest bytes as little endian words for every hash type.

struct Candidate {
    data: array<u32, 16>,
    len: u32,
}

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<u32>;
@group(0) @binding(2) var<storage, read> expected: array<u32, 16>;
@group(0) @binding(3) var<uniform> count: u32;

fn rotl(x: u32, c: u32) -> u32 {
    return (x << c) | (x >> (32u - c));
}

fn bswap(x: u32) -> u32 {
    return (x >> 24u) | ((x >> 8u) & 0xff00u) | ((x << 8u) & 0xff0000u) | (x << 24u);
}

fn compress(st: ptr<function, array<u32, 5>>, m: array<u32, 16>) {
    var w: array<u32, 80>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        w[i] = bswap(m[i]);
    }
    for (var i = 16u; i < 80u; i = i + 1u) {
        w[i] = rotl(w[i - 3u] ^ w[i - 8u] ^ w[i - 14u] ^ w[i - 16u], 1u);
    }

    var a = (*st)[0];
    var b = (*st)[1];
    var c = (*st)[2];
    var d = (*st)[3];
    var e = (*st)[4];

    for (var i = 0u; i < 80u; i = i + 1u) {
        var f: u32;
        var k: u32;
        if (i < 20u) {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999u;
        } else if (i < 40u) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if (i < 60u) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6u;
        }
        let next = rotl(a, 5u) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl(b, 30u);
        b = a;
        a = next;
    }

    (*st)[0] = (*st)[0] + a;
    (*st)[1] = (*st)[1] + b;
    (*st)[2] = (*st)[2] + c;
    (*st)[3] = (*st)[3] + d;
    (*st)[4] = (*st)[4] + e;
}

fn compare(st: array<u32, 5>) -> bool {
    return bswap(st[0]) == expected[0]
        && bswap(st[1]) == expected[1]
        && bswap(st[2]) == expected[2]
        && bswap(st[3]) == expected[3]
        && bswap(st[4]) == expected[4];
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
    if (c.len < 56u) {
        w[15] = c.len * 8u;
    }
    w[31] = c.len * 8u;

    var st = array<u32, 5>(
        0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u,
    );

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
