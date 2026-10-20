// SHA-256, one candidate per invocation. FIPS 180-4 section 6.2.
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

const K: array<u32, 64> = array(
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
);

fn rotr(x: u32, c: u32) -> u32 {
    return (x >> c) | (x << (32u - c));
}

fn bswap(x: u32) -> u32 {
    return (x >> 24u) | ((x >> 8u) & 0xff00u) | ((x << 8u) & 0xff0000u) | (x << 24u);
}

fn compress(st: ptr<function, array<u32, 8>>, m: array<u32, 16>) {
    var w: array<u32, 64>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        w[i] = bswap(m[i]);
    }
    for (var i = 16u; i < 64u; i = i + 1u) {
        let s0 = rotr(w[i - 15u], 7u) ^ rotr(w[i - 15u], 18u) ^ (w[i - 15u] >> 3u);
        let s1 = rotr(w[i - 2u], 17u) ^ rotr(w[i - 2u], 19u) ^ (w[i - 2u] >> 10u);
        w[i] = w[i - 16u] + s0 + w[i - 7u] + s1;
    }

    var a = (*st)[0];
    var b = (*st)[1];
    var c = (*st)[2];
    var d = (*st)[3];
    var e = (*st)[4];
    var f = (*st)[5];
    var g = (*st)[6];
    var h = (*st)[7];

    for (var i = 0u; i < 64u; i = i + 1u) {
        let s1 = rotr(e, 6u) ^ rotr(e, 11u) ^ rotr(e, 25u);
        let ch = (e & f) ^ ((~e) & g);
        let t1 = h + s1 + ch + K[i] + w[i];
        let s0 = rotr(a, 2u) ^ rotr(a, 13u) ^ rotr(a, 22u);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    (*st)[0] = (*st)[0] + a;
    (*st)[1] = (*st)[1] + b;
    (*st)[2] = (*st)[2] + c;
    (*st)[3] = (*st)[3] + d;
    (*st)[4] = (*st)[4] + e;
    (*st)[5] = (*st)[5] + f;
    (*st)[6] = (*st)[6] + g;
    (*st)[7] = (*st)[7] + h;
}

fn compare(st: array<u32, 8>) -> bool {
    for (var i = 0u; i < 8u; i = i + 1u) {
        if (bswap(st[i]) != expected[i]) {
            return false;
        }
    }
    return true;
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

    var st = array<u32, 8>(
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
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
