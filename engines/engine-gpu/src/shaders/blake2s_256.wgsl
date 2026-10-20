// BLAKE2s-256, one candidate per invocation, unkeyed, single final block.
// RFC 7693. BLAKE2s uses 32 bit words and a 64 byte block, so a message of at
// most 64 bytes is exactly one final block.
//
// Layout: see md5.wgsl. The digest is eight little endian words.

struct Candidate {
    data: array<u32, 16>,
    len: u32,
}

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<u32>;
@group(0) @binding(2) var<storage, read> expected: array<u32, 16>;
@group(0) @binding(3) var<uniform> count: u32;

const SIGMA: array<u32, 160> = array(
    0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u,
    14u, 10u, 4u, 8u, 9u, 15u, 13u, 6u, 1u, 12u, 0u, 2u, 11u, 7u, 5u, 3u,
    11u, 8u, 12u, 0u, 5u, 2u, 15u, 13u, 10u, 14u, 3u, 6u, 7u, 1u, 9u, 4u,
    7u, 9u, 3u, 1u, 13u, 12u, 11u, 14u, 2u, 6u, 5u, 10u, 4u, 0u, 15u, 8u,
    9u, 0u, 5u, 7u, 2u, 4u, 10u, 15u, 14u, 1u, 11u, 12u, 6u, 8u, 3u, 13u,
    2u, 12u, 6u, 10u, 0u, 11u, 8u, 3u, 4u, 13u, 7u, 5u, 15u, 14u, 1u, 9u,
    12u, 5u, 1u, 15u, 14u, 13u, 4u, 10u, 0u, 7u, 6u, 3u, 9u, 2u, 8u, 11u,
    13u, 11u, 7u, 14u, 12u, 1u, 3u, 9u, 5u, 0u, 15u, 4u, 8u, 6u, 2u, 10u,
    6u, 15u, 14u, 9u, 11u, 3u, 0u, 8u, 12u, 2u, 13u, 7u, 1u, 4u, 10u, 5u,
    10u, 2u, 8u, 4u, 7u, 6u, 1u, 5u, 15u, 11u, 9u, 14u, 3u, 12u, 13u, 0u,
);

const IV: array<u32, 8> = array(
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
);

fn rotr(x: u32, c: u32) -> u32 {
    return (x >> c) | (x << (32u - c));
}

fn g(v: ptr<function, array<u32, 16>>, a: u32, b: u32, c: u32, d: u32, x: u32, y: u32) {
    (*v)[a] = (*v)[a] + (*v)[b] + x;
    (*v)[d] = rotr((*v)[d] ^ (*v)[a], 16u);
    (*v)[c] = (*v)[c] + (*v)[d];
    (*v)[b] = rotr((*v)[b] ^ (*v)[c], 12u);
    (*v)[a] = (*v)[a] + (*v)[b] + y;
    (*v)[d] = rotr((*v)[d] ^ (*v)[a], 8u);
    (*v)[c] = (*v)[c] + (*v)[d];
    (*v)[b] = rotr((*v)[b] ^ (*v)[c], 7u);
}

fn compare(h: array<u32, 8>) -> bool {
    for (var i = 0u; i < 8u; i = i + 1u) {
        if (h[i] != expected[i]) {
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

    var h = IV;
    // Parameter block: digest length 32, key length 0, fanout 1, depth 1.
    h[0] = h[0] ^ 0x01010020u;

    var v: array<u32, 16>;
    for (var i = 0u; i < 8u; i = i + 1u) {
        v[i] = h[i];
        v[i + 8u] = IV[i];
    }
    // This is the only and final block: t0 = message length, t1 = 0, and the
    // final block flag is all ones.
    v[12] = v[12] ^ c.len;
    v[13] = v[13] ^ 0u;
    v[14] = v[14] ^ 0xffffffffu;

    var m: array<u32, 16>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        m[i] = c.data[i];
    }

    for (var r = 0u; r < 10u; r = r + 1u) {
        let o = 16u * r;
        g(&v, 0u, 4u, 8u, 12u, m[SIGMA[o]], m[SIGMA[o + 1u]]);
        g(&v, 1u, 5u, 9u, 13u, m[SIGMA[o + 2u]], m[SIGMA[o + 3u]]);
        g(&v, 2u, 6u, 10u, 14u, m[SIGMA[o + 4u]], m[SIGMA[o + 5u]]);
        g(&v, 3u, 7u, 11u, 15u, m[SIGMA[o + 6u]], m[SIGMA[o + 7u]]);
        g(&v, 0u, 5u, 10u, 15u, m[SIGMA[o + 8u]], m[SIGMA[o + 9u]]);
        g(&v, 1u, 6u, 11u, 12u, m[SIGMA[o + 10u]], m[SIGMA[o + 11u]]);
        g(&v, 2u, 7u, 8u, 13u, m[SIGMA[o + 12u]], m[SIGMA[o + 13u]]);
        g(&v, 3u, 4u, 9u, 14u, m[SIGMA[o + 14u]], m[SIGMA[o + 15u]]);
    }

    for (var i = 0u; i < 8u; i = i + 1u) {
        h[i] = h[i] ^ v[i] ^ v[i + 8u];
    }

    results[idx] = select(0u, 1u, compare(h));
}
