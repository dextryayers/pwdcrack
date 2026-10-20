// BLAKE2b-512, one candidate per invocation, unkeyed, single final block.
// RFC 7693. 64 bit words are held as two u32 halves for the same reason as
// sha512.wgsl.
//
// Layout: see md5.wgsl. A message of at most 64 bytes fits in one 128 byte
// block, so every candidate is a final block.

struct Candidate {
    data: array<u32, 16>,
    len: u32,
}

struct U64 {
    hi: u32,
    lo: u32,
}

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<u32>;
@group(0) @binding(2) var<storage, read> expected: array<u32, 16>;
@group(0) @binding(3) var<uniform> count: u32;

const SIGMA: array<u32, 192> = array(
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
    0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u,
    14u, 10u, 4u, 8u, 9u, 15u, 13u, 6u, 1u, 12u, 0u, 2u, 11u, 7u, 5u, 3u,
);

const IV: array<U64, 8> = array(
    U64(0x6a09e667u, 0xf3bcc908u), U64(0xbb67ae85u, 0x84caa73bu),
    U64(0x3c6ef372u, 0xfe94f82bu), U64(0xa54ff53au, 0x5f1d36f1u),
    U64(0x510e527fu, 0xade682d1u), U64(0x9b05688cu, 0x2b3e6c1fu),
    U64(0x1f83d9abu, 0xfb41bd6bu), U64(0x5be0cd19u, 0x137e2179u),
);

fn add(a: U64, b: U64) -> U64 {
    let lo = a.lo + b.lo;
    let carry = select(0u, 1u, lo < a.lo);
    return U64(a.hi + b.hi + carry, lo);
}

fn xor(a: U64, b: U64) -> U64 {
    return U64(a.hi ^ b.hi, a.lo ^ b.lo);
}

fn rotr(a: U64, n: u32) -> U64 {
    if (n == 0u) {
        return a;
    } else if (n < 32u) {
        return U64((a.hi >> n) | (a.lo << (32u - n)), (a.lo >> n) | (a.hi << (32u - n)));
    } else if (n == 32u) {
        return U64(a.lo, a.hi);
    }
    let m = n - 32u;
    return U64((a.lo >> m) | (a.hi << (32u - m)), (a.hi >> m) | (a.lo << (32u - m)));
}

fn g(v: ptr<function, array<U64, 16>>, a: u32, b: u32, c: u32, d: u32, x: U64, y: U64) {
    (*v)[a] = add(add((*v)[a], (*v)[b]), x);
    (*v)[d] = rotr(xor((*v)[d], (*v)[a]), 32u);
    (*v)[c] = add((*v)[c], (*v)[d]);
    (*v)[b] = rotr(xor((*v)[b], (*v)[c]), 24u);
    (*v)[a] = add(add((*v)[a], (*v)[b]), y);
    (*v)[d] = rotr(xor((*v)[d], (*v)[a]), 16u);
    (*v)[c] = add((*v)[c], (*v)[d]);
    (*v)[b] = rotr(xor((*v)[b], (*v)[c]), 63u);
}

fn compare(h: array<U64, 8>) -> bool {
    for (var i = 0u; i < 8u; i = i + 1u) {
        if (h[i].lo != expected[2u * i] || h[i].hi != expected[2u * i + 1u]) {
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
    // Parameter block: digest length 64, key length 0, fanout 1, depth 1.
    h[0] = xor(h[0], U64(0x00000000u, 0x01010040u));

    var v: array<U64, 16>;
    for (var i = 0u; i < 8u; i = i + 1u) {
        v[i] = h[i];
        v[i + 8u] = IV[i];
    }
    // Total bytes compressed so far is the message length, and this is the last
    // block, so t0 = len, t1 = 0, and the final block flag is all ones.
    v[12] = xor(v[12], U64(0u, c.len));
    v[14] = xor(v[14], U64(0xffffffffu, 0xffffffffu));

    // Build the 128 byte block: the message, a 0x80 terminator, then zeros. The
    // length is carried in v[12], not in the block, so there is no length field.
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

    var m: array<U64, 16>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        m[i] = U64(w[2u * i + 1u], w[2u * i]);
    }

    for (var r = 0u; r < 12u; r = r + 1u) {
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
        h[i] = xor(h[i], xor(v[i], v[i + 8u]));
    }

    results[idx] = select(0u, 1u, compare(h));
}
