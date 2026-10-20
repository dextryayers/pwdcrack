// RIPEMD-160, one candidate per invocation. Dobbertin, Bosselaers, Preneel,
// "RIPEMD-160: A Strengthened Version of RIPEMD", 1996.
//
// Layout: see md5.wgsl. Input and digest are little endian.

struct Candidate {
    data: array<u32, 16>,
    len: u32,
}

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<u32>;
@group(0) @binding(2) var<storage, read> expected: array<u32, 16>;
@group(0) @binding(3) var<uniform> count: u32;

const R1: array<u32, 16> = array(0u, 1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 15u);
const R2: array<u32, 16> = array(7u, 4u, 13u, 1u, 10u, 6u, 15u, 3u, 12u, 0u, 9u, 5u, 2u, 14u, 11u, 8u);
const R3: array<u32, 16> = array(3u, 10u, 14u, 4u, 9u, 15u, 8u, 1u, 2u, 7u, 0u, 6u, 13u, 11u, 5u, 12u);
const R4: array<u32, 16> = array(1u, 9u, 11u, 10u, 0u, 8u, 12u, 4u, 13u, 3u, 7u, 15u, 14u, 5u, 6u, 2u);
const R5: array<u32, 16> = array(4u, 0u, 5u, 9u, 7u, 12u, 2u, 10u, 14u, 1u, 3u, 8u, 11u, 6u, 15u, 13u);

const RP1: array<u32, 16> = array(5u, 14u, 7u, 0u, 9u, 2u, 11u, 4u, 13u, 6u, 15u, 8u, 1u, 10u, 3u, 12u);
const RP2: array<u32, 16> = array(6u, 11u, 3u, 7u, 0u, 13u, 5u, 10u, 14u, 15u, 8u, 12u, 4u, 9u, 1u, 2u);
const RP3: array<u32, 16> = array(15u, 5u, 1u, 3u, 7u, 14u, 6u, 9u, 11u, 8u, 12u, 2u, 10u, 0u, 4u, 13u);
const RP4: array<u32, 16> = array(8u, 6u, 4u, 1u, 3u, 11u, 15u, 0u, 5u, 12u, 2u, 13u, 9u, 7u, 10u, 14u);
const RP5: array<u32, 16> = array(12u, 15u, 10u, 4u, 1u, 5u, 8u, 7u, 6u, 2u, 13u, 14u, 0u, 3u, 9u, 11u);

const S1: array<u32, 16> = array(11u, 14u, 15u, 12u, 5u, 8u, 7u, 9u, 11u, 13u, 14u, 15u, 6u, 7u, 9u, 8u);
const S2: array<u32, 16> = array(7u, 6u, 8u, 13u, 11u, 9u, 7u, 15u, 7u, 12u, 15u, 9u, 11u, 7u, 13u, 12u);
const S3: array<u32, 16> = array(11u, 13u, 6u, 7u, 14u, 9u, 13u, 15u, 14u, 8u, 13u, 6u, 5u, 12u, 7u, 5u);
const S4: array<u32, 16> = array(11u, 12u, 14u, 15u, 14u, 15u, 9u, 8u, 9u, 14u, 5u, 6u, 8u, 6u, 5u, 12u);
const S5: array<u32, 16> = array(9u, 15u, 5u, 11u, 6u, 8u, 13u, 12u, 5u, 12u, 13u, 14u, 11u, 8u, 5u, 6u);

const SP1: array<u32, 16> = array(8u, 9u, 9u, 11u, 13u, 15u, 15u, 5u, 7u, 7u, 8u, 11u, 14u, 14u, 12u, 6u);
const SP2: array<u32, 16> = array(9u, 13u, 15u, 7u, 12u, 8u, 9u, 11u, 7u, 7u, 12u, 7u, 6u, 15u, 13u, 11u);
const SP3: array<u32, 16> = array(9u, 7u, 15u, 11u, 8u, 6u, 6u, 14u, 12u, 13u, 5u, 14u, 13u, 13u, 7u, 5u);
const SP4: array<u32, 16> = array(15u, 5u, 8u, 11u, 14u, 14u, 6u, 14u, 6u, 9u, 12u, 9u, 12u, 5u, 15u, 8u);
const SP5: array<u32, 16> = array(8u, 5u, 12u, 9u, 12u, 5u, 14u, 6u, 8u, 13u, 6u, 5u, 15u, 13u, 11u, 11u);

fn rotl(x: u32, c: u32) -> u32 {
    return (x << c) | (x >> (32u - c));
}

fn f1(x: u32, y: u32, z: u32) -> u32 { return x ^ y ^ z; }
fn f2(x: u32, y: u32, z: u32) -> u32 { return (x & y) | ((~x) & z); }
fn f3(x: u32, y: u32, z: u32) -> u32 { return (x | (~y)) ^ z; }
fn f4(x: u32, y: u32, z: u32) -> u32 { return (x & z) | (y & (~z)); }
fn f5(x: u32, y: u32, z: u32) -> u32 { return x ^ (y | (~z)); }

fn compress(st: ptr<function, array<u32, 5>>, m: array<u32, 16>) {
    var a = (*st)[0];
    var b = (*st)[1];
    var c = (*st)[2];
    var d = (*st)[3];
    var e = (*st)[4];
    var ap = (*st)[0];
    var bp = (*st)[1];
    var cp = (*st)[2];
    var dp = (*st)[3];
    var ep = (*st)[4];

    for (var j = 0u; j < 16u; j = j + 1u) {
        let t = rotl(a + f1(b, c, d) + m[R1[j]], S1[j]) + e;
        a = e; e = d; d = rotl(c, 10u); c = b; b = t;
        let tp = rotl(ap + f5(bp, cp, dp) + m[RP1[j]] + 0x50a28be6u, SP1[j]) + ep;
        ap = ep; ep = dp; dp = rotl(cp, 10u); cp = bp; bp = tp;
    }
    for (var j = 0u; j < 16u; j = j + 1u) {
        let t = rotl(a + f2(b, c, d) + m[R2[j]] + 0x5a827999u, S2[j]) + e;
        a = e; e = d; d = rotl(c, 10u); c = b; b = t;
        let tp = rotl(ap + f4(bp, cp, dp) + m[RP2[j]] + 0x5c4dd124u, SP2[j]) + ep;
        ap = ep; ep = dp; dp = rotl(cp, 10u); cp = bp; bp = tp;
    }
    for (var j = 0u; j < 16u; j = j + 1u) {
        let t = rotl(a + f3(b, c, d) + m[R3[j]] + 0x6ed9eba1u, S3[j]) + e;
        a = e; e = d; d = rotl(c, 10u); c = b; b = t;
        let tp = rotl(ap + f3(bp, cp, dp) + m[RP3[j]] + 0x6d703ef3u, SP3[j]) + ep;
        ap = ep; ep = dp; dp = rotl(cp, 10u); cp = bp; bp = tp;
    }
    for (var j = 0u; j < 16u; j = j + 1u) {
        let t = rotl(a + f4(b, c, d) + m[R4[j]] + 0x8f1bbcdcu, S4[j]) + e;
        a = e; e = d; d = rotl(c, 10u); c = b; b = t;
        let tp = rotl(ap + f2(bp, cp, dp) + m[RP4[j]] + 0x7a6d76e9u, SP4[j]) + ep;
        ap = ep; ep = dp; dp = rotl(cp, 10u); cp = bp; bp = tp;
    }
    for (var j = 0u; j < 16u; j = j + 1u) {
        let t = rotl(a + f5(b, c, d) + m[R5[j]] + 0xa953fd4eu, S5[j]) + e;
        a = e; e = d; d = rotl(c, 10u); c = b; b = t;
        let tp = rotl(ap + f1(bp, cp, dp) + m[RP5[j]], SP5[j]) + ep;
        ap = ep; ep = dp; dp = rotl(cp, 10u); cp = bp; bp = tp;
    }

    let t = (*st)[1] + c + dp;
    (*st)[1] = (*st)[2] + d + ep;
    (*st)[2] = (*st)[3] + e + ap;
    (*st)[3] = (*st)[4] + a + bp;
    (*st)[4] = (*st)[0] + b + cp;
    (*st)[0] = t;
}

fn compare(st: array<u32, 5>) -> bool {
    for (var i = 0u; i < 5u; i = i + 1u) {
        if (st[i] != expected[i]) {
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
    // MD5 family length field: 64 bit little endian, so the low word goes in
    // word 14 of the block and the high word in word 15.
    if (c.len < 56u) {
        w[14] = c.len * 8u;
    }
    w[30] = c.len * 8u;

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
