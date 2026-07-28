// Optimized RIPEMD-160 — dual-line 80 steps

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

fn rol(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }

fn f1(x: u32, y: u32, z: u32) -> u32 { return x ^ y ^ z; }
fn f2(x: u32, y: u32, z: u32) -> u32 { return (x & y) | (~x & z); }
fn f3(x: u32, y: u32, z: u32) -> u32 { return (x | ~y) ^ z; }
fn f4(x: u32, y: u32, z: u32) -> u32 { return (x & z) | (y & ~z); }
fn f5(x: u32, y: u32, z: u32) -> u32 { return x ^ (y | ~z); }

const R: array<u32, 80> = array(
    0u,1u,2u,3u,4u,5u,6u,7u,8u,9u,10u,11u,12u,13u,14u,15u,
    7u,4u,13u,1u,10u,6u,15u,3u,12u,0u,9u,5u,2u,14u,11u,8u,
    3u,10u,14u,4u,9u,15u,8u,1u,2u,7u,0u,6u,13u,11u,5u,12u,
    1u,9u,11u,10u,0u,8u,12u,4u,13u,3u,7u,15u,14u,5u,6u,2u,
    4u,0u,5u,9u,7u,12u,2u,10u,14u,1u,3u,8u,11u,6u,15u,13u,
);
const R2: array<u32, 80> = array(
    5u,14u,7u,0u,9u,2u,11u,4u,13u,6u,15u,8u,1u,10u,3u,12u,
    6u,11u,3u,7u,0u,13u,5u,10u,14u,15u,8u,12u,4u,9u,1u,2u,
    15u,5u,1u,3u,7u,14u,6u,9u,11u,8u,12u,2u,10u,0u,4u,13u,
    8u,6u,4u,1u,3u,11u,15u,0u,5u,12u,2u,13u,9u,7u,10u,14u,
    12u,15u,10u,4u,1u,5u,8u,7u,6u,2u,13u,14u,0u,3u,9u,11u,
);
const S: array<u32, 80> = array(
    11u,14u,15u,12u,5u,8u,7u,9u,11u,13u,14u,15u,6u,7u,9u,8u,
    7u,6u,8u,13u,11u,9u,7u,15u,7u,12u,15u,9u,11u,7u,13u,12u,
    11u,13u,6u,7u,14u,9u,13u,15u,14u,8u,13u,6u,5u,12u,7u,5u,
    11u,12u,14u,15u,14u,15u,9u,8u,9u,14u,5u,6u,8u,6u,5u,12u,
    9u,15u,5u,11u,6u,8u,13u,12u,5u,12u,13u,14u,11u,8u,5u,6u,
);
const S2: array<u32, 80> = array(
    8u,9u,9u,11u,13u,15u,15u,5u,7u,7u,8u,11u,14u,14u,12u,6u,
    9u,13u,15u,7u,12u,8u,9u,11u,7u,7u,12u,7u,6u,15u,13u,11u,
    9u,7u,15u,11u,8u,6u,6u,14u,12u,13u,5u,14u,13u,13u,7u,5u,
    15u,5u,8u,11u,14u,14u,6u,14u,6u,9u,12u,9u,12u,5u,15u,8u,
    8u,5u,12u,9u,12u,5u,14u,6u,8u,13u,6u,5u,15u,13u,11u,11u,
);

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

    var w: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { w[i] = 0u; }
    for (var i: u32 = 0u; i < len; i++) {
        let word_idx = i / 4u;
        let byte_idx = i % 4u;
        w[word_idx] |= u32(pw[i]) << (byte_idx * 8u);
    }
    w[len / 4u] |= 0x80u << ((len % 4u) * 8u);
    w[14] = len * 8u;

    var h: array<u32, 5> = array(0x67452301u,0xefcdab89u,0x98badcfeu,0x10325476u,0xc3d2e1f0u);
    var a = h[0]; var b = h[1]; var c = h[2]; var d = h[3]; var e = h[4];
    var a2 = h[0]; var b2 = h[1]; var c2 = h[2]; var d2 = h[3]; var e2 = h[4];

    for (var j: u32 = 0u; j < 80u; j++) {
        let rnd = j / 16u;
        var fj: u32;
        if (rnd == 0u) { fj = f1(b, c, d); }
        else if (rnd == 1u) { fj = f2(b, c, d); }
        else if (rnd == 2u) { fj = f3(b, c, d); }
        else if (rnd == 3u) { fj = f4(b, c, d); }
        else { fj = f5(b, c, d); }
        let t = a + fj + w[R[j] & 15u];
        let k_add = select(0x00000000u, 0x5a827999u, rnd == 0u) + select(0x6ed9eba1u, 0x8f1bbcdcu, rnd == 2u) +
                    select(0xa953fd4eu, 0x50a28be6u, rnd > 3u);
        a = e; e = d; d = rol(c, 10u); c = b; b = b + rol(t, S[j]);

        let rnd2 = j / 16u;
        var fj2: u32;
        if (rnd2 == 0u) { fj2 = f5(b2, c2, d2); }
        else if (rnd2 == 1u) { fj2 = f4(b2, c2, d2); }
        else if (rnd2 == 2u) { fj2 = f3(b2, c2, d2); }
        else if (rnd2 == 3u) { fj2 = f2(b2, c2, d2); }
        else { fj2 = f1(b2, c2, d2); }
        let t2 = a2 + fj2 + w[R2[j] & 15u] + select(0x50a28be6u, 0x5c4dd124u, rnd2 == 0u) +
                 select(0x6d703ef3u, 0x7a6d76e9u, rnd2 == 2u);
        a2 = e2; e2 = d2; d2 = rol(c2, 10u); c2 = b2; b2 = b2 + rol(t2, S2[j]);
    }

    let t = h[0]; h[0] = h[0] + a + b2; h[1] = h[1] + b + c2;
    h[2] = h[2] + c + d2; h[3] = h[3] + d + e2; h[4] = h[4] + e + a2;

    let out_base = idx * 5u;
    output[out_base] = h[0]; output[out_base + 1u] = h[1];
    output[out_base + 2u] = h[2]; output[out_base + 3u] = h[3];
    output[out_base + 4u] = h[4];
}
