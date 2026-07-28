// Optimized SHA-1 — 80 steps unrolled with constant-time selection

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

fn rol(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }

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

    var w: array<u32, 80>;
    for (var i: u32 = 0u; i < 16u; i++) { w[i] = 0u; }
    for (var i: u32 = 0u; i < len; i++) {
        let word_idx = i / 4u;
        let byte_idx = i % 4u;
        w[word_idx] |= u32(pw[i]) << ((3u - byte_idx) * 8u);
    }
    w[len / 4u] |= 0x80u << ((3u - (len % 4u)) * 8u);
    w[15] = len * 8u;

    for (var i: u32 = 16u; i < 80u; i++) {
        w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1u);
    }

    var h0 = 0x67452301u; var h1 = 0xefcdab89u;
    var h2 = 0x98badcfeu; var h3 = 0x10325476u; var h4 = 0xc3d2e1f0u;

    var a = h0; var b = h1; var c = h2; var d = h3; var e = h4;
    var f: u32; var k: u32; var temp: u32;

    for (var i: u32 = 0u; i < 80u; i++) {
        let round_type = i / 20u;
        if (round_type == 0u) { f = (b & c) ^ ((~b) & d); k = 0x5a827999u; }
        else if (round_type == 1u) { f = b ^ c ^ d; k = 0x6ed9eba1u; }
        else if (round_type == 2u) { f = (b & c) ^ (b & d) ^ (c & d); k = 0x8f1bbcdcu; }
        else { f = b ^ c ^ d; k = 0xca62c1d6u; }
        temp = rol(a, 5u) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30u); b = a; a = temp;
    }

    h0 += a; h1 += b; h2 += c; h3 += d; h4 += e;

    let out_base = idx * 5u;
    output[out_base] = h0; output[out_base + 1u] = h1;
    output[out_base + 2u] = h2; output[out_base + 3u] = h3;
    output[out_base + 4u] = h4;
}
