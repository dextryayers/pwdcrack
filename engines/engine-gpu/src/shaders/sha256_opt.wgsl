// Optimized SHA-256 — 64 steps, inline scheduled

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

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

fn shr(x: u32, n: u32) -> u32 { return x >> n; }
fn rotr(x: u32, n: u32) -> u32 { return (x >> n) | (x << (32u - n)); }
fn ch(x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ ((~x) & z); }
fn maj(x: u32, y: u32, z: u32) -> u32 { return (x & y) ^ (x & z) ^ (y & z); }
fn sigma0(x: u32) -> u32 { return rotr(x, 2u) ^ rotr(x, 13u) ^ rotr(x, 22u); }
fn sigma1(x: u32) -> u32 { return rotr(x, 6u) ^ rotr(x, 11u) ^ rotr(x, 25u); }
fn gamma0(x: u32) -> u32 { return rotr(x, 7u) ^ rotr(x, 18u) ^ shr(x, 3u); }
fn gamma1(x: u32) -> u32 { return rotr(x, 17u) ^ rotr(x, 19u) ^ shr(x, 10u); }

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

    var w: array<u32, 64>;
    for (var i: u32 = 0u; i < 16u; i++) { w[i] = 0u; }
    for (var i: u32 = 0u; i < len; i++) {
        let word_idx = i / 4u;
        let byte_idx = i % 4u;
        w[word_idx] |= u32(pw[i]) << ((3u - byte_idx) * 8u);
    }
    w[len / 4u] |= 0x80u << ((3u - (len % 4u)) * 8u);

    let bit_len = len * 8u;
    if (len < 56u) { w[15] = bit_len; }

    for (var i: u32 = 16u; i < 64u; i++) {
        w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16];
    }

    var h0 = 0x6a09e667u; var h1 = 0xbb67ae85u;
    var h2 = 0x3c6ef372u; var h3 = 0xa54ff53au;
    var h4 = 0x510e527fu; var h5 = 0x9b05688cu;
    var h6 = 0x1f83d9abu; var h7 = 0x5be0cd19u;

    var a = h0; var b = h1; var c = h2; var d = h3;
    var e = h4; var f = h5; var g = h6; var h = h7;

    for (var i: u32 = 0u; i < 64u; i++) {
        let S1 = sigma1(e);
        let ch_val = ch(e, f, g);
        let temp1 = h + S1 + ch_val + K[i] + w[i];
        let S0 = sigma0(a);
        let maj_val = maj(a, b, c);
        let temp2 = S0 + maj_val;
        h = g; g = f; f = e; e = d + temp1;
        d = c; c = b; b = a; a = temp1 + temp2;
    }

    h0 += a; h1 += b; h2 += c; h3 += d;
    h4 += e; h5 += f; h6 += g; h7 += h;

    let out_base = idx * 8u;
    output[out_base] = h0; output[out_base + 1u] = h1;
    output[out_base + 2u] = h2; output[out_base + 3u] = h3;
    output[out_base + 4u] = h4; output[out_base + 5u] = h5;
    output[out_base + 6u] = h6; output[out_base + 7u] = h7;
}
