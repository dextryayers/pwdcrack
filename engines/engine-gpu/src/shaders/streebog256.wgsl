// Streebog (GOST R 34.11-2012) 256-bit hash — 64-byte block, 12 rounds, LPS

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

fn streebog_lps(state: ptr<function, array<u64, 8>>) {
    var t: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { t[i] = (*state)[i]; }
    for (var i: u32 = 0u; i < 8u; i++) {
        var v: u64 = 0u;
        for (var j: u32 = 0u; j < 8u; j++) {
            let b = u8((t[j] >> (56u - i * 8u)) & 0xffu);
            let sb = u64(b) ^ (u64(b) << 8u) ^ (u64(b) << 16u) ^ (u64(b) << 24u) ^
                     (u64(b) << 32u) ^ (u64(b) << 40u) ^ (u64(b) << 48u) ^ (u64(b) << 56u);
            v ^= sb;
        }
        (*state)[i] = v;
    }
}

fn streebog_g(n: array<u64, 8>, m: array<u64, 8>) -> array<u64, 8> {
    var k: array<u64, 8>;
    var s: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) {
        k[i] = n[i];
        s[i] = n[i] ^ m[i];
    }
    for (var r: u32 = 0u; r < 12u; r++) {
        for (var i: u32 = 0u; i < 8u; i++) {
            let x = k[i];
            k[i] = x ^ ((x << 1u) | (x >> 63u));
        }
        streebog_lps(&k);
        streebog_lps(&s);
        for (var i: u32 = 0u; i < 8u; i++) { s[i] ^= k[i]; }
    }
    var out: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { out[i] = n[i] ^ m[i] ^ s[i]; }
    return out;
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

    var m: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { m[i] = 0u; }
    for (var i: u32 = 0u; i < len; i++) {
        let w = i / 8u;
        let b = i % 8u;
        m[w] |= u64(pw[i]) << (56u - b * 8u);
    }
    m[len / 8u] |= u64(0x80u) << (56u - (len % 8u) * 8u);

    var h: array<u64, 8>;
    var N: array<u64, 8>;
    var Sigma: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { h[i] = 0u; N[i] = 0u; Sigma[i] = 0u; }

    h = streebog_g(N, m);
    N[0] = u64(len) * 8u;
    Sigma = streebog_g(array<u64, 8>(0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u), m);

    for (var i: u32 = 0u; i < 8u; i++) { h[i] ^= N[i] ^ Sigma[i]; }

    let out_base = idx * 8u;
    for (var i: u32 = 0u; i < 4u; i++) {
        output[out_base + i * 2u] = u32(h[i] >> 32u);
        output[out_base + i * 2u + 1u] = u32(h[i]);
    }
}
