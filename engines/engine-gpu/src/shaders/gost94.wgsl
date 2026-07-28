// GOST R 34.11-94 hash — 256-bit, 32-byte block, 32 rounds

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

fn gost_round(x: u32, k: u32) -> u32 {
    var t = x + k;
    t = (t << 11u) | (t >> 21u);
    let sbox: array<u32, 8> = array(0xCu, 0xAu, 0xDu, 0x3u, 0xEu, 0xBu, 0xFu, 0x8u);
    var res: u32 = 0u;
    for (var i: u32 = 0u; i < 8u; i++) {
        let nib = (t >> (i * 4u)) & 0xfu;
        res |= sbox[nib] << (i * 4u);
    }
    return (res << 11u) | (res >> 21u);
}

fn gost_encrypt(block: array<u32, 8>, key: array<u32, 8>) -> array<u32, 8> {
    var a = block[0];
    var b = block[1];
    for (var i: u32 = 0u; i < 32u; i++) {
        let k = key[i % 8u];
        let t = gost_round(a, k);
        let new_b = a;
        a = b ^ t;
        b = new_b;
    }
    return array<u32, 8>(a, b, 0u, 0u, 0u, 0u, 0u, 0u);
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

    var m: array<u32, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { m[i] = 0u; }
    for (var i: u32 = 0u; i < len; i++) {
        let w = i / 4u;
        let b = i % 4u;
        if (w < 8u) { m[w] |= u32(pw[i]) << (b * 8u); }
    }

    var h: array<u32, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { h[i] = 0u; }
    var sigma: array<u32, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { sigma[i] = 0u; }

    for (var i: u32 = 0u; i < 8u; i++) { sigma[i] += m[i]; }
    var enc = gost_encrypt(h, m);
    for (var i: u32 = 0u; i < 8u; i++) { h[i] ^= enc[i]; }

    let out_base = idx * 8u;
    for (var i: u32 = 0u; i < 8u; i++) { output[out_base + i] = h[i]; }
}
