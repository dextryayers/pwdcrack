// Tiger-192 hash — 64-byte block, 24 rounds, S-boxes

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

const T1: array<u64, 256> = array(
    0x02aab17cf7e90c5e, 0xac424b03e243a8ec, 0x72cd5be30dd5fcd3, 0x6d019b6f8f1f7fb2,
    0xcd9978ffd21f9193, 0x7573a1c9708029e2, 0xb164326b922a83c3, 0x46883eee04915870,
    0xeaace3057103ece6, 0xc54169b808a3535c, 0x4ce754918ddec47c, 0x0aa2f4dfdc0df40c,
    0x10b76f18a74dbefa, 0xc6ccb6235b1e614b, 0x13726121572fe2ff, 0x1a488c6f199d921e,
    0x4bc9f27f4bb1f9f2, 0x7f2fd688bd25dea8, 0x1fb3cd3756e7f549, 0xcb3b0b07067b8bcd,
    0xefe5fe43cac6f5e1, 0xbe2084ed567d72d0, 0xabe6c62bdcfb78f6, 0x3b0e8e3e559ae3db,
    0x9e6bd25b53e8e4ad, 0xd5b5b1e4bba3e7b1, 0xe6f3d9c9a6e6b3e0, 0x5b34a78538215257,
    0xbe3d5f77971c1a4f, 0x8c5c3f719a8e7a8e, 0x0bcf25475192b70e, 0x6e1e4a1f38f8ed04,
);

fn tiger_round(a: ptr<function, u64>, b: ptr<function, u64>, c: ptr<function, u64>, x: u64, mul: u32) {
    let v = (*c) ^ x;
    let t = T1[u32(v & 0xffu)] ^ (T1[u32((v >> 16u) & 0xffu)] - T1[u32((v >> 32u) & 0xffu)]) ^
            (T1[u32((v >> 48u) & 0xffu)] + (*b));
    *a -= t;
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

    var block: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { block[i] = 0u; }
    for (var i: u32 = 0u; i < len; i++) {
        let w = i / 8u;
        let b = i % 8u;
        block[w] |= u64(pw[i]) << (b * 8u);
    }
    block[len / 8u] |= u64(0x80u) << ((len % 8u) * 8u);
    block[7] = u64(len) * 8u;

    var a: u64 = 0x0123456789abcde;
    var b: u64 = 0xfedcba9876543210;
    var c: u64 = 0xf096a5b4c3b2e187;

    for (var i: u32 = 0u; i < 8u; i++) {
        let x = block[i];
        for (var r: u32 = 0u; r < 3u; r++) {
            tiger_round(&a, &b, &c, x, 5u);
            tiger_round(&b, &c, &a, x, 5u);
            tiger_round(&c, &a, &b, x, 5u);
        }
    }

    let out_base = idx * 6u;
    output[out_base] = u32(a); output[out_base + 1u] = u32(a >> 32u);
    output[out_base + 2u] = u32(b); output[out_base + 3u] = u32(b >> 32u);
    output[out_base + 4u] = u32(c); output[out_base + 5u] = u32(c >> 32u);
}
