// BLAKE3-256 compute shader (simplified single chunk)

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

const IV: array<u32, 8> = array(
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
);

const MSG_PERM: array<u32, 16> = array(
    2u, 6u, 3u, 10u, 7u, 0u, 4u, 13u, 1u, 11u, 12u, 5u, 9u, 14u, 15u, 8u,
);

fn rotr(x: u32, n: u32) -> u32 { return (x >> n) | (x << (32u - n)); }

fn blake3_g(state: ptr<function, array<u32, 16>>, a: u32, b: u32, c: u32, d: u32, mx: u32, my: u32) {
    (*state)[a] = (*state)[a] + (*state)[b] + mx;
    (*state)[d] = rotr((*state)[d] ^ (*state)[a], 16u);
    (*state)[c] = (*state)[c] + (*state)[d];
    (*state)[b] = rotr((*state)[b] ^ (*state)[c], 12u);
    (*state)[a] = (*state)[a] + (*state)[b] + my;
    (*state)[d] = rotr((*state)[d] ^ (*state)[a], 8u);
    (*state)[c] = (*state)[c] + (*state)[d];
    (*state)[b] = rotr((*state)[b] ^ (*state)[c], 7u);
}

fn blake3_round(state: ptr<function, array<u32, 16>>, m: array<u32, 16>) {
    blake3_g(state, 0u, 4u, 8u, 12u, m[0u], m[1u]);
    blake3_g(state, 1u, 5u, 9u, 13u, m[2u], m[3u]);
    blake3_g(state, 2u, 6u, 10u, 14u, m[4u], m[5u]);
    blake3_g(state, 3u, 7u, 11u, 15u, m[6u], m[7u]);
    blake3_g(state, 0u, 5u, 10u, 15u, m[8u], m[9u]);
    blake3_g(state, 1u, 6u, 11u, 12u, m[10u], m[11u]);
    blake3_g(state, 2u, 7u, 8u, 13u, m[12u], m[13u]);
    blake3_g(state, 3u, 4u, 9u, 14u, m[14u], m[15u]);
}

fn blake3_compress(chaining: ptr<function, array<u32, 8>>, block: array<u32, 16>, block_len: u32, counter: u64, flags: u32) {
    var v: array<u32, 16>;
    for (var i: u32 = 0u; i < 8u; i++) { v[i] = (*chaining)[i]; }
    for (var i: u32 = 0u; i < 8u; i++) { v[i + 8u] = IV[i]; }
    v[12] = u32(counter);
    v[13] = u32(counter >> 32u);
    v[14] = block_len;
    v[15] = flags;

    var m: array<u32, 16> = block;
    for (var round: u32 = 0u; round < 7u; round++) {
        blake3_round(&v, m);
        var permuted: array<u32, 16>;
        for (var i: u32 = 0u; i < 16u; i++) { permuted[i] = m[MSG_PERM[i]]; }
        m = permuted;
    }

    for (var i: u32 = 0u; i < 8u; i++) { (*chaining)[i] ^= v[i] ^ v[i + 8u]; }
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

    var block: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { block[i] = 0u; }
    for (var i: u32 = 0u; i < len; i++) {
        let w = i / 4u;
        let b = i % 4u;
        block[w] |= u32(pw[i]) << (b * 8u);
    }
    block[len / 4u] |= 0x80u << ((len % 4u) * 8u);

    var chain: array<u32, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { chain[i] = IV[i]; }
    chain[0] ^= 0x01010000u;

    let flags = 0x0au;
    blake3_compress(&chain, block, len, u64(len), flags);

    let out_base = idx * 8u;
    for (var i: u32 = 0u; i < 8u; i++) { output[out_base + i] = chain[i]; }
}
