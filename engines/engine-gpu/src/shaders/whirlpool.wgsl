// Whirlpool hash compute shader — 512-bit block, 10 rounds, AES-like

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

const C: array<u64, 10> = array(
    0x1823c6e887b8014f, 0x36a6d2f5796f9152, 0x60bc9b8ea30c7b35, 0x1de0d7c22e4bfe57,
    0x157737e59ff04ada, 0x58c9290ab1a06b85, 0xbd5d10f4cb3e0567, 0xe427418ba77d95d8,
    0xfbee7c66dd17479e, 0xca2dbf07ad5a8333,
);

fn rotr64(x: u64, n: u32) -> u64 { return (x >> n) | (x << (64u - n)); }

fn whirlpool_round(state: ptr<function, array<u64, 8>>, rk: array<u64, 8>) {
    var a: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { a[i] = (*state)[i]; }
    for (var i: u32 = 0u; i < 8u; i++) {
        let col = i;
        var t: u64 = 0u;
        for (var j: u32 = 0u; j < 8u; j++) {
            let b = u8((a[j] >> (56u - col * 8u)) & 0xffu);
            let sub = u64(b) ^ (u64(b) << 8u) ^ (u64(b) << 16u) ^ (u64(b) << 24u) ^
                      (u64(b) << 32u) ^ (u64(b) << 40u) ^ (u64(b) << 48u) ^ (u64(b) << 56u);
            t ^= rotr64(sub, j * 8u);
        }
        (*state)[i] = t ^ rk[i];
    }
}

fn whirlpool_compress(h: ptr<function, array<u64, 8>>, block: array<u64, 8>) {
    var K: array<u64, 8>;
    var state: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) {
        K[i] = (*h)[i];
        state[i] = (*h)[i] ^ block[i];
    }
    for (var r: u32 = 0u; r < 10u; r++) {
        var rk: array<u64, 8>;
        whirlpool_round(&K, array<u64, 8>(C[r], 0u, 0u, 0u, 0u, 0u, 0u, 0u));
        for (var i: u32 = 0u; i < 8u; i++) { rk[i] = K[i]; }
        for (var i: u32 = 0u; i < 8u; i++) { rk[i] ^= C[r]; }
        whirlpool_round(&state, rk);
    }
    for (var i: u32 = 0u; i < 8u; i++) { (*h)[i] ^= state[i] ^ block[i]; }
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
        block[w] |= u64(pw[i]) << (56u - b * 8u);
    }
    block[len / 8u] |= u64(0x80u) << (56u - (len % 8u) * 8u);
    block[7] = u64(len) * 8u;

    var h: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { h[i] = 0u; }
    whirlpool_compress(&h, block);

    let out_base = idx * 16u;
    for (var i: u32 = 0u; i < 8u; i++) {
        output[out_base + i * 2u] = u32(h[i] >> 32u);
        output[out_base + i * 2u + 1u] = u32(h[i]);
    }
}
