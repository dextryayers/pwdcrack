// Argon2i memory-hard hashing core (simplified)

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
    mem_blocks: u32,
    time_cost: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

fn rotr(x: u32, n: u32) -> u32 { return (x >> n) | (x << (32u - n)); }

fn blake2b_g(v: ptr<function, array<u64, 16>>, a: u32, b: u32, c: u32, d: u32, x: u64, y: u64) {
    (*v)[a] = (*v)[a] + (*v)[b] + x;
    (*v)[d] = rotr(u32((*v)[d] ^ (*v)[a]), 32u);
    (*v)[c] = (*v)[c] + (*v)[d];
    (*v)[b] = rotr(u32((*v)[b] ^ (*v)[c]), 24u);
    (*v)[a] = (*v)[a] + (*v)[b] + y;
    (*v)[d] = rotr(u32((*v)[d] ^ (*v)[a]), 16u);
    (*v)[c] = (*v)[c] + (*v)[d];
    (*v)[b] = rotr(u32((*v)[b] ^ (*v)[c]), 63u);
}

const IV: array<u64, 8> = array(
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
);

fn argon2_compress(x: ptr<function, array<u64, 8>>, y: ptr<function, array<u64, 8>>) {
    var v: array<u64, 16>;
    for (var i: u32 = 0u; i < 8u; i++) { v[i] = (*x)[i]; v[i + 8u] = (*y)[i]; }
    for (var r: u32 = 0u; r < 8u; r++) {
        blake2b_g(&v, 0u, 4u, 8u, 12u, v[0], v[4]);
        blake2b_g(&v, 1u, 5u, 9u, 13u, v[1], v[5]);
        blake2b_g(&v, 2u, 6u, 10u, 14u, v[2], v[6]);
        blake2b_g(&v, 3u, 7u, 11u, 15u, v[3], v[7]);
        blake2b_g(&v, 0u, 5u, 10u, 15u, v[0], v[5]);
        blake2b_g(&v, 1u, 6u, 11u, 12u, v[1], v[6]);
        blake2b_g(&v, 2u, 7u, 8u, 13u, v[2], v[7]);
        blake2b_g(&v, 3u, 4u, 9u, 14u, v[3], v[4]);
    }
    for (var i: u32 = 0u; i < 8u; i++) {
        (*x)[i] = v[i] ^ v[i + 8u] ^ (*y)[i];
    }
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

    let mem = config.mem_blocks;
    if (mem == 0u) { return; }

    var block_0: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { block_0[i] = IV[i]; }
    block_0[0] ^= u64(len);

    var block_1: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { block_1[i] = block_0[i]; }

    argon2_compress(&block_0, &block_1);

    var memory: array<array<u64, 8>, 256>;
    memory[0] = block_0;
    memory[1] = block_1;

    for (var i: u32 = 2u; i < mem && i < 256u; i++) {
        var prev = memory[i - 1u];
        var ref_idx = (u32(prev[0]) & 0xffu) % i;
        if (ref_idx >= i) { ref_idx = i - 1u; }
        var ref_block = memory[ref_idx];
        argon2_compress(&prev, &ref_block);
        memory[i] = prev;
    }

    for (var t: u32 = 1u; t < config.time_cost && t < 4u; t++) {
        for (var i: u32 = 0u; i < mem && i < 256u; i++) {
            var prev = memory[(i + mem - 1u) % mem];
            var ref_idx = (u32(prev[0]) & 0xffu) % mem;
            if (ref_idx >= mem) { ref_idx = mem - 1u; }
            var ref_block = memory[ref_idx];
            argon2_compress(&prev, &ref_block);
            memory[i] = prev;
        }
    }

    var final_block: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { final_block[i] = 0u; }
    for (var i: u32 = 0u; i < mem && i < 256u; i++) {
        for (var j: u32 = 0u; j < 8u; j++) { final_block[j] ^= memory[i][j]; }
    }

    let out_base = idx * 16u;
    for (var i: u32 = 0u; i < 8u; i++) {
        output[out_base + i * 2u] = u32(final_block[i] >> 32u);
        output[out_base + i * 2u + 1u] = u32(final_block[i]);
    }
}
