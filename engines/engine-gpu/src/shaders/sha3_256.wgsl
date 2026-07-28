// SHA3-256 (Keccak) — 1088-bit rate, 512-bit capacity, 24 rounds

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

const RC: array<u64, 24> = array(
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
);

const ROT: array<u32, 25> = array(
    0u,1u,62u,28u,27u,36u,44u,6u,55u,20u,3u,10u,43u,25u,39u,41u,45u,15u,21u,8u,18u,2u,61u,56u,14u,
);

fn keccak_round(state: ptr<function, array<u64, 25>>, round: u32) {
    var C: array<u64, 5>;
    for (var x: u32 = 0u; x < 5u; x++) {
        C[x] = (*state)[x] ^ (*state)[x + 5u] ^ (*state)[x + 10u] ^ (*state)[x + 15u] ^ (*state)[x + 20u];
    }
    var D: array<u64, 5>;
    for (var x: u32 = 0u; x < 5u; x++) {
        D[x] = C[(x + 4u) % 5u] ^ ((C[(x + 1u) % 5u] << 1u) | (C[(x + 1u) % 5u] >> 63u));
    }
    for (var x: u32 = 0u; x < 5u; x++) {
        for (var y: u32 = 0u; y < 5u; y++) {
            (*state)[y * 5u + x] ^= D[x];
        }
    }

    var B: array<u64, 25>;
    for (var x: u32 = 0u; x < 5u; x++) {
        for (var y: u32 = 0u; y < 5u; y++) {
            let idx = y * 5u + x;
            let new_x = y;
            let new_y = (2u * x + 3u * y) % 5u;
            let r = ROT[idx];
            B[new_y * 5u + new_x] = ((*state)[idx] << r) | ((*state)[idx] >> (64u - r));
        }
    }

    for (var i: u32 = 0u; i < 25u; i++) { (*state)[i] = B[i]; }

    for (var x: u32 = 0u; x < 5u; x++) {
        for (var y: u32 = 0u; y < 5u; y++) {
            let idx = y * 5u + x;
            let val = B[idx];
            let left = B[y * 5u + ((x + 1u) % 5u)];
            let right = B[(y + 1u) % 5u * 5u + ((x + 1u) % 5u)];
            (*state)[idx] = val ^ ((~left) & right);
        }
    }

    (*state)[0] ^= RC[round];
}

fn keccak_absorb(state: ptr<function, array<u64, 25>>, data: array<u64, 17>) {
    for (var i: u32 = 0u; i < 17u; i++) { (*state)[i] ^= data[i]; }
    for (var r: u32 = 0u; r < 24u; r++) { keccak_round(state, r); }
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if (idx >= config.pcount) { return; }

    var pw: array<u8, 128>;
    let base = idx * 16u;
    for (var i: u32 = 0u; i < 128u; i++) {
        pw[i] = u8((input[base + i / 4u] >> ((i % 4u) * 8u)) & 0xffu);
    }
    var len: u32 = 0u;
    for (var i: u32 = 0u; i < 128u; i++) { if (pw[i] == 0u) { len = i; break; } }
    if (len == 0u && pw[0] != 0u) { len = 128u; }

    var st: array<u64, 25>;
    for (var i: u32 = 0u; i < 25u; i++) { st[i] = 0u; }

    var buf: array<u64, 17>;
    for (var i: u32 = 0u; i < 17u; i++) { buf[i] = 0u; }
    for (var i: u32 = 0u; i < len; i++) {
        let w = i / 8u;
        let b = i % 8u;
        if (w < 17u) { buf[w] |= u64(pw[i]) << (b * 8u); }
    }
    buf[len / 8u] ^= u64(0x06u) << ((len % 8u) * 8u);
    buf[16u] ^= u64(0x8000000000000000);

    keccak_absorb(&st, buf);

    let out_base = idx * 8u;
    for (var i: u32 = 0u; i < 4u; i++) {
        output[out_base + i * 2u] = u32(st[i] >> 32u);
        output[out_base + i * 2u + 1u] = u32(st[i]);
    }
}
