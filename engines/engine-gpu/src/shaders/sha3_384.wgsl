// SHA3-384, one candidate per invocation. FIPS 202, Keccak-f[1600] with the
// SHA-3 domain separation byte 0x06.
//
// wgpu 26 has no 64 bit shader integer type, so every 64 bit lane is a
// `vec2<u32>` holding the low and high halves. A message of at most 64 bytes
// occupies one 104 byte rate block, so there is never a second absorb.
//
// Layout: see md5.wgsl. Input is read little endian; the digest bytes are the
// first 48 bytes of the final state, also little endian.

struct Candidate {
    data: array<u32, 16>,
    len: u32,
}

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<u32>;
@group(0) @binding(2) var<storage, read> expected: array<u32, 16>;
@group(0) @binding(3) var<uniform> count: u32;

const RATE_WORDS: u32 = 26u;
const RATE_LANES: u32 = 13u;
const DIGEST_WORDS: u32 = 12u;

// Round constants, low half first.
const RC: array<vec2<u32>, 24> = array(
    vec2<u32>(0x00000001u, 0x00000000u),
    vec2<u32>(0x00008082u, 0x00000000u),
    vec2<u32>(0x0000808au, 0x80000000u),
    vec2<u32>(0x80008000u, 0x80000000u),
    vec2<u32>(0x0000808bu, 0x00000000u),
    vec2<u32>(0x80000001u, 0x00000000u),
    vec2<u32>(0x80008081u, 0x80000000u),
    vec2<u32>(0x00008009u, 0x80000000u),
    vec2<u32>(0x0000008au, 0x00000000u),
    vec2<u32>(0x00000088u, 0x00000000u),
    vec2<u32>(0x80008009u, 0x00000000u),
    vec2<u32>(0x8000000au, 0x00000000u),
    vec2<u32>(0x8000808bu, 0x00000000u),
    vec2<u32>(0x0000008bu, 0x80000000u),
    vec2<u32>(0x00008089u, 0x80000000u),
    vec2<u32>(0x00008003u, 0x80000000u),
    vec2<u32>(0x00008002u, 0x80000000u),
    vec2<u32>(0x00000080u, 0x80000000u),
    vec2<u32>(0x0000800au, 0x00000000u),
    vec2<u32>(0x8000000au, 0x80000000u),
    vec2<u32>(0x80008081u, 0x80000000u),
    vec2<u32>(0x00008080u, 0x80000000u),
    vec2<u32>(0x80000001u, 0x00000000u),
    vec2<u32>(0x80008008u, 0x80000000u),
);

// rho offsets, indexed by y + 5*x for state index x + 5*y.
const ROT: array<u32, 25> = array(
    0u, 36u, 3u, 41u, 18u,
    1u, 44u, 10u, 45u, 2u,
    62u, 6u, 43u, 15u, 61u,
    28u, 55u, 25u, 21u, 56u,
    27u, 20u, 39u, 8u, 14u,
);

fn rotl64(v: vec2<u32>, n: u32) -> vec2<u32> {
    if (n == 0u) {
        return v;
    }
    if (n < 32u) {
        return vec2<u32>(
            (v.x << n) | (v.y >> (32u - n)),
            (v.y << n) | (v.x >> (32u - n)),
        );
    }
    if (n == 32u) {
        return vec2<u32>(v.y, v.x);
    }
    let m = n - 32u;
    return vec2<u32>(
        (v.y << m) | (v.x >> (32u - m)),
        (v.x << m) | (v.y >> (32u - m)),
    );
}

fn keccak_f(a: ptr<function, array<vec2<u32>, 25>>) {
    for (var round = 0u; round < 24u; round = round + 1u) {
        var c: array<vec2<u32>, 5>;
        for (var x = 0u; x < 5u; x = x + 1u) {
            c[x] = (*a)[x] ^ (*a)[x + 5u] ^ (*a)[x + 10u] ^ (*a)[x + 15u] ^ (*a)[x + 20u];
        }
        for (var x = 0u; x < 5u; x = x + 1u) {
            let d = c[(x + 4u) % 5u] ^ rotl64(c[(x + 1u) % 5u], 1u);
            for (var y = 0u; y < 5u; y = y + 1u) {
                (*a)[x + 5u * y] = (*a)[x + 5u * y] ^ d;
            }
        }

        var b: array<vec2<u32>, 25>;
        for (var y = 0u; y < 5u; y = y + 1u) {
            for (var x = 0u; x < 5u; x = x + 1u) {
                let new_x = y;
                let new_y = (2u * x + 3u * y) % 5u;
                b[new_x + 5u * new_y] = rotl64((*a)[x + 5u * y], ROT[y + 5u * x]);
            }
        }

        for (var y = 0u; y < 5u; y = y + 1u) {
            for (var x = 0u; x < 5u; x = x + 1u) {
                let i = x + 5u * y;
                (*a)[i] = b[i] ^ ((~b[(x + 1u) % 5u + 5u * y]) & b[(x + 2u) % 5u + 5u * y]);
            }
        }
        (*a)[0] = (*a)[0] ^ RC[round];
    }
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if (idx >= count) {
        return;
    }

    let c = candidates[idx];

    // One block, zero padded. The message is at most 64 bytes, so the 0x06
    // domain byte and the final 0x80 byte never coincide.
    var block: array<u32, 40>;
    for (var i = 0u; i < 40u; i = i + 1u) {
        block[i] = 0u;
    }
    for (var i = 0u; i < 16u; i = i + 1u) {
        block[i] = c.data[i];
    }
    let word = c.len / 4u;
    let shift = (c.len % 4u) * 8u;
    let keep = (1u << shift) - 1u;
    block[word] = (block[word] & keep) | (0x06u << shift);
    block[RATE_WORDS - 1u] = block[RATE_WORDS - 1u] | 0x80000000u;

    var state: array<vec2<u32>, 25>;
    for (var i = 0u; i < 25u; i = i + 1u) {
        state[i] = vec2<u32>(0u, 0u);
    }
    for (var i = 0u; i < RATE_LANES; i = i + 1u) {
        state[i] = state[i] ^ vec2<u32>(block[2u * i], block[2u * i + 1u]);
    }

    keccak_f(&state);

    var matched = true;
    var out = 0u;
    for (var i = 0u; out < DIGEST_WORDS; i = i + 1u) {
        if (state[i].x != expected[out]) {
            matched = false;
        }
        out = out + 1u;
        if (out < DIGEST_WORDS) {
            if (state[i].y != expected[out]) {
                matched = false;
            }
            out = out + 1u;
        }
    }

    results[idx] = select(0u, 1u, matched);
}
