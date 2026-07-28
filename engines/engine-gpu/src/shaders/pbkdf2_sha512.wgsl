// PBKDF2-HMAC-SHA512 with configurable iterations

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
    iterations: u32,
    salt_len: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

const K64: array<u64, 80> = array(
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
);

fn rotr64(x: u64, n: u32) -> u64 { return (x >> n) | (x << (64u - n)); }

fn sha512_compress(state: ptr<function, array<u64, 8>>, block: array<u64, 16>) {
    var w: array<u64, 80>;
    for (var i: u32 = 0u; i < 16u; i++) { w[i] = block[i]; }
    for (var i: u32 = 16u; i < 80u; i++) {
        let s0 = rotr64(w[i-15], 1u) ^ rotr64(w[i-15], 8u) ^ (w[i-15] >> 7u);
        let s1 = rotr64(w[i-2], 19u) ^ rotr64(w[i-2], 61u) ^ (w[i-2] >> 6u);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    var a = (*state)[0]; var b = (*state)[1]; var c = (*state)[2]; var d = (*state)[3];
    var e = (*state)[4]; var f = (*state)[5]; var g = (*state)[6]; var h = (*state)[7];
    for (var i: u32 = 0u; i < 80u; i++) {
        let S1 = rotr64(e, 14u) ^ rotr64(e, 18u) ^ rotr64(e, 41u);
        let ch = (e & f) ^ ((~e) & g);
        let temp1 = h + S1 + ch + K64[i] + w[i];
        let S0 = rotr64(a, 28u) ^ rotr64(a, 34u) ^ rotr64(a, 39u);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = S0 + maj;
        h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }
    (*state)[0] += a; (*state)[1] += b; (*state)[2] += c; (*state)[3] += d;
    (*state)[4] += e; (*state)[5] += f; (*state)[6] += g; (*state)[7] += h;
}

fn sha512(data: array<u64, 16>, len: u32) -> array<u64, 8> {
    var block: array<u64, 16> = data;
    block[len / 8u] |= u64(0x80u) << (56u - (len % 8u) * 8u);
    block[15] = u64(len) * 8u;
    var state: array<u64, 8> = array(
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    );
    sha512_compress(&state, block);
    return state;
}

fn xor_block(a: array<u64, 8>, b: array<u64, 8>) -> array<u64, 8> {
    var out: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { out[i] = a[i] ^ b[i]; }
    return out;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if (idx >= config.pcount) { return; }

    let base = idx * 16u;
    var msg: array<u8, 128>;
    for (var i: u32 = 0u; i < 128u; i++) {
        msg[i] = u8((input[base + i / 4u] >> ((i % 4u) * 8u)) & 0xffu);
    }
    var msg_len: u32 = 0u;
    for (var i: u32 = 0u; i < 128u; i++) { if (msg[i] == 0u) { msg_len = i; break; } }
    if (msg_len == 0u && msg[0] != 0u) { msg_len = 128u; }

    var key: array<u64, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { key[i] = 0u; }
    let salt_start = config.pcount * 16u;
    var salt_words = config.salt_len;
    if (salt_words > 16u) { salt_words = 16u; }
    for (var i: u32 = 0u; i < salt_words; i++) {
        let v = input[salt_start + i];
        key[i * 2u] = u64(v);
        key[i * 2u + 1u] = 0u;
    }

    var state: array<u64, 8>;
    for (var i: u32 = 0u; i < 8u; i++) { state[i] = 0u; }

    var block: array<u64, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { block[i] = key[i]; }
    for (var i: u32 = 0u; i < u64(msg_len); i++) {
        let w = i / 8u;
        let b = i % 8u;
        if (w < 16u) { block[w] |= u64(msg[u32(i)]) << (56u - b * 8u); }
    }

    for (var iter: u32 = 0u; iter < config.iterations; iter++) {
        let h = sha512(block, 128u);
        if (iter == 0u) {
            state = h;
        } else {
            state = xor_block(state, h);
        }
        for (var i: u32 = 0u; i < 8u; i++) { block[i] = h[i]; }
        for (var i: u32 = 8u; i < 16u; i++) { block[i] = 0u; }
    }

    let out_base = idx * 16u;
    for (var i: u32 = 0u; i < 8u; i++) {
        output[out_base + i * 2u] = u32(state[i] >> 32u);
        output[out_base + i * 2u + 1u] = u32(state[i]);
    }
}
