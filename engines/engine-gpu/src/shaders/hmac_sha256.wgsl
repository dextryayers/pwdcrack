// HMAC-SHA256 compute shader

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
    key_len: u32,
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

fn sha256_block(msg: array<u32, 16>, state: ptr<function, array<u32, 8>>) {
    var w: array<u32, 64>;
    for (var i: u32 = 0u; i < 16u; i++) { w[i] = msg[i]; }
    for (var i: u32 = 16u; i < 64u; i++) {
        w[i] = gamma1(w[i-2]) + w[i-7] + gamma0(w[i-15]) + w[i-16];
    }
    var a = (*state)[0]; var b = (*state)[1]; var c = (*state)[2]; var d = (*state)[3];
    var e = (*state)[4]; var f = (*state)[5]; var g = (*state)[6]; var h = (*state)[7];
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
    (*state)[0] += a; (*state)[1] += b; (*state)[2] += c; (*state)[3] += d;
    (*state)[4] += e; (*state)[5] += f; (*state)[6] += g; (*state)[7] += h;
}

fn sha256_pad(data: ptr<function, array<u32, 16>>, len: u32) {
    let bit_len = len * 8u;
    let byte_off = len % 4u;
    let word_idx = len / 4u;
    let mask = 0xffffffffu << (byte_off * 8u);
    (*data)[word_idx] = ((*data)[word_idx] & mask) | (0x80u << (byte_off * 8u));
    if (len < 56u) {
        (*data)[15] = bit_len;
    }
}

fn sha256(data: array<u32, 16>, len: u32) -> array<u32, 8> {
    var block: array<u32, 16> = data;
    sha256_pad(&block, len);
    var h: array<u32, 8> = array(
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
    );
    sha256_block(block, &h);
    return h;
}

fn hmac_sha256(msg: array<u32, 16>, msg_len: u32, key_words: u32) -> array<u32, 8> {
    var key_block: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { key_block[i] = 0u; }
    var klen = config.key_len;
    if (klen > 64u) { klen = 64u; }
    let key_start = key_words;
    for (var i: u32 = 0u; i < klen; i++) {
        let byte_idx = i % 4u;
        let word_idx = i / 4u;
        key_block[word_idx] |= input[key_start + i / 4u] & (0xffu << (byte_idx * 8u));
    }

    var ipad: array<u32, 16>;
    var opad: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) {
        ipad[i] = key_block[i] ^ 0x36363636u;
        opad[i] = key_block[i] ^ 0x5c5c5c5cu;
    }

    var inner_msg: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { inner_msg[i] = ipad[i]; }
    let merge_len = klen;
    for (var i: u32 = 0u; i < msg_len && i < 64u; i++) {
        let byte_idx = i % 4u;
        let word_idx = i / 4u;
        if (word_idx < 16u) {
            let msk = 0xffu << (byte_idx * 8u);
            inner_msg[word_idx] = (inner_msg[word_idx] & ~msk) | (msg[word_idx] & msk);
        }
    }
    var inner_len = klen;
    if (msg_len > 64u) { inner_len = 64u; } else { inner_len = klen + msg_len; }
    if (inner_len > 64u) { inner_len = 64u; }

    var inner_hash = sha256(inner_msg, inner_len);

    var outer_msg: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { outer_msg[i] = opad[i]; }
    for (var i: u32 = 0u; i < 8u; i++) {
        outer_msg[4u + i] = inner_hash[i];
    }

    return sha256(outer_msg, klen + 32u);
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if (idx >= config.pcount) { return; }
    let base = idx * 16u;
    var msg: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { msg[i] = input[base + i]; }

    var msg_len: u32 = 0u;
    for (var i: u32 = 0u; i < 64u; i++) {
        if (u8((msg[i / 4u] >> ((i % 4u) * 8u)) & 0xffu) == 0u) { msg_len = i; break; }
    }
    if (msg_len == 0u && (msg[0] & 0xffu) != 0u) { msg_len = 64u; }

    let result = hmac_sha256(msg, msg_len, 256u);
    let out_base = idx * 8u;
    for (var i: u32 = 0u; i < 8u; i++) { output[out_base + i] = result[i]; }
}
