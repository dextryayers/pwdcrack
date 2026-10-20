// HMAC-SHA1 compute shader

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
    key_len: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

fn rol(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }

fn sha1_block(block: array<u32, 16>) -> array<u32, 5> {
    var w: array<u32, 80>;
    for (var i: u32 = 0u; i < 16u; i++) { w[i] = block[i]; }
    for (var i: u32 = 16u; i < 80u; i++) {
        w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1u);
    }
    var h0 = 0x67452301u; var h1 = 0xefcdab89u;
    var h2 = 0x98badcfeu; var h3 = 0x10325476u; var h4 = 0xc3d2e1f0u;
    var a = h0; var b = h1; var c = h2; var d = h3; var e = h4;
    var f: u32; var k: u32; var temp: u32;
    for (var i: u32 = 0u; i < 80u; i++) {
        if (i < 20u) { f = (b & c) ^ ((~b) & d); k = 0x5a827999u; }
        else if (i < 40u) { f = b ^ c ^ d; k = 0x6ed9eba1u; }
        else if (i < 60u) { f = (b & c) ^ (b & d) ^ (c & d); k = 0x8f1bbcdcu; }
        else { f = b ^ c ^ d; k = 0xca62c1d6u; }
        temp = rol(a, 5u) + f + e + k + w[i];
        e = d; d = c; c = rol(b, 30u); b = a; a = temp;
    }
    return array<u32, 5>(h0 + a, h1 + b, h2 + c, h3 + d, h4 + e);
}

fn sha1(data: array<u32, 16>, len: u32) -> array<u32, 5> {
    var block: array<u32, 16> = data;
    let bit_len = len * 8u;
    let byte_off = len % 4u;
    let word_idx = len / 4u;
    let mask = 0xffffffffu << (byte_off * 8u);
    block[word_idx] = (block[word_idx] & mask) | (0x80u << (byte_off * 8u));
    if (len < 56u) { block[15] = bit_len; }
    return sha1_block(block);
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

    var ipad: array<u32, 16>;
    var opad: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { ipad[i] = 0x36363636u; opad[i] = 0x5c5c5c5cu; }

    var klen = config.key_len;
    if (klen > 64u) { klen = 64u; }
    let key_start = config.pcount * 16u;
    for (var i: u32 = 0u; i < klen; i++) {
        let w = i / 4u;
        let b = i % 4u;
        if (w < 16u) {
            let key_byte = u8((input[key_start + w] >> (b * 8u)) & 0xffu);
            let m = 0xffu << (b * 8u);
            ipad[w] = (ipad[w] & ~m) | (u32(key_byte) << (b * 8u));
            opad[w] = (opad[w] & ~m) | (u32(key_byte) << (b * 8u));
        }
    }

    var inner: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { inner[i] = ipad[i]; }
    for (var i: u32 = 0u; i < len && i < 64u; i++) {
        let w = i / 4u;
        let b = i % 4u;
        let m = 0xffu << ((3u - b) * 8u);
        inner[w] = (inner[w] & ~m) | (u32(pw[i]) << ((3u - b) * 8u));
    }
    let inner_len = klen + len;
    var inner_hash = sha1(inner, inner_len);

    var outer: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { outer[i] = opad[i]; }
    for (var i: u32 = 0u; i < 5u; i++) { outer[4u + i] = inner_hash[i]; }

    let result = sha1(outer, klen + 20u);

    let out_base = idx * 5u;
    output[out_base] = result[0]; output[out_base + 1u] = result[1];
    output[out_base + 2u] = result[2]; output[out_base + 3u] = result[3];
    output[out_base + 4u] = result[4];
}
