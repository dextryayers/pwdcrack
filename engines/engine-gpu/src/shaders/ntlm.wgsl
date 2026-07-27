// NTLM compute shader — MD4 + UTF16-LE encoding
// NTLM(pw) = MD4(UTF16-LE(pw))

struct Candidate {
    password: array<u32, 16>,
    len: u32,
}

struct HashResult {
    found: u32,
    idx: u32,
    digest: vec4<u32>,
}

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<HashResult>;
@group(0) @binding(2) var<uniform> target: vec4<u32>;
@group(0) @binding(3) var<uniform> count: u32;

fn left_rotate(x: u32, c: u32) -> u32 {
    return (x << c) | (x >> (32u - c));
}

fn md4_f(x: u32, y: u32, z: u32) -> u32 { return (x & y) | ((~x) & z); }
fn md4_g(x: u32, y: u32, z: u32) -> u32 { return (x & y) | (x & z) | (y & z); }
fn md4_h(x: u32, y: u32, z: u32) -> u32 { return x ^ y ^ z; }

fn md4_verify(password_utf16: array<u32, 16>, len_utf16: u32, target_digest: vec4<u32>) -> u32 {
    var a: u32 = 0x67452301u;
    var b: u32 = 0xefcdab89u;
    var c: u32 = 0x98badcfeu;
    var d: u32 = 0x10325476u;

    var M: array<u32, 16> = password_utf16;

    let bit_len: u32 = len_utf16 * 8u;
    let byte_idx: u32 = len_utf16 / 4u;
    let byte_off: u32 = len_utf16 % 4u;
    let mask: u32 = 0xffffffffu << (byte_off * 8u);
    M[byte_idx] = (M[byte_idx] & mask) | (0x80u << (byte_off * 8u));

    if len_utf16 < 56u {
        M[14u] = bit_len;
    }

    // Round 1
    a = left_rotate(a + md4_f(b, c, d) + M[0],  3u);
    d = left_rotate(d + md4_f(a, b, c) + M[1],  7u);
    c = left_rotate(c + md4_f(d, a, b) + M[2],  11u);
    b = left_rotate(b + md4_f(c, d, a) + M[3],  19u);
    a = left_rotate(a + md4_f(b, c, d) + M[4],  3u);
    d = left_rotate(d + md4_f(a, b, c) + M[5],  7u);
    c = left_rotate(c + md4_f(d, a, b) + M[6],  11u);
    b = left_rotate(b + md4_f(c, d, a) + M[7],  19u);
    a = left_rotate(a + md4_f(b, c, d) + M[8],  3u);
    d = left_rotate(d + md4_f(a, b, c) + M[9],  7u);
    c = left_rotate(c + md4_f(d, a, b) + M[10], 11u);
    b = left_rotate(b + md4_f(c, d, a) + M[11], 19u);
    a = left_rotate(a + md4_f(b, c, d) + M[12], 3u);
    d = left_rotate(d + md4_f(a, b, c) + M[13], 7u);
    c = left_rotate(c + md4_f(d, a, b) + M[14], 11u);
    b = left_rotate(b + md4_f(c, d, a) + M[15], 19u);

    // Round 2
    a = left_rotate(a + md4_g(b, c, d) + M[0]  + 0x5a827999u, 3u);
    d = left_rotate(d + md4_g(a, b, c) + M[4]  + 0x5a827999u, 5u);
    c = left_rotate(c + md4_g(d, a, b) + M[8]  + 0x5a827999u, 9u);
    b = left_rotate(b + md4_g(c, d, a) + M[12] + 0x5a827999u, 13u);
    a = left_rotate(a + md4_g(b, c, d) + M[1]  + 0x5a827999u, 3u);
    d = left_rotate(d + md4_g(a, b, c) + M[5]  + 0x5a827999u, 5u);
    c = left_rotate(c + md4_g(d, a, b) + M[9]  + 0x5a827999u, 9u);
    b = left_rotate(b + md4_g(c, d, a) + M[13] + 0x5a827999u, 13u);
    a = left_rotate(a + md4_g(b, c, d) + M[2]  + 0x5a827999u, 3u);
    d = left_rotate(d + md4_g(a, b, c) + M[6]  + 0x5a827999u, 5u);
    c = left_rotate(c + md4_g(d, a, b) + M[10] + 0x5a827999u, 9u);
    b = left_rotate(b + md4_g(c, d, a) + M[14] + 0x5a827999u, 13u);
    a = left_rotate(a + md4_g(b, c, d) + M[3]  + 0x5a827999u, 3u);
    d = left_rotate(d + md4_g(a, b, c) + M[7]  + 0x5a827999u, 5u);
    c = left_rotate(c + md4_g(d, a, b) + M[11] + 0x5a827999u, 9u);
    b = left_rotate(b + md4_g(c, d, a) + M[15] + 0x5a827999u, 13u);

    // Round 3
    a = left_rotate(a + md4_h(b, c, d) + M[0]  + 0x6ed9eba1u, 3u);
    d = left_rotate(d + md4_h(a, b, c) + M[8]  + 0x6ed9eba1u, 9u);
    c = left_rotate(c + md4_h(d, a, b) + M[4]  + 0x6ed9eba1u, 11u);
    b = left_rotate(b + md4_h(c, d, a) + M[12] + 0x6ed9eba1u, 15u);
    a = left_rotate(a + md4_h(b, c, d) + M[2]  + 0x6ed9eba1u, 3u);
    d = left_rotate(d + md4_h(a, b, c) + M[10] + 0x6ed9eba1u, 9u);
    c = left_rotate(c + md4_h(d, a, b) + M[6]  + 0x6ed9eba1u, 11u);
    b = left_rotate(b + md4_h(c, d, a) + M[14] + 0x6ed9eba1u, 15u);
    a = left_rotate(a + md4_h(b, c, d) + M[1]  + 0x6ed9eba1u, 3u);
    d = left_rotate(d + md4_h(a, b, c) + M[9]  + 0x6ed9eba1u, 9u);
    c = left_rotate(c + md4_h(d, a, b) + M[5]  + 0x6ed9eba1u, 11u);
    b = left_rotate(b + md4_h(c, d, a) + M[13] + 0x6ed9eba1u, 15u);
    a = left_rotate(a + md4_h(b, c, d) + M[3]  + 0x6ed9eba1u, 3u);
    d = left_rotate(d + md4_h(a, b, c) + M[11] + 0x6ed9eba1u, 9u);
    c = left_rotate(c + md4_h(d, a, b) + M[7]  + 0x6ed9eba1u, 11u);
    b = left_rotate(b + md4_h(c, d, a) + M[15] + 0x6ed9eba1u, 15u);

    let digest = vec4(a + 0x67452301u, b + 0xefcdab89u, c + 0x98badcfeu, d + 0x10325476u);
    if digest == target_digest { return 1u; }
    return 0u;
}

fn utf16le_encode(password: array<u32, 16>, len: u32) -> (array<u32, 32>, u32) {
    var utf16: array<u32, 32>;
    var utf16_len: u32 = 0u;
    for (var i: u32 = 0u; i < len && i < 16u; i++) {
        let byte: u32 = (password[i / 4u] >> ((i % 4u) * 8u)) & 0xffu;
        if byte == 0u { break; }
        let low: u32 = byte;
        let high: u32 = 0u;
        let word_idx: u32 = utf16_len / 2u;
        if utf16_len % 2u == 0u {
            utf16[word_idx] = low | (high << 16u);
        }
        utf16_len++;
    }
    return (utf16, utf16_len * 2u);
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if idx >= count { return; }
    let cand = candidates[idx];
    let (utf16_data, utf16_len) = utf16le_encode(cand.password, cand.len);
    let found = md4_verify(utf16_data, utf16_len, target);
    results[idx] = HashResult(found, idx, vec4(0u));
}
