// NTLM hash — MD4 of UTF-16-LE encoded password

@group(0) @binding(0) var<storage, read> input: array<u32>;
@group(0) @binding(1) var<storage, read_write> output: array<u32>;

struct Config {
    pcount: u32,
}
@group(0) @binding(2) var<uniform> config: Config;

fn rol(x: u32, n: u32) -> u32 { return (x << n) | (x >> (32u - n)); }

fn f(x: u32, y: u32, z: u32) -> u32 { return (x & y) | ((~x) & z); }
fn g(x: u32, y: u32, z: u32) -> u32 { return (x & y) | (x & z) | (y & z); }
fn h(x: u32, y: u32, z: u32) -> u32 { return x ^ y ^ z; }

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if (idx >= config.pcount) { return; }

    var pw: array<u8, 64>;
    let base = idx * 16u;
    for (var i: u32 = 0u; i < 64u; i++) {
        pw[i] = u8((input[base + i / 4u] >> ((i % 4u) * 8u)) & 0xffu);
    }
    var pwlen: u32 = 0u;
    for (var i: u32 = 0u; i < 64u; i++) { if (pw[i] == 0u) { pwlen = i; break; } }
    if (pwlen == 0u && pw[0] != 0u) { pwlen = 64u; }

    var utf16: array<u8, 128>;
    var ulen: u32 = 0u;
    for (var i: u32 = 0u; i < pwlen; i++) {
        utf16[ulen] = pw[i]; ulen++;
        utf16[ulen] = 0u; ulen++;
    }

    var w: array<u32, 16>;
    for (var i: u32 = 0u; i < 16u; i++) { w[i] = 0u; }
    for (var i: u32 = 0u; i < ulen; i++) {
        let word_idx = i / 4u;
        let byte_idx = i % 4u;
        w[word_idx] |= u32(utf16[i]) << (byte_idx * 8u);
    }

    let bit_len = ulen * 8u;
    w[ulen / 4u] |= 0x80u << ((ulen % 4u) * 8u);
    w[14] = bit_len;

    var hh: array<u32, 4> = array(0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u);
    var a = hh[0]; var b = hh[1]; var c = hh[2]; var d = hh[3];
    var temp: u32;

    for (var i: u32 = 0u; i < 16u; i++) {
        let k = i;
        temp = rol(a + f(b, c, d) + w[k], 3u);
        a = d; d = c; c = b; b = temp;
    }
    for (var i: u32 = 0u; i < 16u; i++) {
        let k = (i % 4u) * 4u + i / 4u;
        let s = (i % 4u) * 4u + 3u;
        temp = rol(a + g(b, c, d) + w[k] + 0x5a827999u, s);
        a = d; d = c; c = b; b = temp;
    }
    for (var i: u32 = 0u; i < 16u; i++) {
        let perm: array<u32, 16> = array(0u,8u,4u,12u,2u,10u,6u,14u,1u,9u,5u,13u,3u,11u,7u,15u);
        let k = perm[i];
        let s = array(3u,5u,9u,13u)[i % 4u];
        temp = rol(a + h(b, c, d) + w[k] + 0x6ed9eba1u, s);
        a = d; d = c; c = b; b = temp;
    }

    hh[0] += a; hh[1] += b; hh[2] += c; hh[3] += d;

    let out_base = idx * 4u;
    output[out_base] = hh[0]; output[out_base + 1u] = hh[1];
    output[out_base + 2u] = hh[2]; output[out_base + 3u] = hh[3];
}
