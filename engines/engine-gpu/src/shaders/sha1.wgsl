// SHA-1 compute shader — 64 passwords per workgroup

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

fn sha1_verify(password: array<u32, 16>, len: u32, target_digest: vec4<u32>) -> u32 {
    var w: array<u32, 80>;
    for (var i: u32 = 0u; i < 16u; i++) {
        w[i] = password[i];
    }

    var bit_len: u32 = len * 8u;
    let byte_off: u32 = len % 4u;
    let word_idx: u32 = len / 4u;

    var mask: u32 = 0xffffffffu << (byte_off * 8u);
    w[word_idx] = (w[word_idx] & mask) | (0x80u << (byte_off * 8u));

    if len < 56u {
        w[15] = bit_len;
    }

    for (var i: u32 = 16u; i < 80u; i++) {
        w[i] = left_rotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1u);
    }

    var h0: u32 = 0x67452301u;
    var h1: u32 = 0xefcdab89u;
    var h2: u32 = 0x98badcfeu;
    var h3: u32 = 0x10325476u;
    var h4: u32 = 0xc3d2e1f0u;

    var a: u32 = h0;
    var b: u32 = h1;
    var c: u32 = h2;
    var d: u32 = h3;
    var e: u32 = h4;
    var f: u32;
    var k: u32;
    var temp: u32;

    for (var i: u32 = 0u; i < 80u; i++) {
        if i < 20u {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999u;
        } else if i < 40u {
            f = b ^ c ^ d;
            k = 0x6ed9eba1u;
        } else if i < 60u {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdcu;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6u;
        }
        temp = left_rotate(a, 5u) + f + e + k + w[i];
        e = d;
        d = c;
        c = left_rotate(b, 30u);
        b = a;
        a = temp;
    }

    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;

    let digest = vec4(h0, h1, h2, h3);
    if digest == target_digest {
        return 1u;
    }
    return 0u;
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if idx >= count { return; }

    let cand = candidates[idx];
    let found = sha1_verify(cand.password, cand.len, target);
    results[idx] = HashResult(found, idx, vec4(0u));
}
