// MD5, one candidate per invocation.
//
// Layout shared by every supported shader:
//   binding 0  array<Candidate>   input, read only
//   binding 1  array<u32>         one match flag per candidate, read write
//   binding 2  array<u32, 16>     target digest as little endian words
//   binding 3  u32                candidate count
//
// Candidate.data holds the first 64 message bytes as little endian words and
// Candidate.len is the byte length. A message of 55 bytes or less pads into one
// 64 byte block; 56..64 bytes pads into two.

struct Candidate {
    data: array<u32, 16>,
    len: u32,
}

@group(0) @binding(0) var<storage, read> candidates: array<Candidate>;
@group(0) @binding(1) var<storage, read_write> results: array<u32>;
@group(0) @binding(2) var<storage, read> expected: array<u32, 16>;
@group(0) @binding(3) var<uniform> count: u32;

const S: array<u32, 64> = array(
    7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u, 7u, 12u, 17u, 22u,
    5u, 9u, 14u, 20u, 5u, 9u, 14u, 20u, 5u, 9u, 14u, 20u, 5u, 9u, 14u, 20u,
    4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u, 4u, 11u, 16u, 23u,
    6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u, 6u, 10u, 15u, 21u,
);

const K: array<u32, 64> = array(
    0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
    0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
    0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
    0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
    0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
    0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
    0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
    0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
    0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
    0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
    0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
    0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
    0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
    0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
    0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
    0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
);

fn rotl(x: u32, c: u32) -> u32 {
    return (x << c) | (x >> (32u - c));
}

fn compress(st: ptr<function, array<u32, 4>>, m: array<u32, 16>) {
    var a = (*st)[0];
    var b = (*st)[1];
    var c = (*st)[2];
    var d = (*st)[3];

    for (var i = 0u; i < 64u; i = i + 1u) {
        var f: u32;
        var g: u32;
        if (i < 16u) {
            f = (b & c) | ((~b) & d);
            g = i;
        } else if (i < 32u) {
            f = (d & b) | ((~d) & c);
            g = (5u * i + 1u) % 16u;
        } else if (i < 48u) {
            f = b ^ c ^ d;
            g = (3u * i + 5u) % 16u;
        } else {
            f = c ^ (b | (~d));
            g = (7u * i) % 16u;
        }
        let next = b + rotl(a + f + K[i] + m[g], S[i]);
        a = d;
        d = c;
        c = b;
        b = next;
    }

    (*st)[0] = (*st)[0] + a;
    (*st)[1] = (*st)[1] + b;
    (*st)[2] = (*st)[2] + c;
    (*st)[3] = (*st)[3] + d;
}

fn compare(st: array<u32, 4>) -> bool {
    return st[0] == expected[0] && st[1] == expected[1]
        && st[2] == expected[2] && st[3] == expected[3];
}

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) id: vec3<u32>) {
    let idx = id.x;
    if (idx >= count) {
        return;
    }

    let c = candidates[idx];

    // Two zeroed blocks hold every padded form of a message up to 64 bytes.
    var w: array<u32, 32>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        w[i] = c.data[i];
    }
    for (var i = 16u; i < 32u; i = i + 1u) {
        w[i] = 0u;
    }
    let byte_index = c.len / 4u;
    let byte_offset = c.len % 4u;
    let keep = (1u << (byte_offset * 8u)) - 1u;
    w[byte_index] = (w[byte_index] & keep) | (0x80u << (byte_offset * 8u));
    // MD5 family length field: 64 bit little endian, so the low word goes in
    // word 14 of the block and the high word in word 15.
    if (c.len < 56u) {
        w[14] = c.len * 8u;
    }
    w[30] = c.len * 8u;

    var st = array<u32, 4>(0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u);

    var m: array<u32, 16>;
    for (var i = 0u; i < 16u; i = i + 1u) {
        m[i] = w[i];
    }
    compress(&st, m);

    if (c.len >= 56u) {
        for (var i = 0u; i < 16u; i = i + 1u) {
            m[i] = w[16u + i];
        }
        compress(&st, m);
    }

    results[idx] = select(0u, 1u, compare(st));
}
