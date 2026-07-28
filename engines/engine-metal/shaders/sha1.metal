#include <metal_stdlib>
using namespace metal;

constant uint K[4] = { 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6 };

kernel void sha1_compute(device const uchar* input [[buffer(0)]],
                         device uchar* output [[buffer(1)]],
                         uint gid [[thread_position_in_grid]]) {
    uint H[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
    uint W[80];

    for (uint t = 0; t < 16; t++) {
        W[t] = ((device uint*)input)[t];
    }
    for (uint t = 16; t < 80; t++) {
        W[t] = rotate_left(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    uint a = H[0], b = H[1], c = H[2], d = H[3], e = H[4];
    for (uint t = 0; t < 80; t++) {
        uint f, k;
        if (t < 20) { f = (b & c) | ((~b) & d); k = K[0]; }
        else if (t < 40) { f = b ^ c ^ d; k = K[1]; }
        else if (t < 60) { f = (b & c) | (b & d) | (c & d); k = K[2]; }
        else { f = b ^ c ^ d; k = K[3]; }
        uint temp = rotate_left(a, 5) + f + e + k + W[t];
        e = d; d = c; c = rotate_left(b, 30); b = a; a = temp;
    }

    ((device uint*)output)[0] = H[0] + a;
    ((device uint*)output)[1] = H[1] + b;
    ((device uint*)output)[2] = H[2] + c;
    ((device uint*)output)[3] = H[3] + d;
    ((device uint*)output)[4] = H[4] + e;
}
