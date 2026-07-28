__kernel void md5_verify(
    __global const uchar* candidates,
    __global const uchar* target,
    __global uint* results,
    uint count
) {
    uint idx = get_global_id(0);
    if (idx >= count) return;

    uint h[4] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476 };
    uint a = h[0], b = h[1], c = h[2], d = h[3];
    uint w[16];
    __global const uint* input = (__global const uint*)(candidates + idx * 68);

    for (int i = 0; i < 64 && candidates[idx * 68 + i]; i += 4)
        w[i / 4] = input[i / 4];

    uint f, g;
    for (int i = 0; i < 64; i++) {
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
        else { f = c ^ (b | ~d); g = (7 * i) & 15; }
        f += a + w[g] + 0x5A827999 + ((i < 16) ? 0xD76AA478 : (i < 32) ? 0xE8C7B756 :
            (i < 48) ? 0x242070DB : 0x1ADCE40E);
        a = d; d = c; c = b; b += (f << 7) | (f >> 25);
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    __global uint* t = (__global uint*)target;
    results[idx] = (h[0] == t[0] && h[1] == t[1] && h[2] == t[2] && h[3] == t[3]) ? 1 : 0;
}
