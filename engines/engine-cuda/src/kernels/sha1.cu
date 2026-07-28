extern "C" __global__ void sha1_verify(
    const unsigned char* candidates,
    const unsigned char* target,
    unsigned int* results,
    unsigned int count
) {
    unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    unsigned int h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    unsigned int w[80];

    unsigned int* input = (unsigned int*)(candidates + idx * 68);
    for (int i = 0; i < 16; i++) w[i] = input[i];
    for (int i = 16; i < 80; i++) {
        w[i] = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
        w[i] = (w[i] << 1) | (w[i] >> 31);
    }

    unsigned int a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f, k, temp;
    for (int i = 0; i < 80; i++) {
        if (i < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ c ^ d; k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC; }
        else { f = b ^ c ^ d; k = 0xCA62C1D6; }
        temp = (a << 5) | (a >> 27); temp += f + e + k + w[i];
        e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;

    results[idx] = (h[0] == *(unsigned int*)&target[0]) ? 1 : 0;
}
