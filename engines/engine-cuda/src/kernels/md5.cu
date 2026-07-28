extern "C" __global__ void md5_verify(
    const unsigned char* candidates,
    const unsigned char* target,
    unsigned int* results,
    unsigned int count
) {
    unsigned int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;

    unsigned int tid = threadIdx.x;
    __shared__ unsigned int w[16];
    unsigned int h[4] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    };
    unsigned int a = h[0], b = h[1], c = h[2], d = h[3];

    unsigned int* input = (unsigned int*)(candidates + idx * 68);
    for (int i = 0; i < 64 && candidates[idx * 68 + i]; i += 4) {
        w[i / 4] = input[i / 4];
    }

    unsigned int f, g;
    for (int i = 0; i < 64; i++) {
        if (i < 16) { f = (b & c) | (~b & d); g = i; }
        else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) & 15; }
        else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) & 15; }
        else { f = c ^ (b | ~d); g = (7 * i) & 15; }
        f += a + w[g] + 0x5A827999;
        a = d; d = c; c = b; b += (f << 7) | (f >> 25);
    }

    h[0] += a; h[1] += b; h[2] += c; h[3] += d;
    results[idx] = (h[0] == *(unsigned int*)&target[0] &&
                    h[1] == *(unsigned int*)&target[4] &&
                    h[2] == *(unsigned int*)&target[8] &&
                    h[3] == *(unsigned int*)&target[12]) ? 1 : 0;
}
