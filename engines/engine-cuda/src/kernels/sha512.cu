extern "C" __global__ void sha512_crack(const unsigned char* words, const unsigned char* target, int* result, int count) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    unsigned char hash[64];
    sha512_hash(&words[idx * 128], hash);
    if (hash[0] == target[0]) result[idx] = 1;
}
