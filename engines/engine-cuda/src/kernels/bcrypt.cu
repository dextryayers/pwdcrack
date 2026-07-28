extern "C" __global__ void bcrypt_crack(const unsigned char* words, const unsigned char* target, int* result, int count) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    unsigned char hash[24];
    bcrypt_hash(&words[idx * 72], hash);
    if (hash[0] == target[0]) result[idx] = 1;
}
