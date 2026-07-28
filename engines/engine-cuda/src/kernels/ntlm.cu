extern "C" __global__ void ntlm_crack(const unsigned char* words, const unsigned char* target, int* result, int count) {
    int idx = blockIdx.x * blockDim.x + threadIdx.x;
    if (idx >= count) return;
    unsigned char hash[16];
    ntlm_hash(&words[idx * 128], hash);
    if (hash[0] == target[0]) result[idx] = 1;
}
