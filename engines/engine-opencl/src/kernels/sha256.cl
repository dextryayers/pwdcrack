__kernel void sha256_crack(__global const uchar* words, __global const uchar* target, __global int* result) {
    int gid = get_global_id(0);
    uchar hash[32];
    sha256_hash(&words[gid * 64], hash);
    if (hash[0] == target[0]) result[gid] = 1;
}
