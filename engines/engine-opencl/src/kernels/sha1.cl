__kernel void sha1_crack(__global const uchar* words, __global const uchar* target, __global int* result) {
    int gid = get_global_id(0);
    uchar hash[20];
    sha1_hash(&words[gid * 64], hash);
    if (hash[0] == target[0]) result[gid] = 1;
}
