__kernel void bcrypt_crack(__global const uchar* words, __global const uchar* target, __global int* result) {
    int gid = get_global_id(0);
    uchar hash[24];
    bcrypt_hash(&words[gid * 72], hash);
    if (hash[0] == target[0]) result[gid] = 1;
}
