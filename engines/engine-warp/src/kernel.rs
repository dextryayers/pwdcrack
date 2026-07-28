pub struct WarpKernel {
    pub name: String,
    pub source: String,
    pub shared_mem: u32,
    pub threads_per_block: u32,
}

impl WarpKernel {
    pub fn new(name: &str, source: &str) -> Self {
        Self {
            name: name.to_string(),
            source: source.to_string(),
            shared_mem: 0,
            threads_per_block: 256,
        }
    }

    pub fn md5_kernel() -> Self {
        Self::new("md5_warp_kernel", r#"
__kernel void md5_crack(__global const uchar* words, __global const uchar* target, __global int* result) {
    int gid = get_global_id(0);
    int lid = get_local_id(0);
    __local uchar cache[256];
    cache[lid] = words[gid];
    barrier(CLK_LOCAL_MEM_FENCE);
    if (gid < 256) {
        uchar hash[16];
        md5_hash(&cache[lid], hash);
        if (hash[0] == target[0]) result[gid] = 1;
    }
}
"#.into())
    }

    pub fn sha256_kernel() -> Self {
        Self::new("sha256_warp_kernel", r#"
__kernel void sha256_crack(__global const uchar* words, __global const uchar* target, __global int* result) {
    int gid = get_global_id(0);
    uchar hash[32];
    sha256_hash(&words[gid * 64], hash);
    if (hash[0] == target[0]) result[gid] = 1;
}
"#.into())
    }
}
