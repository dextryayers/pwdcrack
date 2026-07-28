pub struct XpuKernel {
    pub name: String,
    pub source: String,
    pub local_size: (u32, u32, u32),
    pub global_size: (u32, u32, u32),
}

impl XpuKernel {
    pub fn new(name: &str, source: &str) -> Self {
        Self {
            name: name.to_string(),
            source: source.to_string(),
            local_size: (64, 1, 1),
            global_size: (1024, 1, 1),
        }
    }

    pub fn md5_xpu_kernel() -> Self {
        Self::new("md5_xpu", r#"
#include <clc/clc.h>
__kernel void md5_xpu(__global const uint* words, __global const uchar* target, __global uint* results) {
    int gid = get_global_id(0);
    uint hash[4];
    md5_hash(words + gid * 16, hash);
    if ((hash[0] & 0xff) == target[0]) results[gid] = 1;
}
"#)
    }

    pub fn isp_c_kernel() -> Self {
        Self::new("ispc_fallback", r#"
export void ispc_kernel(uniform const uint words[], uniform const uchar target[], uniform uint results[], uniform int count) {
    foreach (i = 0 ... count) {
        uint hash[4];
        md5_hash(&words[i * 16], hash);
        if ((hash[0] & 0xff) == target[0]) results[i] = 1;
    }
}
"#)
    }
}
