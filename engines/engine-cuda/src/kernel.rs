use crate::error::CudaError;

pub const KERNEL_MD5: &str = include_str!("kernels/md5.cu");
pub const KERNEL_SHA1: &str = include_str!("kernels/sha1.cu");
pub const KERNEL_SHA256: &str = include_str!("kernels/sha256.cu");
pub const KERNEL_SHA512: &str = include_str!("kernels/sha512.cu");
pub const KERNEL_NTLM: &str = include_str!("kernels/ntlm.cu");
pub const KERNEL_BCRYPT: &str = include_str!("kernels/bcrypt.cu");

pub fn compile_kernel(src: &str, name: &str, _arch: &str) -> Result<Vec<u8>, CudaError> {
    #[cfg(feature = "cuda")]
    return crate::compile_ptx(src, _arch);
    #[cfg(not(feature = "cuda"))]
    {
        let _ = (src, name, _arch);
        Err(CudaError::NoCudaSupport)
    }
}
