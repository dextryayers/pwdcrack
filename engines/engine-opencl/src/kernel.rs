use crate::error::OpenclError;

pub const CL_MD5: &str = include_str!("kernels/md5.cl");
pub const CL_SHA1: &str = include_str!("kernels/sha1.cl");
pub const CL_SHA256: &str = include_str!("kernels/sha256.cl");
pub const CL_SHA512: &str = include_str!("kernels/sha512.cl");
pub const CL_NTLM: &str = include_str!("kernels/ntlm.cl");
pub const CL_BCRYPT: &str = include_str!("kernels/bcrypt.cl");

pub fn get_kernel(name: &str) -> Result<&'static str, OpenclError> {
    match name {
        "md5" | "MD5" => Ok(CL_MD5),
        "sha1" | "SHA1" => Ok(CL_SHA1),
        "sha256" | "SHA256" => Ok(CL_SHA256),
        "sha512" | "SHA512" => Ok(CL_SHA512),
        "ntlm" | "NTLM" => Ok(CL_NTLM),
        "bcrypt" | "BCrypt" | "bcrypt" => Ok(CL_BCRYPT),
        _ => Err(OpenclError::UnsupportedHash),
    }
}
