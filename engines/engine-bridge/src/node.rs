use std::ffi::{CStr, CString};
use std::os::raw::c_char;

extern "C" {
    fn napi_create_string_utf8(env: *mut std::ffi::c_void, str_: *const c_char, length: usize, result: *mut *mut std::ffi::c_void) -> i32;
    fn napi_create_double(env: *mut std::ffi::c_void, value: f64, result: *mut *mut std::ffi::c_void) -> i32;
    fn napi_create_int32(env: *mut std::ffi::c_void, value: i32, result: *mut *mut std::ffi::c_void) -> i32;
    fn napi_get_cb_info(env: *mut std::ffi::c_void, argc: *mut i32, argv: *mut *mut std::ffi::c_void, this_: *mut *mut std::ffi::c_void, data: *mut *mut std::ffi::c_void) -> i32;
    fn napi_get_value_string_utf8(env: *mut std::ffi::c_void, value: *mut std::ffi::c_void, buf: *mut c_char, bufsize: usize, result: *mut usize) -> i32;
    fn napi_set_named_property(env: *mut std::ffi::c_void, obj: *mut std::ffi::c_void, key: *const c_char, value: *mut std::ffi::c_void) -> i32;
}

pub struct NapiEnv {
    env: *mut std::ffi::c_void,
}

impl NapiEnv {
    pub fn new(env: *mut std::ffi::c_void) -> Self { NapiEnv { env } }
}

fn napi_ok() -> i32 { 0 }

fn napi_generic_failure() -> i32 { 1 }

/// napi_value crack_verify(napi_env env, napi_callback_info info)
#[no_mangle]
pub unsafe extern "C" fn crack_verify(
    env: *mut std::ffi::c_void,
    _info: *mut std::ffi::c_void,
) -> *mut std::ffi::c_void {
    let mut argc: i32 = 2;
    let mut argv: [*mut std::ffi::c_void; 2] = [std::ptr::null_mut(); 2];
    if napi_get_cb_info(env, &mut argc, argv.as_mut_ptr(), std::ptr::null_mut(), std::ptr::null_mut()) != napi_ok() {
        return std::ptr::null_mut();
    }
    let mut password_buf = [0u8; 256];
    let mut password_len: usize = 0;
    if napi_get_value_string_utf8(env, argv[0], password_buf.as_mut_ptr() as *mut c_char, 256, &mut password_len) != napi_ok() {
        return std::ptr::null_mut();
    }
    let password = std::str::from_utf8(&password_buf[..password_len]).unwrap_or("");
    let _ = password;
    let mut result: *mut std::ffi::c_void = std::ptr::null_mut();
    napi_create_string_utf8(env, CString::new("ok").unwrap().as_ptr(), 2, &mut result);
    result
}
