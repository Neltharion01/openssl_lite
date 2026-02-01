#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use core::ffi::{c_int, c_ulong, c_long, c_char, c_void};

// Those are uninhabited void pointers
#[repr(C)]
pub struct SSL([u8; 0]);
#[repr(C)]
pub struct SSL_CTX([u8; 0]);
#[repr(C)]
pub struct SSL_METHOD([u8; 0]);

pub const SSL_VERIFY_NONE: c_int = 0;
pub const SSL_VERIFY_PEER: c_int = 1;

pub const SSL_CTRL_SET_MIN_PROTO_VERSION: c_int = 123;
pub const TLS1_2_VERSION: c_long = 0x0303;
pub const SSL_CTRL_SET_TLSEXT_HOSTNAME: c_int = 55;
pub const TLSEXT_NAMETYPE_host_name: c_long = 0;

pub const SSL_FILETYPE_PEM: c_int = 1;

pub mod error {
    use core::ffi::c_int;

    pub const SSL_ERROR_SSL: c_int = 1;
    pub const SSL_ERROR_WANT_READ: c_int = 2;
    pub const SSL_ERROR_WANT_WRITE: c_int = 3;
    pub const SSL_ERROR_SYSCALL: c_int = 5;
    pub const SSL_ERROR_ZERO_RETURN: c_int = 6;
}

unsafe extern "C" {
    pub fn TLS_method() -> *const SSL_METHOD;
    pub fn SSL_CTX_new(method: *const SSL_METHOD) -> *mut SSL_CTX;
    //pub fn SSL_CTX_set_alpn_protos(ctx: *mut SSL_CTX, protos: *const u8, protos_len: c_int) -> c_int;
    pub fn SSL_CTX_set_default_verify_paths(ctx: *mut SSL_CTX) -> c_int;
    pub fn SSL_CTX_set_verify(ctx: *mut SSL_CTX, mode: c_int, verify_callback: *const c_void);
    pub fn SSL_CTX_ctrl(ctx: *mut SSL_CTX, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn SSL_CTX_use_certificate_file(ctx: *mut SSL_CTX, file: *const c_char, _type: c_int) -> c_int;
    pub fn SSL_CTX_use_PrivateKey_file(ctx: *mut SSL_CTX, file: *const c_char, _type: c_int) -> c_int;
    pub fn SSL_CTX_check_private_key(ctx: *mut SSL_CTX) -> c_int;

    pub fn SSL_CTX_free(ctx: *mut SSL_CTX);

    pub fn SSL_new(ctx: *mut SSL_CTX) -> *mut SSL;
    pub fn SSL_ctrl(ctx: *mut SSL, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn SSL_set1_host(ssl: *mut SSL, name: *const c_char) -> c_int;
    pub fn SSL_set_fd(ssl: *mut SSL, fd: c_int) -> c_int;
    pub fn SSL_connect(ssl: *mut SSL) -> c_int;
    pub fn SSL_accept(ssl: *mut SSL) -> c_int;
    pub fn SSL_read(ssl: *mut SSL, buf: *mut u8, num: c_int) -> c_int;
    pub fn SSL_write(ssl: *mut SSL, buf: *const u8, num: c_int) -> c_int;
    pub fn SSL_get_error(ssl: *const SSL, ret: c_int) -> c_int;
    pub fn SSL_shutdown(ssl: *mut SSL) -> c_int;
    pub fn SSL_free(ssl: *mut SSL);

    pub fn ERR_get_error() -> c_ulong;
    pub fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);
}

// implemented in C macros
pub unsafe fn SSL_CTX_set_min_proto_version(ctx: *mut SSL_CTX, version: c_long) -> c_long {
    unsafe { SSL_CTX_ctrl(ctx, SSL_CTRL_SET_MIN_PROTO_VERSION, version, core::ptr::null_mut()) }
}

pub unsafe fn SSL_set_tlsext_host_name(ssl: *mut SSL, name: *const c_char) -> c_long {
    unsafe { SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, name as *mut c_void) }
}
