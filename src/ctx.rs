use core::ffi::CStr;

use crate::sys;
use crate::ErrorStack;

pub struct SslCtx(pub(crate) *mut sys::SSL_CTX);

impl SslCtx {
    fn new() -> Result<SslCtx, ErrorStack> {
        let ptr = unsafe { sys::SSL_CTX_new(sys::TLS_method()) };
        if ptr.is_null() { return Err(ErrorStack::get()); }

        let mut ctx = SslCtx(ptr);
        ctx.set_default_verify_paths()?;
        ctx.set_tls12()?;
        ctx.set_verify(true);

        Ok(ctx)
    }

    pub fn new_client() -> Result<SslCtx, ErrorStack> {
        let mut ctx = SslCtx::new()?;
        ctx.set_cipher_list(c"DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK")?;
        Ok(ctx)
    }

    pub fn new_server() -> Result<SslCtx, ErrorStack> {
        let mut ctx = SslCtx::new()?;
        ctx.set_cipher_list(
            c"ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
              ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
              DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
        )?;
        Ok(ctx)
    }

    fn set_cipher_list(&mut self, list: &CStr) -> Result<(), ErrorStack> {
        let ret = unsafe { sys::SSL_CTX_set_cipher_list(self.0, list.as_ptr()) };
        if ret == 0 { return Err(ErrorStack::get()); }
        /* success == 1 */ Ok(())
    }

    fn set_default_verify_paths(&mut self) -> Result<(), ErrorStack> {
        let ret = unsafe { sys::SSL_CTX_set_default_verify_paths(self.0) };
        if ret == 0 { return Err(ErrorStack::get()); }
        /* success == 1 */ Ok(())
    }

    fn set_tls12(&mut self) -> Result<(), ErrorStack> {
        let ret = unsafe { sys::SSL_CTX_set_min_proto_version(self.0, sys::TLS1_2_VERSION) };
        if ret == 0 { return Err(ErrorStack::get()); }
        /* success == 1 */ Ok(())
    }

    pub fn set_verify(&mut self, verify: bool) {
        let mode = if verify { sys::SSL_VERIFY_PEER } else { sys::SSL_VERIFY_NONE };
        unsafe { sys::SSL_CTX_set_verify(self.0, mode, core::ptr::null()) };
    }

    pub fn load_certificate_chain(&mut self, certificate: &CStr, key: &CStr) -> Result<(), ErrorStack> {
        let ret = unsafe { sys::SSL_CTX_use_certificate_file(self.0, certificate.as_ptr(), sys::SSL_FILETYPE_PEM) };
        if ret == 0 { return Err(ErrorStack::get()); }

        let ret = unsafe { sys::SSL_CTX_use_PrivateKey_file(self.0, key.as_ptr(), sys::SSL_FILETYPE_PEM) };
        if ret == 0 { return Err(ErrorStack::get()); }

        let ret = unsafe { sys::SSL_CTX_check_private_key(self.0) };
        if ret == 0 { return Err(ErrorStack::get()); }

        Ok(())
    }
}

impl Drop for SslCtx {
    fn drop(&mut self) {
        unsafe { sys::SSL_CTX_free(self.0) };
    }
}
