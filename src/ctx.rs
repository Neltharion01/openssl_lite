use core::ffi::{CStr, c_long};

use crate::sys;
use crate::ErrorStack;

/// SSL context
pub struct SslCtx(pub(crate) *mut sys::SSL_CTX);

unsafe impl Send for SslCtx {}
unsafe impl Sync for SslCtx {}

impl SslCtx {
    /// Construct a new SSL context
    ///
    /// By default, verifies certificates and only accepts TLSv1.2 and newer
    #[doc(alias = "SSL_CTX_new")]
    pub fn new() -> Result<SslCtx, ErrorStack> {
        let ptr = unsafe { sys::SSL_CTX_new(sys::TLS_method()) };
        if ptr.is_null() { return Err(ErrorStack::get()); }

        let mut ctx = SslCtx(ptr);
        ctx.set_min_version(crate::version::TLS1_2_VERSION)?;
        ctx.set_verify(true);

        Ok(ctx)
    }

    /// Sets default verify paths
    ///
    /// You always need this for client
    #[doc(alias = "SSL_CTX_set_default_verify_paths")]
    pub fn set_default_verify_paths(&mut self) -> Result<(), ErrorStack> {
        let ret = unsafe { sys::SSL_CTX_set_default_verify_paths(self.0) };
        if ret == 0 { return Err(ErrorStack::get()); }
        /* success == 1 */ Ok(())
    }

    /// Set min TLS version. Accepts constants from [`crate::version`]
    ///
    /// By default, it is TLS 1.2
    #[doc(alias = "SSL_CTX_set_min_proto_version")]
    pub fn set_min_version(&mut self, ver: c_long) -> Result<(), ErrorStack> {
        let ret = unsafe { sys::SSL_CTX_set_min_proto_version(self.0, ver) };
        if ret == 0 { return Err(ErrorStack::get()); }
        /* success == 1 */ Ok(())
    }

    /// Set supported cipher list
    #[doc(alias = "SSL_CTX_set_cipher_list")]
    pub fn set_cipher_list(&mut self, list: &CStr) -> Result<(), ErrorStack> {
        let ret = unsafe { sys::SSL_CTX_set_cipher_list(self.0, list.as_ptr()) };
        if ret == 0 { return Err(ErrorStack::get()); }
        /* success == 1 */ Ok(())
    }

    /// Sets SSL options. Check `SSL_CTX_set_options` manpage for available options.
    ///
    /// Accepts constants from [`crate::op`]
    ///
    /// These are for legacy compatibility, and almost always you don't need them
    #[doc(alias = "SSL_CTX_set_options")]
    pub fn set_options(&mut self, opts: u64) {
        unsafe { sys::SSL_CTX_set_options(self.0, opts) };
    }

    /// Enable/disable certificate verification
    #[doc(alias = "SSL_CTX_set_verify")]
    pub fn set_verify(&mut self, verify: bool) {
        let mode = if verify { sys::SSL_VERIFY_PEER } else { sys::SSL_VERIFY_NONE };
        unsafe { sys::SSL_CTX_set_verify(self.0, mode, core::ptr::null()) };
    }

    /// Load server's certificate and private key files
    #[doc(alias = "SSL_CTX_use_certificate_file", alias = "SSL_CTX_use_PrivateKey_file", alias = "SSL_CTX_check_private_key")]
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
