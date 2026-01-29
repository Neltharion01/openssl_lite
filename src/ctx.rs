use crate::sys;
use crate::ErrorStack;

pub struct SslCtx(pub(crate) *mut sys::SSL_CTX);

impl SslCtx {
    pub fn new() -> Result<SslCtx, ErrorStack> {
        let ptr = unsafe { sys::SSL_CTX_new(sys::TLS_method()) };
        if ptr.is_null() { return Err(ErrorStack::get()); }

        let mut ctx = SslCtx(ptr);
        ctx.set_default_verify_paths()?;
        ctx.set_tls12()?;
        ctx.set_verify(true);

        Ok(ctx)
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
}

impl Drop for SslCtx {
    fn drop(&mut self) {
        unsafe { sys::SSL_CTX_free(self.0) };
    }
}
