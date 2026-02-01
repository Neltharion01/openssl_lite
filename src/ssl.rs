use core::ffi::{CStr, c_int};
use std::io::{self, Read, Write};

#[cfg(windows)]
use std::os::windows::AsRawHandle;
#[cfg(unix)]
use std::os::fd::AsRawFd;

use crate::sys;
use crate::{SslCtx, ErrorStack, SslError};

/// Main SSL object
///
/// Example usage:
/// ```
/// # fn main() -> std::io::Result<()> {
/// # use openssl_lite::{SslCtx, Ssl};
/// let ctx = SslCtx::new()?;
/// let mut ssl = Ssl::new(&ctx)?;
/// ssl.set_hostname(c"Neltharion01.github.io");
/// # /*
/// // Does not take ownership of your socket!
/// ssl.set_fd(&socket);
/// ssl.connect()?;
///
/// // Now call ssl.read(), ssl.write()
///
/// // After you are done, close the connection
/// ssl.shutdown()?;
/// # */
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Ssl(*mut sys::SSL);

// All non-reentrant methods take &mut ref
unsafe impl Send for Ssl {}
unsafe impl Sync for Ssl {}

impl Ssl {
    /// Constructs a new SSL object from the given context
    #[doc(alias = "SSL_new")]
    pub fn new(ctx: &SslCtx) -> Result<Ssl, ErrorStack> {
        let ptr = unsafe { sys::SSL_new(ctx.0) };
        if ptr.is_null() { return Err(ErrorStack::get()); }
        Ok(Ssl(ptr))
    }

    /// Sets SNI and hostname for verification
    #[doc(alias = "SSL_set1_host", alias = "SSL_set_tlsext_host_name")]
    pub fn set_hostname(&mut self, hostname: &CStr) -> Result<(), ErrorStack> {
        let ret = unsafe { sys::SSL_set1_host(self.0, hostname.as_ptr()) };
        if ret == 0 { return Err(ErrorStack::get()); }

        let ret = unsafe { sys::SSL_set_tlsext_host_name(self.0, hostname.as_ptr()) };
        if ret == 0 { return Err(ErrorStack::get()); }

        Ok(())
    }

    /// Sets the socket handle to be used for TLS
    #[doc(alias = "SSL_set_fd")]
    #[cfg(windows)]
    pub fn set_fd(&mut self, fd: &impl AsRawHandle) -> Result<(), ErrorStack> {
        let ret = unsafe { sys::SSL_set_fd(self.0, fd.as_raw_handle() as c_int) };
        if ret == 0 { return Err(ErrorStack::get()); }
        /* success == 1 */ Ok(())
    }

    /// Sets the file descriptor to be used for TLS
    #[doc(alias = "SSL_set_fd")]
    #[cfg(unix)]
    pub fn set_fd(&mut self, fd: &impl AsRawFd) -> Result<(), ErrorStack> {
        let ret = unsafe { sys::SSL_set_fd(self.0, fd.as_raw_fd()) };
        if ret == 0 { return Err(ErrorStack::get()); }
        /* success == 1 */ Ok(())
    }

    /// Performs the SSL connection as a client
    #[doc(alias = "SSL_connect")]
    pub fn connect(&mut self) -> Result<(), SslError> {
        let ret = unsafe { sys::SSL_connect(self.0) };
        if ret == 1 { return Ok(()); }
        Err(self.make_error(ret))
    }

    /// Gracefully closes the connection
    #[doc(alias = "SSL_shutdown")]
    pub fn shutdown(&mut self) -> Result<(), SslError> {
        loop {
            let ret = unsafe { sys::SSL_shutdown(self.0) };
            match ret {
                1 => return Ok(()),
                0 => continue, // retry
                _ => return Err(self.make_error(ret)),
            }
        }
    }

    fn make_error(&self, ret: c_int) -> SslError {
        use sys::error::*;

        let code = unsafe { sys::SSL_get_error(self.0, ret) };
        match code {
            SSL_ERROR_ZERO_RETURN => SslError::ZeroReturn,
            SSL_ERROR_SYSCALL => SslError::Syscall(io::Error::last_os_error()),
            SSL_ERROR_SSL => SslError::Ssl(ErrorStack::get()),
            SSL_ERROR_WANT_READ => SslError::WantRead,
            SSL_ERROR_WANT_WRITE => SslError::WantWrite,
            _ => SslError::Other,
        }
    }

    /// Accepts the SSL connection as a server
    #[doc(alias = "SSL_accept")]
    pub fn accept(&mut self) -> Result<(), SslError> {
        let ret = unsafe { sys::SSL_accept(self.0) };
        if ret == 1 { return Ok(()); }
        /* ret <= 0 */ Err(self.make_error(ret))
    }

    /// Performs SSL read, returning SSL error
    ///
    /// Also implements [`std::io::Read`]
    #[doc(alias = "SSL_read")]
    pub fn ssl_read(&mut self, buf: &mut [u8]) -> Result<usize, SslError> {
        // Can't read with empty buffer because ret == 0 means error
        if buf.is_empty() { return Ok(0); }
        let len = usize::min(buf.len(), c_int::MAX as usize) as c_int;
        let ret = unsafe { sys::SSL_read(self.0, buf.as_mut_ptr(), len) };
        if ret <= 0 {
            let err = self.make_error(ret);
            if matches!(err, SslError::ZeroReturn) { return Ok(0); }
            return Err(err.into());
        }
        Ok(ret as usize)
    }

    /// Performs SSL write, returning SSL error
    ///
    /// Also implements [`std::io::Write`]
    #[doc(alias = "SSL_write")]
    pub fn ssl_write(&mut self, buf: &[u8]) -> Result<usize, SslError> {
        // Can't write with empty buffer because ret == 0 means error
        if buf.is_empty() { return Ok(0); }
        let len = usize::min(buf.len(), c_int::MAX as usize) as c_int;
        let ret = unsafe { sys::SSL_write(self.0, buf.as_ptr(), len) };
        if ret <= 0 {
            return Err(self.make_error(ret).into());
        }
        Ok(ret as usize)
    }
}

impl Read for Ssl {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.ssl_read(buf).map_err(|e| e.into())
    }
}

impl Write for Ssl {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.ssl_write(buf).map_err(|e| e.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for Ssl {
    fn drop(&mut self) {
        let _ = self.shutdown();
        unsafe { sys::SSL_free(self.0) };
    }
}
