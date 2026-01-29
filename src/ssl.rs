use core::ffi::c_int;
use std::io::{self, Read, Write, ErrorKind};

#[cfg(windows)]
use std::os::windows::IntoRawHandle;
#[cfg(unix)]
use std::os::fd::IntoRawFd;

use crate::sys;
use crate::{SslCtx, ErrorStack};

pub struct Ssl(*mut sys::SSL);

// All non-reentrant methods take &mut ref
unsafe impl Send for Ssl {}
unsafe impl Sync for Ssl {}

impl Ssl {
    pub fn new(ctx: &SslCtx) -> Result<Ssl, ErrorStack> {
        let ptr = unsafe { sys::SSL_new(ctx.0) };
        if ptr.is_null() { return Err(ErrorStack::get()); }
        Ok(Ssl(ptr))
    }

    #[cfg(windows)]
    pub fn set_fd(&mut self, fd: impl IntoRawHandle) -> Result<(), ErrorStack> {
        let ret = unsafe { sys::SSL_set_fd(self.0, fd.into_raw_handle() as c_int) };
        if ret == 0 { return Err(ErrorStack::get()); }
        /* success == 1 */ Ok(())
    }

    #[cfg(unix)]
    pub fn set_fd(&mut self, fd: impl IntoRawFd) -> Result<(), ErrorStack> {
        let ret = unsafe { sys::SSL_set_fd(self.0, fd.into_raw_fd()) };
        if ret == 0 { return Err(ErrorStack::get()); }
        /* success == 1 */ Ok(())
    }

    pub fn connect(&mut self) -> io::Result<()> {
        let ret = unsafe { sys::SSL_connect(self.0) };
        if ret == 1 { return Ok(()); }
        Err(self.make_error(ret))
    }

    pub fn shutdown(&mut self) -> io::Result<()> {
        while self.do_shutdown()? != 1 {}
        Ok(())
    }

    fn do_shutdown(&mut self) -> io::Result<c_int> {
        let ret = unsafe { sys::SSL_shutdown(self.0) };
        if ret < 0 { return Err(self.make_error(ret)); }
        Ok(ret)
    }

    fn make_error(&self, ret: c_int) -> io::Error {
        use sys::error::*;

        let code = unsafe { sys::SSL_get_error(self.0, ret) };
        match code {
            SSL_ERROR_SSL | SSL_ERROR_SYSCALL => io::Error::other(ErrorStack::get()),
            SSL_ERROR_ZERO_RETURN => ErrorKind::UnexpectedEof.into(),
            SSL_ERROR_WANT_READ | SSL_ERROR_WANT_WRITE => ErrorKind::WouldBlock.into(),
            _ => ErrorKind::Other.into(),
        }
    }
}

impl Read for Ssl {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() { return Ok(0); }
        let len = usize::min(buf.len(), c_int::MAX as usize) as c_int;
        let ret = unsafe { sys::SSL_read(self.0, buf.as_mut_ptr(), len) };
        if ret <= 0 {
            let err = self.make_error(ret);
            if err.kind() == ErrorKind::UnexpectedEof { return Ok(0); }
            return Err(err);
        }
        Ok(ret as usize)
    }
}

impl Write for Ssl {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() { return Ok(0); }
        let len = usize::min(buf.len(), c_int::MAX as usize) as c_int;
        let ret = unsafe { sys::SSL_write(self.0, buf.as_ptr(), len) };
        if ret <= 0 {
            let err = self.make_error(ret);
            if err.kind() == ErrorKind::UnexpectedEof { return Ok(0); }
            return Err(err);
        }
        Ok(ret as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        todo!()
    }
}

impl Drop for Ssl {
    fn drop(&mut self) {
        let _ = self.shutdown();
        unsafe { sys::SSL_free(self.0) };
    }
}
