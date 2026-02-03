use core::fmt;
use core::ffi::{CStr, c_char};
use std::io::{self, ErrorKind};
use std::error::Error;

use crate::sys;

/// OpenSSL error stack
#[derive(Debug)]
pub struct ErrorStack(pub Vec<String>);

impl ErrorStack {
    /// Retrieves the error stack. Usually, you don't need this
    pub fn get() -> ErrorStack {
        let mut errors = vec![];
        while let Some(err) = get_error() {
            errors.push(err);
        }
        ErrorStack(errors)
    }
}

impl fmt::Display for ErrorStack {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.0.is_empty() {
            f.write_str("Empty SSL error stack")
        } else {
            f.write_str(&self.0[0])
        }
    }
}

impl Error for ErrorStack {}

impl From<ErrorStack> for io::Error {
    fn from(es: ErrorStack) -> io::Error {
        io::Error::other(es)
    }
}

fn get_error() -> Option<String> {
    let code = unsafe { sys::ERR_get_error() };
    if code == 0 { return None; }

    let mut buf = [0u8; 256];
    unsafe { sys::ERR_error_string_n(code, buf.as_mut_ptr() as *mut c_char, buf.len()); }

    let s = match CStr::from_bytes_until_nul(&buf) {
        Ok(s) => s.to_string_lossy().into_owned(),
        Err(_) => "Error too long".to_string(), // Never happens
    };

    Some(s)
}

/// Error returned by the SSL object methods
///
/// Can be automatically converted to [`std::io::Error`]
#[derive(Debug)]
pub enum SslError {
    /// `SSL_ERROR_ZERO_RETURN`: The socket does not have any more data because it has been closed
    ZeroReturn,
    /// `SSL_ERROR_SYSCALL`: A fatal I/O error occured, and no more operations should be performed on this object
    Syscall(io::Error),
    /// `SSL_ERROR_SSL`: Non-recoverable protocol error
    Ssl(ErrorStack),
    /// `SSL_ERROR_WANT_READ`: The operation was not completed and can be retried after socket becomes readable
    WantRead,
    /// `SSL_ERROR_WANT_WRITE`: Same as `WantRead`, but socket has to become writable
    WantWrite,
    /// Unspecified error
    Other,
}

impl From<SslError> for io::Error {
    fn from(err: SslError) -> io::Error {
        use SslError::*;
        match err {
            ZeroReturn => ErrorKind::UnexpectedEof.into(),
            Syscall(err) => err,
            Ssl(es) => es.into(),
            WantRead | WantWrite => ErrorKind::WouldBlock.into(),
            Other => ErrorKind::Other.into(),
        }
    }
}

impl From<io::Error> for SslError {
    fn from(err: io::Error) -> SslError {
        SslError::Syscall(err)
    }
}

impl fmt::Display for SslError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use SslError::*;
        match self {
            ZeroReturn => f.write_str("zero return"),
            Syscall(err) => write!(f, "syscall: {err}"),
            Ssl(es) => write!(f, "ssl error: {es}"),
            WantRead => f.write_str("want read"),
            WantWrite => f.write_str("want write"),
            Other => f.write_str("other ssl error"),
        }
    }
}

impl Error for SslError {}
