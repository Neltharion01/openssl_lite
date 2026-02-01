use core::fmt;
use core::ffi::{CStr, c_char};
use std::io::{self, ErrorKind};
use std::error::Error;

use crate::sys;

#[derive(Debug)]
pub struct ErrorStack(pub Vec<String>);

impl ErrorStack {
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
        for err in &self.0 {
            write!(f, "{err}\n")?;
        }
        Ok(())
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

#[derive(Debug)]
pub enum SslError {
    ZeroReturn,
    Syscall(io::Error),
    Ssl(ErrorStack),
    WantRead, WantWrite,
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
