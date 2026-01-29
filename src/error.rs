use core::fmt;
use core::ffi::{CStr, c_char};
use std::io::Error as IoError;
use std::error::Error;

use crate::sys;

#[derive(Debug)]
pub struct ErrorStack {
    pub errors: Vec<String>,
}

impl ErrorStack {
    pub fn get() -> ErrorStack {
        let mut errors = vec![];
        while let Some(err) = get_error() {
            errors.push(err);
        }
        ErrorStack { errors }
    }
}

impl fmt::Display for ErrorStack {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for err in &self.errors {
            write!(f, "{err}\n")?;
        }
        Ok(())
    }
}

impl Error for ErrorStack {}

impl From<ErrorStack> for IoError {
    fn from(es: ErrorStack) -> IoError {
        IoError::other(es)
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
