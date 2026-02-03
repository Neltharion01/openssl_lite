//! Lightweight OpenSSL bindings for Rust (with tokio support)
//!
//! For sync usage example, check [`Ssl`]
#![cfg_attr(feature = "tokio", doc = "")]
#![cfg_attr(feature = "tokio", doc = "For async usage example, check [`AsyncSsl`]")]
//!
//! Also, a simple server/client is available in `src/main.rs`. Build with:
//! `cargo build --release --features=cmd`

pub(crate) mod sys;

mod error;
pub use error::{ErrorStack, SslError};
mod ctx;
pub use ctx::SslCtx;
mod ssl;
pub use ssl::Ssl;

#[cfg(feature = "tokio")]
mod async_ssl;
#[cfg(feature = "tokio")]
pub use async_ssl::AsyncSsl;

/// TLS versions for [`SslCtx::set_min_version`]
pub mod version {
    use core::ffi::c_long;

    pub const TLS1_0_VERSION: c_long = 0x0301;
    pub const TLS1_1_VERSION: c_long = 0x0302;
    pub const TLS1_2_VERSION: c_long = 0x0303;
    pub const TLS1_3_VERSION: c_long = 0x0304;
}
