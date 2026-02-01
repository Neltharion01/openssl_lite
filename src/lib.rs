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
