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

// Very important TODOs:
// - Rustdoc
