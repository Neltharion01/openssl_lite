pub(crate) mod sys;

mod error;
pub use error::ErrorStack;
mod ctx;
pub use ctx::SslCtx;
mod ssl;
pub use ssl::Ssl;

// Very important TODOs:
// - Ssl::flush
// - Hostname verification (!!!)
// - Rustdoc
