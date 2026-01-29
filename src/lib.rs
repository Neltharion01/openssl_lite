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
// - Server allowed ciphers:
// ctx.set_cipher_list(
//     "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:\
//      ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
//      DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
// )?;
// - Client allowed ciphers:
// ctx.set_cipher_list("DEFAULT:!aNULL:!eNULL:!MD5:!3DES:!DES:!RC4:!IDEA:!SEED:!aDSS:!SRP:!PSK")?;
// - Rustdoc
