use core::ffi::CStr;
use core::task::{Poll, Context, ready};
use core::pin::Pin;

use std::io;

use tokio::net::TcpStream;
use tokio::io::{AsyncRead, ReadBuf, AsyncWrite};
use pin_project_lite::pin_project;

use crate::{SslCtx, Ssl, ErrorStack, SslError};

pin_project! {
    /// Async version of [`Ssl`], implements [`tokio::io::AsyncRead`] and [`tokio::io::AsyncWrite`]
    ///
    /// Example usage:
    /// ```ignore
    /// let ctx = SslCtx::new()?;
    /// let mut ssl = AsyncSsl::new(&ctx, socket)?;
    /// ssl.set_hostname(c"Neltharion01.github.io");
    /// ssl.connect().await?;
    ///
    /// // Async versions of ssl.read(), ssl.write() are available
    /// // To use, import:
    /// // use tokio::io::{AsyncReadExt, AsyncWriteExt};
    ///
    /// // After you are done, close the connection
    /// ssl.shutdown().await?;
    /// ```
    /// Async version DOES NOT close the connection automatically!
    /// Always make sure that you have closed it by calling `ssl.shutdown().await`
    #[derive(Debug)]
    pub struct AsyncSsl {
        ssl: Ssl,
        stream: TcpStream,
    }
}

impl AsyncSsl {
    /// Constructs a new async SSL
    pub fn new(ctx: &SslCtx, stream: TcpStream) -> Result<AsyncSsl, ErrorStack> {
        let mut ssl = Ssl::new(ctx)?;
        ssl.set_fd(&stream)?;
        Ok(AsyncSsl { ssl, stream })
    }

    /// Sets the hostname for verification
    pub fn set_hostname(&mut self, hostname: &CStr) -> Result<(), ErrorStack> {
        self.ssl.set_hostname(hostname)
    }

    /// Performs the connection as a client
    pub async fn connect(&mut self) -> Result<(), SslError> {
        loop {
            let ret = self.ssl.connect();
            match ret {
                Err(SslError::WantRead) => self.stream.readable().await?,
                Err(SslError::WantWrite) => self.stream.writable().await?,
                other => return other,
            }
        }
    }

    /// Accepts the connection as a server
    pub async fn accept(&mut self) -> Result<(), SslError> {
        loop {
            let ret = self.ssl.accept();
            match ret {
                Err(SslError::WantRead) => self.stream.readable().await?,
                Err(SslError::WantWrite) => self.stream.writable().await?,
                other => return other,
            }
        }
    }
}

impl AsyncRead for AsyncSsl {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let me = self.project();
        loop {
            let ret = me.ssl.ssl_read(buf.initialize_unfilled());
            match ret {
                Ok(n) => { buf.advance(n); return Poll::Ready(Ok(())) },
                Err(SslError::WantRead) => ready!(me.stream.poll_read_ready(cx))?,
                Err(SslError::WantWrite) => ready!(me.stream.poll_write_ready(cx))?,
                Err(other) => return Poll::Ready(Err(other.into())),
            };
        }
    }
}

impl AsyncWrite for AsyncSsl {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let me = self.project();
        loop {
            let ret = me.ssl.ssl_write(buf);
            match ret {
                Ok(n) => return Poll::Ready(Ok(n)),
                Err(SslError::WantRead) => ready!(me.stream.poll_read_ready(cx))?,
                Err(SslError::WantWrite) => ready!(me.stream.poll_write_ready(cx))?,
                Err(other) => return Poll::Ready(Err(other.into())),
            };
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.project();
        loop {
            let ret = me.ssl.shutdown();
            match ret {
                Ok(()) => return Poll::Ready(Ok(())),
                Err(SslError::WantRead) => ready!(me.stream.poll_read_ready(cx))?,
                Err(SslError::WantWrite) => ready!(me.stream.poll_write_ready(cx))?,
                Err(other) => return Poll::Ready(Err(other.into())),
            };
        }
    }
}
