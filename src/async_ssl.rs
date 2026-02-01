use core::ffi::CStr;
use core::task::{Poll, Context, ready};
use core::pin::Pin;

use std::io;

use tokio::net::TcpStream;
use tokio::io::{AsyncRead, ReadBuf, AsyncWrite};
use pin_project_lite::pin_project;

use crate::{SslCtx, Ssl, ErrorStack, SslError};

// Don't forget to manually shut down

pin_project! {
    #[derive(Debug)]
    pub struct AsyncSsl {
        ssl: Ssl,
        stream: TcpStream,
    }
}

impl AsyncSsl {
    pub fn new(ctx: &SslCtx, stream: TcpStream) -> Result<AsyncSsl, ErrorStack> {
        let mut ssl = Ssl::new(ctx)?;
        ssl.set_fd(&stream)?;
        Ok(AsyncSsl { ssl, stream })
    }

    pub fn set_hostname(&mut self, hostname: &CStr) -> Result<(), ErrorStack> {
        self.ssl.set_hostname(hostname)
    }

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
        todo!()
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
