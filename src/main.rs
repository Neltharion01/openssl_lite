use std::io;

use openssl_lite::{SslCtx, Ssl, AsyncSsl};

fn help() -> ! {
    eprintln!("Usage: openssl_lite <cmd>");
    eprintln!("Available commands:");
    eprintln!("    s_client <addr>");
    eprintln!("    s_server <addr>");
    eprintln!("Add flag `-tokio` to use async version");
    eprintln!("Add flag `-insecure` to disable peer verification");
    std::process::exit(1)
}

fn main() -> io::Result<()> {
    let mut args = std::env::args();
    /* skip first */ args.next();
    let Some(cmd) = args.next() else { help() };
    if cmd != "s_client" && cmd != "s_server" { help(); }
    let mut tokio = false;
    let mut insecure = false;
    let mut addr = String::new();
    for a in args {
        match a.as_str() {
            "-tokio" => tokio = true,
            "-insecure" => insecure = true,
            a if addr.is_empty() => addr = a.to_string(),
            _ => help(),
        }
    }

    if cmd == "s_client" && !tokio {
        s_client(&addr, insecure)?;
    } else if cmd == "s_client" && tokio {
        s_client_tokio(&addr, insecure)?;
    } else if cmd == "s_server" && !tokio {
        s_server(&addr)?;
    } else if cmd == "s_server" && tokio {
        s_server_tokio(&addr)?;
    } else {
        eprintln!("Unknown command!");
        help();
    }

    Ok(())
}

fn s_client(addr: &str, insecure: bool) -> io::Result<()> {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::ffi::CString;

    let mut ctx = SslCtx::new()?;
    ctx.set_default_verify_paths()?;
    ctx.set_verify(!insecure);

    let sock = TcpStream::connect(addr)?;
    sock.set_nodelay(true)?;

    let domain = addr.split(':').next().unwrap();
    let mut ssl = Ssl::new(&ctx)?;
    ssl.set_hostname(&CString::new(domain).unwrap())?;
    ssl.set_fd(&sock)?; // This calls AsRawFd
    ssl.connect()?;

    // Read stdin
    let mut buf = vec![];
    io::stdin().read_to_end(&mut buf).expect("stdin");
    ssl.write_all(&buf)?;

    // Read connection
    buf.clear();
    ssl.read_to_end(&mut buf)?;
    io::stdout().write_all(&buf).expect("stdout");
    ssl.shutdown()?;

    Ok(())
}

fn s_client_tokio(addr: &str, insecure: bool) -> io::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(s_client_tokio_async(addr, insecure))
}

async fn s_client_tokio_async(addr: &str, insecure: bool) -> io::Result<()> {
    use std::ffi::CString;
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut ctx = SslCtx::new()?;
    ctx.set_default_verify_paths()?;
    ctx.set_verify(!insecure);

    let sock = TcpStream::connect(addr).await?;
    sock.set_nodelay(true)?;

    let domain = addr.split(':').next().unwrap();
    let mut ssl = AsyncSsl::new(&ctx, sock)?;
    ssl.set_hostname(&CString::new(domain).unwrap())?;
    ssl.connect().await?;

    // Read stdin
    let mut buf = vec![];
    tokio::io::stdin().read_to_end(&mut buf).await.expect("stdin");
    ssl.write_all(&buf).await?;

    // Read connection
    buf.clear();
    ssl.read_to_end(&mut buf).await?;
    tokio::io::stdout().write_all(&buf).await.expect("stdout");
    ssl.shutdown().await?;

    Ok(())
}

fn s_server(addr: &str) -> io::Result<()> {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let mut ctx = SslCtx::new()?;
    ctx.load_certificate_chain(c"cert.pem", c"key.pem")?;

    let sock = TcpListener::bind(addr)?;

    let (conn, addr) = sock.accept()?;
    eprintln!("[*] Connection from {addr}");
    conn.set_nodelay(true)?;
    let mut ssl = Ssl::new(&ctx)?;
    ssl.set_fd(&conn)?;
    ssl.accept()?;

    // Read stdin
    let mut buf = vec![];
    io::stdin().read_to_end(&mut buf).expect("stdin");
    ssl.write_all(&buf)?;

    // Read connection
    buf.clear();
    ssl.read_to_end(&mut buf)?;
    io::stdout().write_all(&buf).expect("stdout");
    ssl.shutdown()?;

    Ok(())
}

fn s_server_tokio(addr: &str) -> io::Result<()> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(s_server_tokio_async(addr))
}

async fn s_server_tokio_async(addr: &str) -> io::Result<()> {
    use tokio::net::TcpListener;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut ctx = SslCtx::new()?;
    ctx.load_certificate_chain(c"cert.pem", c"key.pem")?;

    let sock = TcpListener::bind(addr).await?;

    let (conn, addr) = sock.accept().await?;
    eprintln!("[*] Connection from {addr}");
    conn.set_nodelay(true)?;
    let mut ssl = AsyncSsl::new(&ctx, conn)?;
    ssl.accept().await?;

    // Read stdin
    let mut buf = vec![];
    tokio::io::stdin().read_to_end(&mut buf).await.expect("stdin");
    ssl.write_all(&buf).await?;

    // Read connection
    buf.clear();
    ssl.read_to_end(&mut buf).await?;
    tokio::io::stdout().write_all(&buf).await.expect("stdout");
    ssl.shutdown().await?;

    Ok(())
}
