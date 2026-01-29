use std::io;

use openssl_lite::{SslCtx, Ssl};

fn help() -> ! {
    eprintln!("Usage: openssl_lite <cmd>");
    eprintln!("Available commands:");
    eprintln!("    s_client <addr>");
    eprintln!("    s_server <addr>");
    eprintln!("Add flag `-tokio` to use async version");
    std::process::exit(1)
}

fn main() -> io::Result<()> {
    let mut args = std::env::args();
    /* skip first */ args.next();
    let Some(cmd) = args.next() else { help() };
    if cmd != "s_client" && cmd != "s_server" { help(); }
    let mut tokio = false;
    let mut addr = String::new();
    for a in args {
        match a.as_str() {
            "-tokio" => tokio = true,
            a if addr.is_empty() => addr = a.to_string(),
            _ => help(),
        }
    }

    if cmd == "s_client" && !tokio {
        s_client(&addr)?;
    } else if cmd == "s_client" && tokio {
        s_client_tokio(&addr)?;
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

fn s_client(addr: &str) -> io::Result<()> {
    use std::io::{Read, Write};
    use std::net::TcpStream;

    let mut ctx = SslCtx::new()?;
    // Certificate verification has been intentionally disabled for testing,
    // local server has self signed certificate
    ctx.set_verify(false);

    let mut ssl = Ssl::new(&ctx)?;
    let sock = TcpStream::connect(addr)?;
    sock.set_nodelay(true)?;
    ssl.set_fd(sock)?; // This calls IntoRawFd
    ssl.connect()?;

    // Read stdin
    let mut buf = vec![];
    io::stdin().read_to_end(&mut buf).expect("stdin");
    ssl.write_all(&buf)?;

    // Read connection
    buf.clear();
    ssl.read_to_end(&mut buf)?;
    io::stdout().write_all(&buf).expect("stdout");

    Ok(())
}

fn s_client_tokio(_addr: &str) -> io::Result<()> { todo!(); }
fn s_server(_addr: &str) -> io::Result<()> { todo!(); }
fn s_server_tokio(_addr: &str) -> io::Result<()> { todo!(); }

// To make it async:
// - BIO has to call AsyncRead/AsyncWrite
// - When SSL_ERROR_WANT_READ/WRITE is returned, just convert it into Poll

// The problem:
// To call AsyncRead BIO, we have to pass cx
// We either set bio state as cx reference each time,
// or create a memory BIO instead and push bytes on every SSL_ERROR_WANTS_READ/WRITE
// Blocking BIO does not need any state
