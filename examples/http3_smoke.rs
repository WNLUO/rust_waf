#[cfg(not(feature = "http3"))]
fn main() {
    eprintln!("This example requires the `http3` feature.");
    eprintln!("Usage: cargo run --example http3_smoke --features http3 -- <url> <ca-cert.pem>");
    std::process::exit(1);
}

#[cfg(feature = "http3")]
use anyhow::{Context, Result};
#[cfg(feature = "http3")]
use bytes::Buf;
#[cfg(feature = "http3")]
use h3::client;
#[cfg(feature = "http3")]
use h3_quinn::Connection as H3Connection;
#[cfg(feature = "http3")]
use http::{Request, Uri};
#[cfg(feature = "http3")]
use quinn::crypto::rustls::QuicClientConfig;
#[cfg(feature = "http3")]
use quinn::{ClientConfig, Endpoint};
#[cfg(feature = "http3")]
use rustls::RootCertStore;
#[cfg(feature = "http3")]
use rustls::pki_types::CertificateDer;
#[cfg(feature = "http3")]
use std::env;
#[cfg(feature = "http3")]
use std::fs::File;
#[cfg(feature = "http3")]
use std::io::BufReader;
#[cfg(feature = "http3")]
use std::net::{SocketAddr, ToSocketAddrs};
#[cfg(feature = "http3")]
use std::sync::Arc;

#[cfg(feature = "http3")]
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    waf::tls::ensure_rustls_crypto_provider();

    let args = Args::parse()?;
    let remote_addr = resolve_remote_addr(&args.uri)?;
    let server_name = args
        .uri
        .host()
        .context("URL is missing a host")?
        .to_string();

    let roots = load_root_certificates(&args.ca_cert_path)?;
    let mut crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![b"h3".to_vec()];

    let client_config = ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto)?));
    let bind_addr: SocketAddr = if remote_addr.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };

    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);

    let quinn_connection = endpoint
        .connect(remote_addr, &server_name)?
        .await
        .with_context(|| format!("failed to connect to {}", args.uri))?;

    let (mut driver, mut send_request) =
        client::new(H3Connection::new(quinn_connection.clone())).await?;
    let driver_task = tokio::spawn(async move { driver.wait_idle().await });

    let mut request_stream = send_request
        .send_request(Request::get(args.uri.to_string()).body(())?)
        .await?;
    request_stream.finish().await?;

    let response = request_stream.recv_response().await?;
    let mut body = Vec::new();
    while let Some(mut chunk) = request_stream.recv_data().await? {
        let remaining = chunk.remaining();
        body.extend_from_slice(chunk.copy_to_bytes(remaining).as_ref());
    }

    println!("status: {}", response.status());
    if !response.headers().is_empty() {
        println!("headers:");
        for (name, value) in response.headers() {
            println!("{}: {}", name, value.to_str().unwrap_or("<binary>"));
        }
    }
    if body.is_empty() {
        println!("body: <empty>");
    } else {
        println!("body:\n{}", String::from_utf8_lossy(&body));
    }

    drop(send_request);
    match driver_task.await {
        Ok(_) => {}
        Err(err) => eprintln!("http3 driver task ended unexpectedly: {err}"),
    }

    quinn_connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

#[cfg(feature = "http3")]
struct Args {
    uri: Uri,
    ca_cert_path: String,
}

#[cfg(feature = "http3")]
impl Args {
    fn parse() -> Result<Self> {
        let mut args = env::args().skip(1);
        let uri = args
            .next()
            .context("missing <url> argument")?
            .parse::<Uri>()
            .context("invalid URL")?;
        let ca_cert_path = args.next().context("missing <ca-cert.pem> argument")?;

        if args.next().is_some() {
            anyhow::bail!("too many arguments");
        }

        if uri.scheme_str() != Some("https") {
            anyhow::bail!("URL must use https://");
        }

        Ok(Self { uri, ca_cert_path })
    }
}

#[cfg(feature = "http3")]
fn resolve_remote_addr(uri: &Uri) -> Result<SocketAddr> {
    let host = uri.host().context("URL is missing a host")?;
    let port = uri.port_u16().unwrap_or(443);

    if let Ok(ip) = host.parse() {
        return Ok(SocketAddr::new(ip, port));
    }

    (host, port)
        .to_socket_addrs()?
        .next()
        .with_context(|| format!("failed to resolve {host}:{port}"))
}

#[cfg(feature = "http3")]
fn load_root_certificates(path: &str) -> Result<RootCertStore> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", path);
    }

    let mut roots = RootCertStore::empty();
    for cert in certs {
        roots.add(CertificateDer::from(cert))?;
    }

    Ok(roots)
}
