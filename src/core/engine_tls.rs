use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig as RustlsServerConfig;
use std::fs::File;
use std::io::BufReader;
#[cfg(feature = "http3")]
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;

use crate::core::WafContext;

pub(super) fn build_tls_acceptor(context: &WafContext) -> Result<Option<TlsAcceptor>> {
    if context
        .config
        .gateway_config
        .https_listen_addr
        .trim()
        .is_empty()
    {
        return Ok(None);
    }

    let Some(cert_resolver) = context.gateway_runtime.tls_resolver() else {
        return Ok(None);
    };

    crate::tls::ensure_rustls_crypto_provider();

    let mut server_config = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(cert_resolver);
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
}

#[cfg(feature = "http3")]
pub(super) fn build_http3_endpoint(
    config: &crate::config::Http3Config,
) -> Result<Option<quinn::Endpoint>> {
    use log::warn;
    use quinn::crypto::rustls::QuicServerConfig;

    if !config.enabled {
        return Ok(None);
    }

    if !config.enable_tls13 {
        warn!("HTTP/3 requires TLS 1.3; skipping QUIC listener because enable_tls13=false");
        return Ok(None);
    }

    let (Some(cert_path), Some(key_path)) = (
        config.certificate_path.as_deref(),
        config.private_key_path.as_deref(),
    ) else {
        warn!(
            "HTTP/3 is enabled but certificate_path/private_key_path are missing; skipping QUIC listener"
        );
        return Ok(None);
    };

    crate::tls::ensure_rustls_crypto_provider();

    let certs = load_tls_certificates(cert_path)?;
    let private_key = load_tls_private_key(key_path)?;
    let mut server_crypto = RustlsServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];

    let mut server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto)?));
    let transport = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow::anyhow!("Failed to configure QUIC transport"))?;
    transport.max_concurrent_uni_streams(256_u32.into());
    transport.max_concurrent_bidi_streams((config.max_concurrent_streams as u32).into());
    transport.keep_alive_interval(Some(std::time::Duration::from_secs(
        (config.idle_timeout_secs / 3).max(1),
    )));
    transport.max_idle_timeout(Some(
        std::time::Duration::from_secs(config.idle_timeout_secs)
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid HTTP/3 idle timeout"))?,
    ));

    let listen_addr: SocketAddr = config.listen_addr.parse()?;
    Ok(Some(quinn::Endpoint::server(server_config, listen_addr)?))
}

#[cfg_attr(not(feature = "http3"), allow(dead_code))]
fn load_tls_certificates(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certs = rustls_pemfile::certs(&mut reader).collect::<std::result::Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        anyhow::bail!("No TLS certificates found in {}", path);
    }
    Ok(certs)
}

#[cfg_attr(not(feature = "http3"), allow(dead_code))]
fn load_tls_private_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?
        .ok_or_else(|| anyhow::anyhow!("No TLS private key found in {}", path))
}
