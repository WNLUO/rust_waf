use super::*;

pub(super) fn build_upstream_tls_connector(
    skip_certificate_verification: bool,
) -> Result<TlsConnector> {
    if skip_certificate_verification {
        return Ok(build_insecure_upstream_tls_connector());
    }

    build_verified_upstream_tls_connector()
}

fn build_verified_upstream_tls_connector() -> Result<TlsConnector> {
    crate::tls::ensure_rustls_crypto_provider();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = RustlsClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsConnector::from(Arc::new(config)))
}

fn build_insecure_upstream_tls_connector() -> TlsConnector {
    crate::tls::ensure_rustls_crypto_provider();
    let mut config = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    TlsConnector::from(Arc::new(config))
}

pub(super) fn should_skip_upstream_tls_verification(
    context: &WafContext,
    upstream: &crate::core::gateway::UpstreamEndpoint,
) -> bool {
    if !matches!(upstream.scheme, UpstreamScheme::Https) {
        return false;
    }

    let config = context.config_snapshot();
    let safeline_base_url = config.integrations.safeline.base_url.trim();
    if safeline_base_url.is_empty() {
        return false;
    }

    let safeline_uri = match safeline_base_url.parse::<http::Uri>() {
        Ok(uri) => uri,
        Err(_) => return false,
    };
    if !safeline_uri
        .scheme_str()
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
    {
        return false;
    }

    let Some(safeline_authority) = safeline_uri.authority().map(|value| value.as_str()) else {
        return false;
    };

    authorities_match_https(safeline_authority, &upstream.authority)
}

fn authorities_match_https(left: &str, right: &str) -> bool {
    let Some((left_host, left_port)) = parse_https_authority(left) else {
        return false;
    };
    let Some((right_host, right_port)) = parse_https_authority(right) else {
        return false;
    };

    left_host.eq_ignore_ascii_case(&right_host) && left_port == right_port
}

fn parse_https_authority(authority: &str) -> Option<(String, u16)> {
    let uri = format!("https://{}", authority).parse::<http::Uri>().ok()?;
    let host = uri.host()?.to_string();
    let port = uri.port_u16().unwrap_or(443);
    Some((host, port))
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}
