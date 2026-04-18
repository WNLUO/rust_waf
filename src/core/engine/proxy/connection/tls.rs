use super::*;

pub(super) async fn connect_upstream_client(
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
    resolved_server_name: Option<&str>,
    connect_timeout_ms: u64,
    skip_certificate_verification: bool,
) -> Result<UpstreamClientConnection> {
    match upstream.scheme {
        UpstreamScheme::Http => {
            let stream = tokio::time::timeout(
                std::time::Duration::from_millis(connect_timeout_ms),
                TcpStream::connect(upstream.authority.as_str()),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
            Ok(UpstreamClientConnection::Plain {
                authority: upstream.authority.clone(),
                stream,
            })
        }
        UpstreamScheme::Https => {
            let upstream_stream = tokio::time::timeout(
                std::time::Duration::from_millis(connect_timeout_ms),
                TcpStream::connect(upstream.authority.as_str()),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
            let server_name_text = match resolved_server_name {
                Some(value) => value.to_string(),
                None => resolve_upstream_tls_server_name(request, upstream)?
                    .ok_or_else(|| anyhow::anyhow!("HTTPS upstream missing server name"))?,
            };
            let server_name = ServerName::try_from(server_name_text.clone())
                .map_err(|_| anyhow::anyhow!("Invalid HTTPS upstream server name"))?;
            let tls_connector = build_upstream_tls_connector(skip_certificate_verification)?;
            let stream = tokio::time::timeout(
                std::time::Duration::from_millis(connect_timeout_ms),
                tls_connector.connect(server_name, upstream_stream),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Upstream TLS handshake timed out"))??;
            Ok(UpstreamClientConnection::Tls {
                authority: upstream.authority.clone(),
                server_name: server_name_text,
                stream,
            })
        }
    }
}

pub(super) fn build_upstream_tls_server_name(
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
) -> Result<ServerName<'static>> {
    let server_name = resolve_upstream_tls_server_name(request, upstream)?
        .ok_or_else(|| anyhow::anyhow!("HTTPS upstream missing server name"))?;
    ServerName::try_from(server_name)
        .map_err(|_| anyhow::anyhow!("Invalid HTTPS upstream server name"))
}

pub(super) fn resolve_upstream_tls_server_name(
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
) -> Result<Option<String>> {
    if !matches!(upstream.scheme, UpstreamScheme::Https) {
        return Ok(None);
    }

    // Even when we connect to a loopback upstream like 127.0.0.1:880, the TLS
    // identity should prefer the original request host so virtual-hosted
    // upstreams keep seeing wnluo.com instead of the local connect target.
    if let Some(hostname) = crate::core::engine::policy::request_hostname(request) {
        return Ok(Some(hostname));
    }

    if let Some(primary_hostname) = request
        .get_metadata("gateway.primary_hostname")
        .and_then(|value| normalize_hostname(value))
    {
        return Ok(Some(primary_hostname));
    }

    let authority_uri = format!("https://{}", upstream.authority).parse::<http::Uri>()?;
    Ok(authority_uri.host().map(ToOwned::to_owned))
}
