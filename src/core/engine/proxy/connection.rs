use super::*;

#[allow(dead_code)]
async fn forward_http1_request<W>(
    client_stream: &mut W,
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let response = proxy_http_request(
        context,
        request,
        upstream_addr,
        connect_timeout_ms,
        write_timeout_ms,
        read_timeout_ms,
    )
    .await?;
    let approx_bytes = response.body.len() as u64;
    write_http1_upstream_response(context, client_stream, &response).await?;
    Ok(approx_bytes)
}

#[allow(clippy::large_enum_variant)]
pub(crate) enum UpstreamClientConnection {
    Plain {
        authority: String,
        stream: TcpStream,
    },
    Tls {
        authority: String,
        server_name: String,
        stream: tokio_rustls::client::TlsStream<TcpStream>,
    },
}

pub(crate) fn resolve_runtime_custom_response(response: &CustomHttpResponse) -> CustomHttpResponse {
    let mut resolved = response.clone();
    if let Some(random_status) = response.random_status.as_ref() {
        let roll = rand::thread_rng().gen_range(0..100);
        if roll < u32::from(random_status.success_rate_percent) {
            resolved.status_code = 200;
            resolved.body = random_status.success_body.clone();
        } else if !random_status.failure_statuses.is_empty() {
            let index = rand::thread_rng().gen_range(0..random_status.failure_statuses.len());
            resolved.status_code = random_status.failure_statuses[index];
            resolved.body = random_status.failure_body.clone();
        }
    }
    resolved
}

pub(crate) async fn proxy_http_request(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<UpstreamHttpResponse> {
    let upstream = parse_upstream_endpoint(upstream_addr)?;
    let skip_verify = should_skip_upstream_tls_verification(context, &upstream);
    if matches!(upstream.scheme, UpstreamScheme::Http) {
        let upstream_stream = tokio::time::timeout(
            std::time::Duration::from_millis(connect_timeout_ms),
            TcpStream::connect(upstream.authority.as_str()),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
        let parsed = proxy_raw_http1_over_stream(
            upstream_stream,
            request,
            write_timeout_ms,
            read_timeout_ms,
        )
        .await?;
        context.set_upstream_health(true, None);
        return Ok(parsed);
    }

    let upstream_stream = tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        TcpStream::connect(upstream.authority.as_str()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
    let server_name = build_upstream_tls_server_name(request, &upstream)?;
    let tls_connector = build_upstream_tls_connector(skip_verify)?;
    let tls_stream = tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        tls_connector.connect(server_name, upstream_stream),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream TLS handshake timed out"))??;
    let parsed =
        proxy_raw_http1_over_stream(tls_stream, request, write_timeout_ms, read_timeout_ms).await?;
    context.set_upstream_health(true, None);
    Ok(parsed)
}

pub(crate) async fn proxy_http_request_with_session_affinity(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
    reusable_connection: &mut Option<UpstreamClientConnection>,
) -> Result<UpstreamHttpResponse> {
    let upstream = parse_upstream_endpoint(upstream_addr)?;
    let skip_verify = should_skip_upstream_tls_verification(context, &upstream);
    let effective_tls_server_name = if matches!(upstream.scheme, UpstreamScheme::Https) {
        resolve_upstream_tls_server_name(request, &upstream)?
    } else {
        None
    };
    let same_authority = reusable_connection
        .as_ref()
        .map(|connection| match connection {
            UpstreamClientConnection::Plain { authority, .. } => authority == &upstream.authority,
            UpstreamClientConnection::Tls {
                authority,
                server_name,
                ..
            } => {
                authority == &upstream.authority
                    && effective_tls_server_name
                        .as_deref()
                        .map(|expected| expected == server_name)
                        .unwrap_or(false)
            }
        })
        .unwrap_or(false);
    if !same_authority {
        *reusable_connection = None;
    }
    if reusable_connection.is_none() {
        *reusable_connection = Some(
            connect_upstream_client(
                request,
                &upstream,
                effective_tls_server_name.as_deref(),
                connect_timeout_ms,
                skip_verify,
            )
            .await?,
        );
    }

    let response = match reusable_connection.as_mut() {
        Some(UpstreamClientConnection::Plain { stream, .. }) => {
            proxy_raw_http1_over_stream(stream, request, write_timeout_ms, read_timeout_ms).await
        }
        Some(UpstreamClientConnection::Tls { stream, .. }) => {
            proxy_raw_http1_over_stream(stream, request, write_timeout_ms, read_timeout_ms).await
        }
        None => Err(anyhow::anyhow!("missing upstream connection after connect")),
    };

    match response {
        Ok(response) => {
            let should_close = response.headers.iter().any(|(key, value)| {
                key.eq_ignore_ascii_case("connection")
                    && value.to_ascii_lowercase().contains("close")
            });
            if should_close {
                *reusable_connection = None;
            }
            context.set_upstream_health(true, None);
            Ok(response)
        }
        Err(err) => {
            *reusable_connection = None;
            Err(err)
        }
    }
}

async fn connect_upstream_client(
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

fn build_upstream_tls_server_name(
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
) -> Result<ServerName<'static>> {
    let server_name = resolve_upstream_tls_server_name(request, upstream)?
        .ok_or_else(|| anyhow::anyhow!("HTTPS upstream missing server name"))?;
    ServerName::try_from(server_name)
        .map_err(|_| anyhow::anyhow!("Invalid HTTPS upstream server name"))
}

fn resolve_upstream_tls_server_name(
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
) -> Result<Option<String>> {
    if !matches!(upstream.scheme, UpstreamScheme::Https) {
        return Ok(None);
    }

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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    fn https_upstream(authority: &str) -> crate::core::gateway::UpstreamEndpoint {
        crate::core::gateway::UpstreamEndpoint {
            scheme: UpstreamScheme::Https,
            authority: authority.to_string(),
        }
    }

    #[test]
    fn upstream_tls_server_name_prefers_original_host_without_port() {
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
        request.add_header("host".to_string(), "wnluo.com:660".to_string());

        let resolved =
            resolve_upstream_tls_server_name(&request, &https_upstream("127.0.0.1:880")).unwrap();

        assert_eq!(resolved.as_deref(), Some("wnluo.com"));
    }

    #[test]
    fn upstream_tls_server_name_preserves_wildcard_request_host() {
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
        request.add_header("host".to_string(), "api.wnluo.com".to_string());

        let resolved =
            resolve_upstream_tls_server_name(&request, &https_upstream("127.0.0.1:880")).unwrap();

        assert_eq!(resolved.as_deref(), Some("api.wnluo.com"));
    }

    #[test]
    fn upstream_tls_server_name_falls_back_to_site_primary_hostname() {
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
        request.add_metadata(
            "gateway.primary_hostname".to_string(),
            "portal.example.com".to_string(),
        );

        let resolved =
            resolve_upstream_tls_server_name(&request, &https_upstream("127.0.0.1:880")).unwrap();

        assert_eq!(resolved.as_deref(), Some("portal.example.com"));
    }

    #[test]
    fn upstream_tls_server_name_falls_back_to_upstream_host() {
        let request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());

        let resolved =
            resolve_upstream_tls_server_name(&request, &https_upstream("origin.example.com:8443"))
                .unwrap();

        assert_eq!(resolved.as_deref(), Some("origin.example.com"));
    }
}

async fn proxy_raw_http1_over_stream<S>(
    mut upstream_stream: S,
    request: &UnifiedHttpRequest,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<UpstreamHttpResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request_bytes = request.to_http1_bytes();
    tokio::time::timeout(
        std::time::Duration::from_millis(write_timeout_ms),
        upstream_stream.write_all(&request_bytes),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream write timed out"))??;

    let mut response_bytes = Vec::new();
    let mut buffer = vec![0u8; 8192];
    let mut expected_total_len: Option<usize> = None;
    let mut chunked = false;
    loop {
        let read_result = tokio::time::timeout(
            std::time::Duration::from_millis(read_timeout_ms),
            upstream_stream.read(&mut buffer),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Upstream read timed out"))?;
        match read_result {
            Ok(0) => break,
            Ok(n) => {
                response_bytes.extend_from_slice(&buffer[..n]);

                if let Some(headers_end) = response_bytes
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                {
                    if expected_total_len.is_none() && !chunked {
                        let header_block = &response_bytes[..headers_end];
                        let header_text = String::from_utf8_lossy(header_block);
                        let mut content_length = None;
                        for line in header_text.lines() {
                            if let Some((name, value)) = line.split_once(':') {
                                if name.eq_ignore_ascii_case("content-length") {
                                    content_length = value.trim().parse::<usize>().ok();
                                }
                                if name.eq_ignore_ascii_case("transfer-encoding")
                                    && value.to_ascii_lowercase().contains("chunked")
                                {
                                    chunked = true;
                                }
                            }
                        }
                        if let Some(length) = content_length {
                            expected_total_len = Some(headers_end + 4 + length);
                        }
                    }

                    if let Some(expected) = expected_total_len {
                        if response_bytes.len() >= expected {
                            break;
                        }
                    } else if chunked
                        && response_bytes[headers_end + 4..]
                            .windows(5)
                            .any(|window| window == b"0\r\n\r\n")
                    {
                        break;
                    }
                }
            }
            Err(err) if !response_bytes.is_empty() => {
                debug!(
                    "Ignoring upstream read error after receiving response bytes: {}",
                    err
                );
                break;
            }
            Err(err) => return Err(err.into()),
        }
    }

    parse_http1_response(&response_bytes)
}
