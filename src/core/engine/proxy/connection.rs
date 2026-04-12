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

pub(crate) enum UpstreamClientConnection {
    Plain {
        authority: String,
        stream: TcpStream,
    },
    Tls {
        authority: String,
        stream: tokio_rustls::client::TlsStream<TcpStream>,
    },
}

pub(crate) fn resolve_runtime_custom_response(
    response: &CustomHttpResponse,
) -> CustomHttpResponse {
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
    let authority_uri = format!("https://{}", upstream.authority).parse::<http::Uri>()?;
    let server_name = ServerName::try_from(
        authority_uri
            .host()
            .ok_or_else(|| anyhow::anyhow!("HTTPS upstream missing host"))?
            .to_string(),
    )
    .map_err(|_| anyhow::anyhow!("Invalid HTTPS upstream server name"))?;
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
    let same_authority = reusable_connection
        .as_ref()
        .map(|connection| match connection {
            UpstreamClientConnection::Plain { authority, .. }
            | UpstreamClientConnection::Tls { authority, .. } => authority == &upstream.authority,
        })
        .unwrap_or(false);
    if !same_authority {
        *reusable_connection = None;
    }
    if reusable_connection.is_none() {
        *reusable_connection = Some(
            connect_upstream_client(&upstream, connect_timeout_ms, skip_verify).await?,
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
    upstream: &crate::core::gateway::UpstreamEndpoint,
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
            let authority_uri = format!("https://{}", upstream.authority).parse::<http::Uri>()?;
            let server_name = ServerName::try_from(
                authority_uri
                    .host()
                    .ok_or_else(|| anyhow::anyhow!("HTTPS upstream missing host"))?
                    .to_string(),
            )
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
                stream,
            })
        }
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
