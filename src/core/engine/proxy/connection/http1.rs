use super::request::enforce_http1_request_safety;
use super::tls::build_upstream_tls_server_name;
use super::*;
use crate::core::engine::proxy::response::parse_http1_response_head;

pub(super) async fn proxy_http1_request_strict(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<UpstreamHttpResponse> {
    enforce_http1_request_safety(context, request)?;
    let skip_verify = should_skip_upstream_tls_verification(context, upstream);
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
    let server_name = build_upstream_tls_server_name(request, upstream)?;
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

pub(super) async fn proxy_http1_request_to_http1_client<W>(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
    client_stream: &mut W,
) -> Result<super::StreamedUpstreamResponse>
where
    W: AsyncWrite + Unpin,
{
    enforce_http1_request_safety(context, request)?;
    let skip_verify = should_skip_upstream_tls_verification(context, upstream);
    if matches!(upstream.scheme, UpstreamScheme::Http) {
        let upstream_stream = tokio::time::timeout(
            std::time::Duration::from_millis(connect_timeout_ms),
            TcpStream::connect(upstream.authority.as_str()),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
        return stream_raw_http1_over_stream_to_http1_client(
            context,
            upstream_stream,
            request,
            write_timeout_ms,
            read_timeout_ms,
            client_stream,
        )
        .await;
    }

    let upstream_stream = tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        TcpStream::connect(upstream.authority.as_str()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
    let server_name = build_upstream_tls_server_name(request, upstream)?;
    let tls_connector = build_upstream_tls_connector(skip_verify)?;
    let tls_stream = tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        tls_connector.connect(server_name, upstream_stream),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream TLS handshake timed out"))??;
    stream_raw_http1_over_stream_to_http1_client(
        context,
        tls_stream,
        request,
        write_timeout_ms,
        read_timeout_ms,
        client_stream,
    )
    .await
}

pub(super) async fn proxy_raw_http1_over_stream<S>(
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

async fn stream_raw_http1_over_stream_to_http1_client<S, W>(
    context: &WafContext,
    mut upstream_stream: S,
    request: &UnifiedHttpRequest,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
    client_stream: &mut W,
) -> Result<super::StreamedUpstreamResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    let request_bytes = request.to_http1_bytes();
    tokio::time::timeout(
        std::time::Duration::from_millis(write_timeout_ms),
        upstream_stream.write_all(&request_bytes),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream write timed out"))??;

    let mut response_bytes = Vec::with_capacity(16 * 1024);
    let mut buffer = vec![0u8; 8192];
    let headers_end = loop {
        let read_result = tokio::time::timeout(
            std::time::Duration::from_millis(read_timeout_ms),
            upstream_stream.read(&mut buffer),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Upstream read timed out"))?;
        match read_result {
            Ok(0) => anyhow::bail!("Upstream closed before sending full HTTP/1 response head"),
            Ok(n) => {
                response_bytes.extend_from_slice(&buffer[..n]);
                if let Some(headers_end) = response_bytes
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                {
                    break headers_end + 4;
                }
                if response_bytes.len() >= 64 * 1024 {
                    anyhow::bail!("Upstream HTTP/1 response headers exceeded 64KB");
                }
            }
            Err(err) => return Err(err.into()),
        }
    };

    let head = parse_http1_response_head(&response_bytes[..headers_end])?;
    let mut headers = head.headers.clone();
    apply_response_policies(context, &mut headers, head.status_code);
    Http1Handler::new()
        .write_response_head_with_headers(
            client_stream,
            head.status_code,
            head.status_text
                .as_deref()
                .unwrap_or(http_status_text(head.status_code)),
            &headers,
            None,
            true,
        )
        .await?;

    let mut body_bytes_sent = 0usize;
    if response_bytes.len() > headers_end {
        let buffered_body = &response_bytes[headers_end..];
        body_bytes_sent = body_bytes_sent.saturating_add(buffered_body.len());
        client_stream.write_all(buffered_body).await?;
        client_stream.flush().await?;
    }

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
                body_bytes_sent = body_bytes_sent.saturating_add(n);
                client_stream.write_all(&buffer[..n]).await?;
                client_stream.flush().await?;
            }
            Err(err) => return Err(err.into()),
        }
    }

    Ok(super::StreamedUpstreamResponse {
        status_code: head.status_code,
        body_bytes_sent,
    })
}

#[cfg(feature = "http3")]
pub(super) async fn proxy_http1_request_to_http3_client(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<super::StreamedUpstreamResponse> {
    enforce_http1_request_safety(context, request)?;
    let skip_verify = should_skip_upstream_tls_verification(context, upstream);
    if matches!(upstream.scheme, UpstreamScheme::Http) {
        let upstream_stream = tokio::time::timeout(
            std::time::Duration::from_millis(connect_timeout_ms),
            TcpStream::connect(upstream.authority.as_str()),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
        return stream_raw_http1_over_stream_to_http3_client(
            context,
            upstream_stream,
            request,
            write_timeout_ms,
            read_timeout_ms,
            stream,
        )
        .await;
    }

    let upstream_stream = tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        TcpStream::connect(upstream.authority.as_str()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
    let server_name = build_upstream_tls_server_name(request, upstream)?;
    let tls_connector = build_upstream_tls_connector(skip_verify)?;
    let tls_stream = tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        tls_connector.connect(server_name, upstream_stream),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream TLS handshake timed out"))??;
    stream_raw_http1_over_stream_to_http3_client(
        context,
        tls_stream,
        request,
        write_timeout_ms,
        read_timeout_ms,
        stream,
    )
    .await
}

#[cfg(feature = "http3")]
async fn stream_raw_http1_over_stream_to_http3_client<S>(
    context: &WafContext,
    mut upstream_stream: S,
    request: &UnifiedHttpRequest,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<super::StreamedUpstreamResponse>
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

    let mut response_bytes = Vec::with_capacity(16 * 1024);
    let mut buffer = vec![0u8; 8192];
    let headers_end = loop {
        let read_result = tokio::time::timeout(
            std::time::Duration::from_millis(read_timeout_ms),
            upstream_stream.read(&mut buffer),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Upstream read timed out"))?;
        match read_result {
            Ok(0) => anyhow::bail!("Upstream closed before sending full HTTP/1 response head"),
            Ok(n) => {
                response_bytes.extend_from_slice(&buffer[..n]);
                if let Some(headers_end) = response_bytes
                    .windows(4)
                    .position(|window| window == b"\r\n\r\n")
                {
                    break headers_end + 4;
                }
                if response_bytes.len() >= 64 * 1024 {
                    anyhow::bail!("Upstream HTTP/1 response headers exceeded 64KB");
                }
            }
            Err(err) => return Err(err.into()),
        }
    };

    let head = parse_http1_response_head(&response_bytes[..headers_end])?;
    let mut headers = head.headers.clone();
    apply_response_policies(context, &mut headers, head.status_code);
    let mut builder = http::Response::builder().status(head.status_code);
    for (key, value) in &headers {
        if key.eq_ignore_ascii_case("transfer-encoding")
            || key.eq_ignore_ascii_case("connection")
            || key.starts_with(':')
        {
            continue;
        }
        builder = builder.header(key, value);
    }
    stream.send_response(builder.body(())?).await?;

    let mut body_bytes_sent = 0usize;
    if response_bytes.len() > headers_end {
        let buffered_body = &response_bytes[headers_end..];
        body_bytes_sent = body_bytes_sent.saturating_add(buffered_body.len());
        stream
            .send_data(Bytes::copy_from_slice(buffered_body))
            .await?;
    }

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
                body_bytes_sent = body_bytes_sent.saturating_add(n);
                stream
                    .send_data(Bytes::copy_from_slice(&buffer[..n]))
                    .await?;
            }
            Err(err) => return Err(err.into()),
        }
    }
    stream.finish().await?;

    Ok(super::StreamedUpstreamResponse {
        status_code: head.status_code,
        body_bytes_sent,
    })
}
