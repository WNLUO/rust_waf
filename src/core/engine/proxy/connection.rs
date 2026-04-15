use super::*;
use bytes::Bytes;
use dashmap::DashMap;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2 as hyper_http2;
use hyper::header::{CONNECTION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use hyper_util::rt::{TokioExecutor, TokioIo};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UpstreamTransport {
    Http1,
    Http2,
}

type Http2Sender = hyper_http2::SendRequest<Full<Bytes>>;

#[derive(Debug)]
struct PooledHttp2Connection {
    sender: Http2Sender,
}

fn http2_pool() -> &'static DashMap<String, Arc<tokio::sync::Mutex<PooledHttp2Connection>>> {
    static POOL: OnceLock<DashMap<String, Arc<tokio::sync::Mutex<PooledHttp2Connection>>>> =
        OnceLock::new();
    POOL.get_or_init(DashMap::new)
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
    match select_upstream_transport(context, request, &upstream)? {
        UpstreamTransport::Http1 => {
            proxy_http1_request_strict(
                context,
                request,
                &upstream,
                connect_timeout_ms,
                write_timeout_ms,
                read_timeout_ms,
            )
            .await
        }
        UpstreamTransport::Http2 => {
            proxy_http2_request(
                context,
                request,
                &upstream,
                connect_timeout_ms,
                read_timeout_ms,
            )
            .await
        }
    }
}

fn select_upstream_transport(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
) -> Result<UpstreamTransport> {
    let policy = context.config_snapshot().l7_config.upstream_protocol_policy;
    let supports_http2 = matches!(upstream.scheme, UpstreamScheme::Https);
    match policy {
        crate::config::UpstreamProtocolPolicy::Http1Only => Ok(UpstreamTransport::Http1),
        crate::config::UpstreamProtocolPolicy::Http2Only => {
            if supports_http2 {
                Ok(UpstreamTransport::Http2)
            } else {
                Err(anyhow::anyhow!(
                    "Upstream HTTP/2 required, but upstream does not support negotiated TLS HTTP/2: {}",
                    upstream
                ))
            }
        }
        crate::config::UpstreamProtocolPolicy::Http2Preferred => {
            if supports_http2 {
                Ok(UpstreamTransport::Http2)
            } else {
                Ok(UpstreamTransport::Http1)
            }
        }
        crate::config::UpstreamProtocolPolicy::Auto => {
            if supports_http2 && !matches!(request.version, HttpVersion::Http1_0) {
                Ok(UpstreamTransport::Http2)
            } else {
                Ok(UpstreamTransport::Http1)
            }
        }
    }
}

async fn proxy_http1_request_strict(
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

async fn proxy_http2_request(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
    connect_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<UpstreamHttpResponse> {
    if !matches!(upstream.scheme, UpstreamScheme::Https) {
        anyhow::bail!("Upstream HTTP/2 currently requires HTTPS upstreams");
    }

    let pool_key = build_http2_pool_key(context, request, upstream)?;
    let pooled =
        get_or_connect_http2_sender(context, request, upstream, &pool_key, connect_timeout_ms)
            .await?;
    let upstream_request = build_http2_upstream_request(request, upstream)?;
    emit_http2_upstream_request_debug_event(context, request, upstream, &upstream_request)?;
    let mut guard = pooled.lock().await;
    let response = tokio::time::timeout(
        std::time::Duration::from_millis(read_timeout_ms),
        guard.sender.send_request(upstream_request),
    )
    .await;
    match response {
        Ok(Ok(response)) => {
            emit_http2_upstream_response_debug_event(context, request, &response);
            let mapped = map_http2_upstream_response(response).await?;
            context.set_upstream_health(true, None);
            Ok(mapped)
        }
        Ok(Err(err)) => {
            http2_pool().remove(&pool_key);
            emit_http2_upstream_error_debug_event(
                context,
                request,
                "send_request",
                &err.to_string(),
            );
            Err(err.into())
        }
        Err(_) => {
            http2_pool().remove(&pool_key);
            emit_http2_upstream_error_debug_event(
                context,
                request,
                "timeout",
                "Upstream HTTP/2 request timed out",
            );
            Err(anyhow::anyhow!("Upstream HTTP/2 request timed out"))
        }
    }
}

fn build_http2_pool_key(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
) -> Result<String> {
    let skip_verify = should_skip_upstream_tls_verification(context, upstream);
    let server_name = resolve_upstream_tls_server_name(request, upstream)?
        .unwrap_or_else(|| upstream.authority.clone());
    Ok(format!(
        "{}|skip_verify={}|sni={}",
        upstream.authority, skip_verify, server_name
    ))
}

async fn get_or_connect_http2_sender(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
    pool_key: &str,
    connect_timeout_ms: u64,
) -> Result<Arc<tokio::sync::Mutex<PooledHttp2Connection>>> {
    if let Some(existing) = http2_pool().get(pool_key) {
        return Ok(existing.clone());
    }

    let sender = connect_http2_sender(context, request, upstream, connect_timeout_ms).await?;
    let pooled = Arc::new(tokio::sync::Mutex::new(PooledHttp2Connection { sender }));
    let pooled_ref = pooled.clone();
    let entry = http2_pool()
        .entry(pool_key.to_string())
        .or_insert_with(|| pooled_ref);
    Ok(entry.clone())
}

async fn connect_http2_sender(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
    connect_timeout_ms: u64,
) -> Result<Http2Sender> {
    let skip_verify = should_skip_upstream_tls_verification(context, upstream);
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

    let io = TokioIo::new(tls_stream);
    let (sender, connection) = tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        hyper_http2::handshake(TokioExecutor::new(), io),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream HTTP/2 handshake timed out"))??;
    tokio::spawn(async move {
        if let Err(err) = connection.await {
            debug!("Upstream HTTP/2 connection ended: {}", err);
        }
    });
    Ok(sender)
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
    if context
        .config_snapshot()
        .l7_config
        .upstream_http1_strict_mode
        || !context
            .config_snapshot()
            .l7_config
            .upstream_http1_allow_connection_reuse
        || !matches!(
            select_upstream_transport(context, request, &upstream)?,
            UpstreamTransport::Http1
        )
    {
        return proxy_http_request(
            context,
            request,
            upstream_addr,
            connect_timeout_ms,
            write_timeout_ms,
            read_timeout_ms,
        )
        .await;
    }

    enforce_http1_request_safety(context, request)?;
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

pub(crate) fn enforce_http1_request_safety(
    context: &WafContext,
    request: &UnifiedHttpRequest,
) -> Result<()> {
    let config = &context.config_snapshot().l7_config;
    if !config.upstream_http1_strict_mode {
        return Ok(());
    }

    let content_length_count = request
        .get_metadata("http1.content_length_count")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or_else(|| usize::from(request.get_header("content-length").is_some()));
    let has_transfer_encoding = request
        .get_metadata("http1.has_transfer_encoding")
        .map(|value| value == "true")
        .unwrap_or_else(|| request.get_header("transfer-encoding").is_some());
    let has_expect_100_continue = request
        .get_metadata("http1.has_expect_100_continue")
        .map(|value| value == "true")
        .unwrap_or_else(|| {
            request
                .get_header("expect")
                .map(|value| value.eq_ignore_ascii_case("100-continue"))
                .unwrap_or(false)
        });

    if config.reject_ambiguous_http1_requests && content_length_count > 1 {
        anyhow::bail!("rejected ambiguous HTTP/1 request: multiple Content-Length headers");
    }
    if config.reject_http1_transfer_encoding_requests && has_transfer_encoding {
        anyhow::bail!("rejected HTTP/1 request carrying Transfer-Encoding");
    }
    if config.reject_ambiguous_http1_requests && has_transfer_encoding && content_length_count > 0 {
        anyhow::bail!(
            "rejected ambiguous HTTP/1 request: both Content-Length and Transfer-Encoding present"
        );
    }
    if config.reject_expect_100_continue && has_expect_100_continue {
        anyhow::bail!("rejected HTTP/1 request carrying Expect: 100-continue");
    }
    let declared_body_len = request
        .get_header("content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    if config.reject_body_on_safe_http_methods
        && (declared_body_len > 0 || !request.body.is_empty())
        && matches!(request.method.as_str(), "GET" | "HEAD" | "OPTIONS")
    {
        anyhow::bail!(
            "rejected HTTP/1 request carrying a body on safe method {}",
            request.method
        );
    }

    Ok(())
}

fn build_http2_upstream_request(
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
) -> Result<Request<Full<Bytes>>> {
    let upstream_authority = effective_http2_upstream_authority(request, upstream);
    let uri = format!(
        "https://{}{}",
        upstream_authority,
        normalize_http2_upstream_path(&request.uri)
    );
    let mut builder = Request::builder().method(request.method.as_str()).uri(uri);

    for (key, value) in &request.headers {
        if key.eq_ignore_ascii_case(CONNECTION.as_str())
            || key.eq_ignore_ascii_case(TRANSFER_ENCODING.as_str())
            || key.eq_ignore_ascii_case(HOST.as_str())
            || should_strip_loop_detection_header(key)
            || key.starts_with(':')
        {
            continue;
        }
        if key.eq_ignore_ascii_case(CONTENT_LENGTH.as_str()) {
            continue;
        }
        builder = builder.header(key.as_str(), value.as_str());
    }

    // In HTTP/2 the request authority is already carried by the URI/:authority.
    // Re-injecting a plain `Host` header here caused the local Tengine upstream
    // to reject otherwise valid requests with 400 Bad Request.
    builder
        .body(Full::new(Bytes::from(request.body.clone())))
        .map_err(Into::into)
}

fn emit_http2_upstream_request_debug_event(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
    upstream_request: &Request<Full<Bytes>>,
) -> Result<()> {
    let sni = resolve_upstream_tls_server_name(request, upstream)?
        .unwrap_or_else(|| "<none>".to_string());
    let forwarded_headers = upstream_request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| serde_json::json!({ "name": name.as_str(), "value": value }))
        })
        .collect::<Vec<_>>();
    crate::core::engine::policy::persist_upstream_http2_debug_event(
        context,
        request,
        "request",
        serde_json::json!({
            "method": upstream_request.method().as_str(),
            "path": request.uri,
            "uri": upstream_request.uri().to_string(),
            "connect_target": upstream.authority,
            "host": upstream_request
                .uri()
                .authority()
                .map(|value| value.as_str())
                .unwrap_or("<missing>"),
            "sni": sni,
            "headers": forwarded_headers,
        }),
    );
    Ok(())
}

fn emit_http2_upstream_response_debug_event(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    response: &http::Response<hyper::body::Incoming>,
) {
    let header_dump = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| serde_json::json!({ "name": name.as_str(), "value": value }))
        })
        .collect::<Vec<_>>();
    crate::core::engine::policy::persist_upstream_http2_debug_event(
        context,
        request,
        "response",
        serde_json::json!({
            "status": response.status().as_u16(),
            "reason": response.status().canonical_reason(),
            "headers": header_dump,
        }),
    );
}

fn emit_http2_upstream_error_debug_event(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    stage: &str,
    error: &str,
) {
    crate::core::engine::policy::persist_upstream_http2_debug_event(
        context,
        request,
        "error",
        serde_json::json!({
            "stage": stage,
            "error": error,
        }),
    );
}

fn effective_http2_upstream_authority(
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
) -> String {
    // `upstream.authority` is only the connect target (for example 127.0.0.1:880).
    // The business host seen by the upstream virtual host must still come from the
    // original request host/authority so that SNI and routing stay on wnluo.com.
    request
        .get_header("host")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            request
                .metadata
                .get("authority")
                .cloned()
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or_else(|| upstream.authority.clone())
}

fn should_strip_loop_detection_header(header_name: &str) -> bool {
    header_name.eq_ignore_ascii_case("cdn-loop")
        || header_name.eq_ignore_ascii_case("via")
        || header_name.eq_ignore_ascii_case("eo-log-uuid")
}

fn normalize_http2_upstream_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_string()
    } else if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{}", path)
    }
}

async fn map_http2_upstream_response(
    response: http::Response<hyper::body::Incoming>,
) -> Result<UpstreamHttpResponse> {
    let (parts, body) = response.into_parts();
    let body = body.collect().await?.to_bytes().to_vec();
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect::<Vec<_>>();

    Ok(UpstreamHttpResponse {
        status_code: parts.status.as_u16(),
        status_text: parts.status.canonical_reason().map(ToOwned::to_owned),
        headers,
        body,
    })
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

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::config::{Config, L7Config, UpstreamProtocolPolicy};

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
            resolve_upstream_tls_server_name(&request, &https_upstream("origin.example.com:880"))
                .unwrap();

        assert_eq!(resolved.as_deref(), Some("wnluo.com"));
    }

    #[test]
    fn upstream_tls_server_name_preserves_wildcard_request_host() {
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
        request.add_header("host".to_string(), "api.wnluo.com".to_string());

        let resolved =
            resolve_upstream_tls_server_name(&request, &https_upstream("origin.example.com:880"))
                .unwrap();

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
            resolve_upstream_tls_server_name(&request, &https_upstream("origin.example.com:880"))
                .unwrap();

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

    async fn test_context(l7_config: L7Config) -> WafContext {
        WafContext::new(Config {
            sqlite_enabled: false,
            metrics_enabled: false,
            l7_config,
            ..Config::default()
        })
        .await
        .expect("context should build")
    }

    #[tokio::test]
    async fn strict_http1_validation_rejects_multiple_content_length() {
        let context = test_context(L7Config::default()).await;
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "POST".to_string(), "/".to_string());
        request.add_header("content-length".to_string(), "5".to_string());
        request.add_metadata("http1.content_length_count".to_string(), "2".to_string());

        let result = enforce_http1_request_safety(&context, &request);

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn upstream_selection_prefers_http2_for_https_when_enabled() {
        let mut l7_config = L7Config::default();
        l7_config.upstream_protocol_policy = UpstreamProtocolPolicy::Http2Preferred;
        let context = test_context(l7_config).await;
        let request =
            UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());

        let selected =
            select_upstream_transport(&context, &request, &https_upstream("up.example:443"))
                .expect("selection should succeed");

        assert_eq!(selected, UpstreamTransport::Http2);
    }

    #[tokio::test]
    async fn upstream_selection_falls_back_to_http1_for_plain_http() {
        let mut l7_config = L7Config::default();
        l7_config.upstream_protocol_policy = UpstreamProtocolPolicy::Http2Preferred;
        let context = test_context(l7_config).await;
        let request =
            UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
        let upstream = crate::core::gateway::UpstreamEndpoint {
            scheme: UpstreamScheme::Http,
            authority: "127.0.0.1:8080".to_string(),
        };

        let selected = select_upstream_transport(&context, &request, &upstream)
            .expect("selection should succeed");

        assert_eq!(selected, UpstreamTransport::Http1);
    }

    #[test]
    fn http2_upstream_authority_prefers_original_host() {
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
        request.add_header("host".to_string(), "wnluo.com".to_string());

        let authority =
            effective_http2_upstream_authority(&request, &https_upstream("127.0.0.1:880"));

        assert_eq!(authority, "wnluo.com");
    }

    #[test]
    fn http2_upstream_request_preserves_forwarded_headers() {
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
        request.add_header("host".to_string(), "wnluo.com".to_string());
        request.add_header("eo-log-uuid".to_string(), "trace".to_string());
        request.add_header(
            "cdn-loop".to_string(),
            "TencentEdgeOne; loops=2".to_string(),
        );
        request.add_header("via".to_string(), "ens-cache".to_string());
        request.add_header("x-cdn-real-ip".to_string(), "1.2.3.4".to_string());
        request.add_header("x-forwarded-for".to_string(), "1.2.3.4".to_string());

        let built = build_http2_upstream_request(&request, &https_upstream("127.0.0.1:880"))
            .expect("request should build");

        assert_eq!(
            built.uri().authority().map(|value| value.as_str()),
            Some("wnluo.com")
        );
        assert!(built.headers().get("host").is_none());
        assert!(built.headers().get("eo-log-uuid").is_none());
        assert!(built.headers().get("cdn-loop").is_none());
        assert!(built.headers().get("via").is_none());
        assert_eq!(built.headers()["x-cdn-real-ip"], "1.2.3.4");
        assert_eq!(built.headers()["x-forwarded-for"], "1.2.3.4");
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
