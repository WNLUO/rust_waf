use super::request::build_http2_upstream_request;
use super::tls::{build_upstream_tls_server_name, resolve_upstream_tls_server_name};
use super::*;
use bytes::Bytes;
use dashmap::DashMap;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2 as hyper_http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const HTTP2_POOL_MAX_ENTRIES: usize = 128;
const HTTP2_POOL_IDLE_SECS: u64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpstreamTransport {
    Http1,
    Http2,
}

type Http2Sender = hyper_http2::SendRequest<Full<Bytes>>;

#[derive(Debug)]
struct PooledHttp2Connection {
    sender: tokio::sync::Mutex<Http2Sender>,
    last_used_unix: AtomicU64,
}

fn http2_pool() -> &'static DashMap<String, Arc<PooledHttp2Connection>> {
    static POOL: OnceLock<DashMap<String, Arc<PooledHttp2Connection>>> = OnceLock::new();
    POOL.get_or_init(DashMap::new)
}

pub(super) fn select_upstream_transport(
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

pub(super) async fn proxy_http2_request(
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
    pooled
        .last_used_unix
        .store(current_unix_second(), Ordering::Relaxed);
    let mut guard = pooled.sender.lock().await;
    let response = tokio::time::timeout(
        std::time::Duration::from_millis(read_timeout_ms),
        guard.send_request(upstream_request),
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

pub(super) async fn proxy_http2_request_to_http1_client<W>(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
    connect_timeout_ms: u64,
    read_timeout_ms: u64,
    client_stream: &mut W,
) -> Result<super::StreamedUpstreamResponse>
where
    W: AsyncWrite + Unpin,
{
    if !matches!(upstream.scheme, UpstreamScheme::Https) {
        anyhow::bail!("Upstream HTTP/2 currently requires HTTPS upstreams");
    }

    let pool_key = build_http2_pool_key(context, request, upstream)?;
    let pooled =
        get_or_connect_http2_sender(context, request, upstream, &pool_key, connect_timeout_ms)
            .await?;
    let upstream_request = build_http2_upstream_request(request, upstream)?;
    emit_http2_upstream_request_debug_event(context, request, upstream, &upstream_request)?;
    pooled
        .last_used_unix
        .store(current_unix_second(), Ordering::Relaxed);
    let mut guard = pooled.sender.lock().await;
    let response = tokio::time::timeout(
        std::time::Duration::from_millis(read_timeout_ms),
        guard.send_request(upstream_request),
    )
    .await;
    match response {
        Ok(Ok(response)) => {
            emit_http2_upstream_response_debug_event(context, request, &response);
            let (parts, mut body) = response.into_parts();
            let mut headers = parts
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value.to_string()))
                })
                .collect::<Vec<_>>();
            apply_response_policies(context, &mut headers, parts.status.as_u16());
            Http1Handler::new()
                .write_response_head_with_headers(
                    client_stream,
                    parts.status.as_u16(),
                    parts
                        .status
                        .canonical_reason()
                        .unwrap_or(http_status_text(parts.status.as_u16())),
                    &headers,
                    None,
                    true,
                )
                .await?;

            let mut body_bytes_sent = 0usize;
            while let Some(frame) = tokio::time::timeout(
                std::time::Duration::from_millis(read_timeout_ms),
                body.frame(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Upstream HTTP/2 body read timed out"))?
            {
                let frame = frame?;
                if let Ok(data) = frame.into_data() {
                    body_bytes_sent = body_bytes_sent.saturating_add(data.len());
                    client_stream.write_all(data.as_ref()).await?;
                    client_stream.flush().await?;
                }
            }

            context.set_upstream_health(true, None);
            Ok(super::StreamedUpstreamResponse {
                status_code: parts.status.as_u16(),
                body_bytes_sent,
            })
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

#[cfg(feature = "http3")]
pub(super) async fn proxy_http2_request_to_http3_client(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream: &crate::core::gateway::UpstreamEndpoint,
    connect_timeout_ms: u64,
    read_timeout_ms: u64,
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<super::StreamedUpstreamResponse> {
    if !matches!(upstream.scheme, UpstreamScheme::Https) {
        anyhow::bail!("Upstream HTTP/2 currently requires HTTPS upstreams");
    }

    let pool_key = build_http2_pool_key(context, request, upstream)?;
    let pooled =
        get_or_connect_http2_sender(context, request, upstream, &pool_key, connect_timeout_ms)
            .await?;
    let upstream_request = build_http2_upstream_request(request, upstream)?;
    emit_http2_upstream_request_debug_event(context, request, upstream, &upstream_request)?;
    pooled
        .last_used_unix
        .store(current_unix_second(), Ordering::Relaxed);
    let mut guard = pooled.sender.lock().await;
    let response = tokio::time::timeout(
        std::time::Duration::from_millis(read_timeout_ms),
        guard.send_request(upstream_request),
    )
    .await;
    match response {
        Ok(Ok(response)) => {
            emit_http2_upstream_response_debug_event(context, request, &response);
            let (parts, mut body) = response.into_parts();
            let mut builder = http::Response::builder().status(parts.status.as_u16());
            let mut headers = parts
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value.to_string()))
                })
                .collect::<Vec<_>>();
            apply_response_policies(context, &mut headers, parts.status.as_u16());
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
            while let Some(frame) = tokio::time::timeout(
                std::time::Duration::from_millis(read_timeout_ms),
                body.frame(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Upstream HTTP/2 body read timed out"))?
            {
                let frame = frame?;
                if let Ok(data) = frame.into_data() {
                    body_bytes_sent = body_bytes_sent.saturating_add(data.len());
                    stream.send_data(data).await?;
                }
            }
            stream.finish().await?;

            context.set_upstream_health(true, None);
            Ok(super::StreamedUpstreamResponse {
                status_code: parts.status.as_u16(),
                body_bytes_sent,
            })
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
) -> Result<Arc<PooledHttp2Connection>> {
    cleanup_http2_pool(context);
    if let Some(existing) = http2_pool().get(pool_key) {
        existing
            .last_used_unix
            .store(current_unix_second(), Ordering::Relaxed);
        return Ok(existing.clone());
    }

    let sender = connect_http2_sender(context, request, upstream, connect_timeout_ms).await?;
    let pooled = Arc::new(PooledHttp2Connection {
        sender: tokio::sync::Mutex::new(sender),
        last_used_unix: AtomicU64::new(current_unix_second()),
    });
    let pooled_ref = pooled.clone();
    let entry = http2_pool()
        .entry(pool_key.to_string())
        .or_insert_with(|| pooled_ref);
    entry
        .value()
        .last_used_unix
        .store(current_unix_second(), Ordering::Relaxed);
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

fn cleanup_http2_pool(context: &WafContext) {
    let now = current_unix_second();
    let idle_before = now.saturating_sub(HTTP2_POOL_IDLE_SECS);
    let mut removed = 0u64;

    http2_pool().retain(|_, connection| {
        let keep = connection.last_used_unix.load(Ordering::Relaxed) >= idle_before;
        if !keep {
            removed = removed.saturating_add(1);
        }
        keep
    });

    let overflow = http2_pool().len().saturating_sub(HTTP2_POOL_MAX_ENTRIES);
    if overflow > 0 {
        let mut idle_entries = http2_pool()
            .iter()
            .map(|entry| {
                (
                    entry.key().clone(),
                    entry.value().last_used_unix.load(Ordering::Relaxed),
                )
            })
            .collect::<Vec<_>>();
        idle_entries.sort_by_key(|(_, last_used)| *last_used);
        for (key, _) in idle_entries.into_iter().take(overflow) {
            if http2_pool().remove(&key).is_some() {
                removed = removed.saturating_add(1);
            }
        }
    }

    if removed > 0 {
        if let Some(metrics) = context.metrics.as_ref() {
            for _ in 0..removed {
                metrics.record_http2_pool_eviction();
            }
        }
        debug!(
            "Evicted {} idle/excess HTTP/2 upstream pooled connection(s)",
            removed
        );
    }
}

fn current_unix_second() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
