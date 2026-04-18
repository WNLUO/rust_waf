use super::request::build_http2_upstream_request;
use super::tls::{build_upstream_tls_server_name, resolve_upstream_tls_server_name};
use super::*;
use bytes::Bytes;
use dashmap::DashMap;
use http::Request;
use http_body_util::{BodyExt, Full};
use hyper::client::conn::http2 as hyper_http2;
use hyper_util::rt::{TokioExecutor, TokioIo};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpstreamTransport {
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
