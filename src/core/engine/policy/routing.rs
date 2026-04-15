use super::*;
use crate::core::engine_maintenance;

pub(crate) fn http_status_text(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

pub(crate) fn infer_forwarded_proto(request: &UnifiedHttpRequest) -> String {
    if matches!(request.version, HttpVersion::Http3_0) {
        return "https".to_string();
    }

    if request
        .get_metadata("transport")
        .map(|transport| {
            transport.eq_ignore_ascii_case("tls") || transport.eq_ignore_ascii_case("quic")
        })
        .unwrap_or(false)
    {
        return "https".to_string();
    }

    "http".to_string()
}

pub(crate) fn redirect_to_https_location(
    context: &WafContext,
    request: &UnifiedHttpRequest,
) -> Option<String> {
    let gateway = &context.config_snapshot().gateway_config;
    if !gateway.http_to_https_redirect || gateway.https_listen_addr.trim().is_empty() {
        return None;
    }
    if infer_forwarded_proto(request) == "https" {
        return None;
    }

    let host = request
        .get_header("host")
        .cloned()
        .or_else(|| request.get_metadata("authority").cloned())?;
    let host_without_port = request_hostname(request).unwrap_or(host.clone());
    let https_port = gateway
        .https_listen_addr
        .parse::<std::net::SocketAddr>()
        .ok()
        .map(|addr| addr.port())
        .unwrap_or(443);
    let authority = if https_port == 443 {
        host_without_port
    } else {
        format!("{host_without_port}:{https_port}")
    };
    Some(format!("https://{}{}", authority, request.uri))
}

pub(crate) fn resolve_gateway_site(
    context: &WafContext,
    request: &UnifiedHttpRequest,
) -> Option<GatewaySiteRuntime> {
    let listener_port = request
        .get_metadata("listener_port")
        .and_then(|port| port.parse::<u16>().ok())?;
    let hostname = request_hostname(request);
    context
        .gateway_runtime
        .resolve_site(hostname.as_deref(), listener_port)
}

pub(crate) fn apply_gateway_site_metadata(
    request: &mut UnifiedHttpRequest,
    site: &GatewaySiteRuntime,
) {
    request.add_metadata("gateway.site_id".to_string(), site.id.to_string());
    request.add_metadata("gateway.site_name".to_string(), site.name.clone());
    request.add_metadata(
        "gateway.primary_hostname".to_string(),
        site.primary_hostname.clone(),
    );
    if let Some(upstream) = &site.upstream_endpoint {
        request.add_metadata("gateway.upstream".to_string(), upstream.clone());
    }
}

pub(crate) fn request_hostname(request: &UnifiedHttpRequest) -> Option<String> {
    request
        .get_header("host")
        .or_else(|| request.get_metadata("authority"))
        .and_then(|value| normalize_request_host(value))
}

fn normalize_request_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(uri) = format!("http://{}", trimmed).parse::<http::Uri>() {
        if let Some(authority) = uri.authority() {
            return normalize_hostname(authority.host());
        }
    }

    if let Some(host) = trimmed
        .strip_prefix('[')
        .and_then(|value| value.split(']').next())
    {
        return normalize_hostname(host);
    }

    normalize_hostname(trimmed.split(':').next().unwrap_or(trimmed))
}

pub(crate) fn select_upstream_target(site: Option<&GatewaySiteRuntime>) -> Option<String> {
    site.and_then(|site| site.upstream_endpoint.clone())
}

pub(crate) fn resolve_safeline_intercept_config<'a>(
    config: &'a crate::config::Config,
    site: Option<&'a GatewaySiteRuntime>,
) -> &'a crate::config::l7::SafeLineInterceptConfig {
    site.and_then(|item| item.safeline_intercept.as_ref())
        .unwrap_or(&config.l7_config.safeline_intercept)
}

pub(crate) fn should_reject_unmatched_site(
    context: &WafContext,
    request: &UnifiedHttpRequest,
) -> bool {
    context.gateway_runtime.has_sites() && request_hostname(request).is_some()
}

pub(crate) fn generate_request_id() -> String {
    let sequence = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}", unix_timestamp(), sequence)
}

pub(crate) fn enforce_upstream_policy(context: &WafContext) -> Result<()> {
    let snapshot = context.upstream_health_snapshot();
    if snapshot.healthy {
        return Ok(());
    }

    match context.config_snapshot().l7_config.upstream_failure_mode {
        UpstreamFailureMode::FailOpen => Ok(()),
        UpstreamFailureMode::FailClose => Err(anyhow::anyhow!(
            "{}",
            snapshot
                .last_error
                .unwrap_or_else(|| "Upstream health check reports unhealthy".to_string())
        )),
    }
}

#[allow(dead_code)]
async fn probe_upstream_tcp(upstream_addr: &str, timeout_ms: u64) -> Result<()> {
    engine_maintenance::probe_upstream_tcp(upstream_addr, timeout_ms).await
}

pub(crate) fn resolve_client_ip(
    context: &WafContext,
    peer_addr: std::net::SocketAddr,
    request: &UnifiedHttpRequest,
) -> (std::net::IpAddr, &'static str, Option<String>) {
    let config = context.config_snapshot();
    let gateway = &config.gateway_config;
    let trusted_proxy_peer = peer_is_trusted_proxy(context, peer_addr.ip());

    if matches!(
        gateway.source_ip_strategy,
        crate::config::SourceIpStrategy::Header
    ) {
        let resolved = if gateway.custom_source_ip_header.trim().is_empty() {
            None
        } else {
            request
                .get_header(&gateway.custom_source_ip_header)
                .and_then(|value| extract_forwarded_ip_by_strategy(value, 0))
                .map(|ip| (ip, Some(gateway.custom_source_ip_header.clone())))
        };

        return if let Some((ip, header)) = resolved {
            (ip, "forwarded_header", header)
        } else {
            (peer_addr.ip(), "socket_peer", None)
        };
    }

    if !trusted_proxy_peer {
        return (peer_addr.ip(), "socket_peer", None);
    }

    let resolved = match gateway.source_ip_strategy {
        crate::config::SourceIpStrategy::Connection => None,
        crate::config::SourceIpStrategy::XForwardedForFirst => request
            .get_header("x-forwarded-for")
            .and_then(|value| extract_forwarded_ip_by_strategy(value, 0))
            .map(|ip| (ip, Some("x-forwarded-for".to_string()))),
        crate::config::SourceIpStrategy::XForwardedForLast => request
            .get_header("x-forwarded-for")
            .and_then(|value| extract_forwarded_ip_from_right(value, 0))
            .map(|ip| (ip, Some("x-forwarded-for".to_string()))),
        crate::config::SourceIpStrategy::XForwardedForLastButOne => request
            .get_header("x-forwarded-for")
            .and_then(|value| extract_forwarded_ip_from_right(value, 1))
            .map(|ip| (ip, Some("x-forwarded-for".to_string()))),
        crate::config::SourceIpStrategy::XForwardedForLastButTwo => request
            .get_header("x-forwarded-for")
            .and_then(|value| extract_forwarded_ip_from_right(value, 2))
            .map(|ip| (ip, Some("x-forwarded-for".to_string()))),
        crate::config::SourceIpStrategy::Header => None,
        crate::config::SourceIpStrategy::ProxyProtocol => request
            .get_metadata("proxy_protocol_source_ip")
            .and_then(|value| value.parse::<std::net::IpAddr>().ok())
            .map(|ip| (ip, None)),
    };

    if let Some((ip, header)) = resolved {
        (ip, "forwarded_header", header)
    } else {
        (peer_addr.ip(), "socket_peer", None)
    }
}

fn peer_is_trusted_proxy(context: &WafContext, peer_ip: std::net::IpAddr) -> bool {
    if peer_ip.is_loopback() {
        return true;
    }

    let config = context.config_snapshot();
    config
        .effective_trusted_proxy_cidrs()
        .iter()
        .filter_map(|cidr| cidr.parse::<IpNet>().ok())
        .any(|network| network.contains(&peer_ip))
}

fn extract_forwarded_ip_by_strategy(value: &str, index: usize) -> Option<std::net::IpAddr> {
    value
        .split(',')
        .nth(index)
        .and_then(|candidate| candidate.trim().parse::<std::net::IpAddr>().ok())
}

fn extract_forwarded_ip_from_right(
    value: &str,
    index_from_right: usize,
) -> Option<std::net::IpAddr> {
    value
        .split(',')
        .rev()
        .nth(index_from_right)
        .and_then(|candidate| candidate.trim().parse::<std::net::IpAddr>().ok())
}

pub(crate) fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
