use super::*;

pub(crate) fn apply_client_identity(
    context: &WafContext,
    peer_addr: std::net::SocketAddr,
    request: &mut UnifiedHttpRequest,
) {
    let (resolved_client_ip, source_label) = resolve_client_ip(context, peer_addr, request);
    let used_forwarded_header = source_label != "socket_peer";

    request.set_client_ip(resolved_client_ip.to_string());
    request.add_metadata("network.peer_ip".to_string(), peer_addr.ip().to_string());
    request.add_metadata(
        "network.client_ip".to_string(),
        resolved_client_ip.to_string(),
    );
    request.add_metadata(
        "network.client_ip_source".to_string(),
        source_label.to_string(),
    );

    apply_proxy_headers(
        context,
        peer_addr,
        request,
        resolved_client_ip,
        used_forwarded_header,
    );
}

pub(crate) fn prepare_request_for_routing(context: &WafContext, request: &mut UnifiedHttpRequest) {
    ensure_request_id(request);
    if context.config_snapshot().gateway_config.enable_ntlm && request_looks_like_ntlm(request) {
        request.add_metadata(
            "proxy_connection_mode".to_string(),
            "keep-alive".to_string(),
        );
    }
    apply_standard_forwarding_headers(context, request);
}

pub(crate) fn prepare_request_for_proxy(context: &WafContext, request: &mut UnifiedHttpRequest) {
    apply_request_rewrite_policy(context, request);
    apply_request_header_operations(context, request);
}

fn request_looks_like_ntlm(request: &UnifiedHttpRequest) -> bool {
    ["authorization", "proxy-authorization"]
        .iter()
        .filter_map(|header| request.get_header(header))
        .any(|value| {
            let lower = value.to_ascii_lowercase();
            lower.starts_with("ntlm ") || lower.starts_with("negotiate ")
        })
}

pub(crate) fn should_keep_client_connection_open(request: &UnifiedHttpRequest) -> bool {
    if request
        .get_metadata("l4.force_close")
        .map(|value| value == "true")
        .unwrap_or(false)
    {
        return false;
    }

    let connection = request
        .get_header("connection")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    match request.version {
        HttpVersion::Http1_0 => connection.contains("keep-alive"),
        HttpVersion::Http1_1 => !connection.contains("close"),
        _ => false,
    }
}

fn apply_proxy_headers(
    context: &WafContext,
    peer_addr: std::net::SocketAddr,
    request: &mut UnifiedHttpRequest,
    resolved_client_ip: std::net::IpAddr,
    preserve_forwarded_chain: bool,
) {
    request.add_header("x-real-ip".to_string(), resolved_client_ip.to_string());

    let preserve_forwarded_chain = preserve_forwarded_chain
        && !context
            .config_snapshot()
            .gateway_config
            .rewrite_x_forwarded_for;
    let forwarded_for = match (
        preserve_forwarded_chain,
        request.get_header("x-forwarded-for"),
    ) {
        (true, Some(existing)) if !existing.trim().is_empty() => {
            let existing = existing.trim();
            let peer_ip = peer_addr.ip().to_string();
            if existing
                .rsplit(',')
                .next()
                .map(|item| item.trim() == peer_ip)
                .unwrap_or(false)
            {
                existing.to_string()
            } else {
                format!("{existing}, {peer_ip}")
            }
        }
        (false, Some(_existing)) => resolved_client_ip.to_string(),
        _ => resolved_client_ip.to_string(),
    };

    request.add_header("x-forwarded-for".to_string(), forwarded_for);
}

fn ensure_request_id(request: &mut UnifiedHttpRequest) {
    let request_id = request
        .get_header("x-request-id")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(generate_request_id);
    request.add_header("x-request-id".to_string(), request_id.clone());
    request.add_metadata("request_id".to_string(), request_id);
}

fn apply_standard_forwarding_headers(context: &WafContext, request: &mut UnifiedHttpRequest) {
    if !context
        .config_snapshot()
        .gateway_config
        .add_x_forwarded_headers
    {
        return;
    }
    let forwarded_proto = request
        .get_header("x-forwarded-proto")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| infer_forwarded_proto(request));
    request.add_header("x-forwarded-proto".to_string(), forwarded_proto);

    let forwarded_host = request
        .get_header("x-forwarded-host")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| request.get_header("host").cloned())
        .or_else(|| request.get_metadata("authority").cloned());
    if let Some(forwarded_host) = forwarded_host {
        request.add_header("x-forwarded-host".to_string(), forwarded_host);
    }

    if let Some(port) = request
        .get_header("x-forwarded-port")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| request.get_metadata("listener_port").cloned())
    {
        request.add_header("x-forwarded-port".to_string(), port);
    }
}

fn apply_request_rewrite_policy(context: &WafContext, request: &mut UnifiedHttpRequest) {
    let gateway = &context.config_snapshot().gateway_config;
    if gateway.rewrite_host_enabled && !gateway.rewrite_host_value.is_empty() {
        let rewritten = expand_request_template(&gateway.rewrite_host_value, request);
        if !rewritten.trim().is_empty() {
            request.add_header("host".to_string(), rewritten);
        }
    }

    if !gateway.support_gzip || !gateway.support_brotli {
        let filtered = request
            .get_header("accept-encoding")
            .map(|value| {
                value
                    .split(',')
                    .map(|item| item.trim())
                    .filter(|item| {
                        (!item.starts_with("gzip") || gateway.support_gzip)
                            && (!item.starts_with("br") || gateway.support_brotli)
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();

        if filtered.is_empty() {
            request.headers.remove("accept-encoding");
        } else {
            request.add_header("accept-encoding".to_string(), filtered);
        }
    }
}

pub(crate) fn expand_request_template(template: &str, request: &UnifiedHttpRequest) -> String {
    let original_host = request
        .get_header("host")
        .or_else(|| request.get_metadata("authority"))
        .cloned()
        .unwrap_or_default();
    let normalized_host = request_hostname(request).unwrap_or_default();
    let scheme = request
        .get_metadata("scheme")
        .cloned()
        .unwrap_or_else(|| infer_forwarded_proto(request));
    let listener_port = request
        .get_metadata("listener_port")
        .cloned()
        .unwrap_or_default();

    template
        .replace("$http_host", &original_host)
        .replace("${http_host}", &original_host)
        .replace("$host", &normalized_host)
        .replace("${host}", &normalized_host)
        .replace("$scheme", &scheme)
        .replace("${scheme}", &scheme)
        .replace("$server_port", &listener_port)
        .replace("${server_port}", &listener_port)
}

fn apply_request_header_operations(context: &WafContext, request: &mut UnifiedHttpRequest) {
    for item in &context.config_snapshot().gateway_config.header_operations {
        if item.scope != crate::config::HeaderOperationScope::Request {
            continue;
        }

        match item.action {
            crate::config::HeaderOperationAction::Set
            | crate::config::HeaderOperationAction::Add => {
                request.add_header(item.header.clone(), item.value.clone());
            }
            crate::config::HeaderOperationAction::Remove => {
                request.headers.remove(&item.header);
            }
        }
    }
}

pub(crate) fn apply_response_policies(
    context: &WafContext,
    response: &mut Vec<(String, String)>,
    status_code: u16,
) {
    let gateway = &context.config_snapshot().gateway_config;
    if gateway.enable_hsts {
        response.retain(|(key, _)| !key.eq_ignore_ascii_case("strict-transport-security"));
        response.push((
            "strict-transport-security".to_string(),
            "max-age=31536000; includeSubDomains".to_string(),
        ));
    }

    if !gateway.support_sse {
        response.retain(|(key, value)| {
            !(key.eq_ignore_ascii_case("content-type")
                && value.to_ascii_lowercase().contains("text/event-stream"))
        });
    }

    for item in &gateway.header_operations {
        if item.scope != crate::config::HeaderOperationScope::Response {
            continue;
        }
        match item.action {
            crate::config::HeaderOperationAction::Set => {
                response.retain(|(key, _)| !key.eq_ignore_ascii_case(&item.header));
                response.push((item.header.clone(), item.value.clone()));
            }
            crate::config::HeaderOperationAction::Add => {
                response.push((item.header.clone(), item.value.clone()));
            }
            crate::config::HeaderOperationAction::Remove => {
                response.retain(|(key, _)| !key.eq_ignore_ascii_case(&item.header));
            }
        }
    }

    if status_code >= 500 && gateway.fallback_self_signed_certificate {
        response.push((
            "x-rust-waf-fallback-certificate".to_string(),
            "self-signed".to_string(),
        ));
    }
}

fn request_expects_empty_body(request: &UnifiedHttpRequest) -> bool {
    request.method.eq_ignore_ascii_case("HEAD")
}

pub(crate) fn body_for_request(request: &UnifiedHttpRequest, body: &[u8]) -> Vec<u8> {
    if request_expects_empty_body(request) {
        Vec::new()
    } else {
        body.to_vec()
    }
}
