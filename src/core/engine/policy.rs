fn try_handle_browser_fingerprint_report(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    matched_site: Option<&GatewaySiteRuntime>,
) -> Option<CustomHttpResponse> {
    if request_path(&request.uri) != BROWSER_FINGERPRINT_REPORT_PATH {
        return None;
    }

    Some(handle_browser_fingerprint_report(
        context,
        packet,
        request,
        matched_site,
    ))
}

fn handle_browser_fingerprint_report(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    matched_site: Option<&GatewaySiteRuntime>,
) -> CustomHttpResponse {
    if !request.method.eq_ignore_ascii_case("POST") {
        return json_http_response(
            405,
            serde_json::json!({
                "success": false,
                "message": "浏览器指纹上报只接受 POST 请求",
            }),
            &[("allow", "POST")],
        );
    }

    let Some(store) = context.sqlite_store.as_ref() else {
        return json_http_response(
            503,
            serde_json::json!({
                "success": false,
                "message": "SQLite 事件存储未启用，无法落库浏览器指纹",
            }),
            &[],
        );
    };

    if request.body.is_empty() {
        return json_http_response(
            400,
            serde_json::json!({
                "success": false,
                "message": "浏览器指纹上报体不能为空",
            }),
            &[],
        );
    }

    let mut payload = match serde_json::from_slice::<serde_json::Value>(&request.body) {
        Ok(value) => value,
        Err(err) => {
            return json_http_response(
                400,
                serde_json::json!({
                    "success": false,
                    "message": format!("浏览器指纹上报不是合法 JSON: {}", err),
                }),
                &[],
            );
        }
    };

    let provided_provider_event_id = payload
        .get("fingerprintId")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let derived_provider_event_id = derive_browser_fingerprint_id(&payload);

    let Some(payload_object) = payload.as_object_mut() else {
        return json_http_response(
            400,
            serde_json::json!({
                "success": false,
                "message": "浏览器指纹上报必须是 JSON 对象",
            }),
            &[],
        );
    };

    let source_ip = request
        .client_ip
        .clone()
        .unwrap_or_else(|| packet.source_ip.to_string());
    let provider_event_id = provided_provider_event_id.unwrap_or(derived_provider_event_id);

    payload_object.insert(
        "fingerprintId".to_string(),
        serde_json::Value::String(provider_event_id.clone()),
    );
    payload_object.insert(
        "server".to_string(),
        serde_json::json!({
            "received_at": unix_timestamp(),
            "client_ip": source_ip.clone(),
            "request_id": request.get_header("x-request-id").cloned(),
            "host": request_hostname(request),
            "uri": request.uri,
            "method": request.method,
            "http_version": request.version.to_string(),
            "listener_port": request.get_metadata("listener_port").cloned(),
            "site_id": matched_site.map(|site| site.id),
            "site_name": matched_site.map(|site| site.name.clone()),
            "site_primary_hostname": matched_site.map(|site| site.primary_hostname.clone()),
        }),
    );

    let details_json = match serde_json::to_string_pretty(&payload) {
        Ok(serialized) => serialized,
        Err(err) => {
            return json_http_response(
                500,
                serde_json::json!({
                    "success": false,
                    "message": format!("浏览器指纹序列化失败: {}", err),
                }),
                &[],
            );
        }
    };

    if details_json.len() > MAX_BROWSER_FINGERPRINT_DETAILS_BYTES {
        return json_http_response(
            413,
            serde_json::json!({
                "success": false,
                "message": format!(
                    "浏览器指纹详情过大，最大允许 {} 字节",
                    MAX_BROWSER_FINGERPRINT_DETAILS_BYTES
                ),
            }),
            &[],
        );
    }

    let mut event = SecurityEventRecord::now(
        "L7",
        "respond",
        build_browser_fingerprint_reason(&provider_event_id, &payload),
        source_ip,
        packet.dest_ip.to_string(),
        packet.source_port,
        packet.dest_port,
        format!("{:?}", packet.protocol),
    );
    event.provider = Some("browser_fingerprint".to_string());
    event.provider_event_id = Some(provider_event_id.clone());
    event.provider_site_id = matched_site.map(|site| site.id.to_string());
    event.provider_site_name = matched_site.map(|site| site.name.clone());
    event.provider_site_domain = request_hostname(request)
        .or_else(|| matched_site.map(|site| site.primary_hostname.clone()));
    event.http_method = Some(request.method.clone());
    event.uri = Some(request.uri.clone());
    event.http_version = Some(request.version.to_string());
    event.details_json = Some(details_json);
    store.enqueue_security_event(event);

    json_http_response(
        202,
        serde_json::json!({
            "success": true,
            "message": "浏览器指纹已接收并写入事件库",
            "fingerprint_id": provider_event_id,
        }),
        &[],
    )
}

fn build_browser_fingerprint_reason(
    provider_event_id: &str,
    payload: &serde_json::Value,
) -> String {
    let timezone = payload
        .get("timezone")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let platform = payload
        .get("platform")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let fonts = payload
        .get("fonts")
        .and_then(|value| value.as_array())
        .map(|items| items.len())
        .unwrap_or(0);
    format!(
        "浏览器指纹回传 fp={} tz={} platform={} fonts={}",
        provider_event_id, timezone, platform, fonts
    )
}

fn derive_browser_fingerprint_id(payload: &serde_json::Value) -> String {
    let serialized = serde_json::to_vec(payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&serialized);
    format!("{:x}", hasher.finalize())
        .chars()
        .take(24)
        .collect()
}

fn json_http_response(
    status_code: u16,
    body: serde_json::Value,
    extra_headers: &[(&str, &str)],
) -> CustomHttpResponse {
    let mut headers = vec![
        (
            "content-type".to_string(),
            "application/json; charset=utf-8".to_string(),
        ),
        ("cache-control".to_string(), "no-store".to_string()),
    ];
    headers.extend(
        extra_headers
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string())),
    );

    CustomHttpResponse {
        status_code,
        headers,
        body: serde_json::to_vec(&body).unwrap_or_else(|_| {
            br#"{"success":false,"message":"response serialization failed"}"#.to_vec()
        }),
        tarpit: None,
        random_status: None,
    }
}

fn request_path(uri: &str) -> &str {
    uri.split('?').next().unwrap_or(uri)
}

fn inspect_application_layers(
    context: &WafContext,
    _packet: &PacketInfo,
    _request: &UnifiedHttpRequest,
    serialized_request: &str,
) -> InspectionResult {
    let rule_result = inspect_l7_rules(context, _packet, serialized_request);
    if rule_result.blocked || !rule_result.reason.is_empty() {
        return rule_result;
    }

    InspectionResult::allow(InspectionLayer::L7)
}

fn http_status_text(status_code: u16) -> &'static str {
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

fn inspect_l4_rules(context: &WafContext, packet: &PacketInfo) -> InspectionResult {
    let rule_engine_guard = context
        .rule_engine
        .read()
        .expect("rule_engine lock poisoned");
    let Some(rule_engine) = rule_engine_guard.as_ref() else {
        return InspectionResult::allow(InspectionLayer::L4);
    };

    let rule_result = rule_engine.inspect(packet, None);
    if rule_result.blocked {
        return rule_result;
    }
    if rule_engine.has_rules() && !rule_result.reason.is_empty() {
        match rule_result.action {
            InspectionAction::Alert => {
                debug!("Non-blocking L4 alert rule matched: {}", rule_result.reason);
                return rule_result;
            }
            InspectionAction::Allow => {
                debug!("L4 allow rule matched: {}", rule_result.reason);
                return rule_result;
            }
            InspectionAction::Respond => {
                debug!(
                    "L4 respond rule matched unexpectedly: {}",
                    rule_result.reason
                );
                return rule_result;
            }
            InspectionAction::Block => {}
        }
    }

    InspectionResult::allow(InspectionLayer::L4)
}

fn inspect_l7_rules(
    context: &WafContext,
    packet: &PacketInfo,
    serialized_request: &str,
) -> InspectionResult {
    let rule_engine_guard = context
        .rule_engine
        .read()
        .expect("rule_engine lock poisoned");
    let Some(rule_engine) = rule_engine_guard.as_ref() else {
        return InspectionResult::allow(InspectionLayer::L7);
    };

    let rule_result = rule_engine.inspect(packet, Some(serialized_request));
    if rule_result.blocked {
        return rule_result;
    }
    if rule_engine.has_rules() && !rule_result.reason.is_empty() {
        match rule_result.action {
            InspectionAction::Alert => {
                debug!("Non-blocking L7 alert rule matched: {}", rule_result.reason);
                return rule_result;
            }
            InspectionAction::Allow => {
                debug!("L7 allow rule matched: {}", rule_result.reason);
                return rule_result;
            }
            InspectionAction::Respond => {
                debug!("L7 respond rule matched: {}", rule_result.reason);
                return rule_result;
            }
            InspectionAction::Block => {}
        }
    }

    InspectionResult::allow(InspectionLayer::L7)
}

fn inspect_transport_layers(context: &WafContext, packet: &PacketInfo) -> InspectionResult {
    if let Some(l4_inspector) = &context.l4_inspector {
        let l4_result = l4_inspector.inspect_packet(packet);
        if l4_result.blocked || l4_result.should_persist_event() {
            return l4_result;
        }
    }

    inspect_l4_rules(context, packet)
}

fn persist_l4_inspection_event(
    context: &WafContext,
    packet: &PacketInfo,
    result: &InspectionResult,
) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    store.enqueue_security_event(SecurityEventRecord::now(
        "L4",
        result.event_action(),
        result.reason.clone(),
        packet.source_ip.to_string(),
        packet.dest_ip.to_string(),
        packet.source_port,
        packet.dest_port,
        format!("{:?}", packet.protocol),
    ));

    if result.persist_blocked_ip {
        let blocked_at = unix_timestamp();
        store.enqueue_blocked_ip(BlockedIpRecord::new(
            packet.source_ip.to_string(),
            result.reason.clone(),
            blocked_at,
            blocked_at + RATE_LIMIT_BLOCK_DURATION_SECS as i64,
        ));
    }
}

fn persist_http_inspection_event(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    result: &InspectionResult,
) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    let mut event = SecurityEventRecord::now(
        match result.layer {
            InspectionLayer::L4 => "L4",
            InspectionLayer::L7 => "L7",
        },
        result.event_action(),
        result.reason.clone(),
        request
            .client_ip
            .clone()
            .unwrap_or_else(|| packet.source_ip.to_string()),
        packet.dest_ip.to_string(),
        packet.source_port,
        packet.dest_port,
        format!("{:?}", packet.protocol),
    );
    event.http_method = Some(request.method.clone());
    event.uri = Some(request.uri.clone());
    event.http_version = Some(request.version.to_string());

    store.enqueue_security_event(event);
}

fn persist_safeline_intercept_event(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    matched_site: Option<&GatewaySiteRuntime>,
    matched: &SafeLineInterceptMatch,
    upstream_status_code: u16,
    local_action: &str,
) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    let mut event = SecurityEventRecord::now(
        "L7",
        "block",
        format!(
            "safeline upstream intercept detected; evidence={}; upstream_status={}; local_action={}",
            matched.evidence, upstream_status_code, local_action
        ),
        request
            .client_ip
            .clone()
            .unwrap_or_else(|| packet.source_ip.to_string()),
        packet.dest_ip.to_string(),
        packet.source_port,
        packet.dest_port,
        format!("{:?}", packet.protocol),
    );
    event.provider = Some("safeline".to_string());
    event.provider_event_id = matched.event_id.clone();
    event.provider_site_id = matched_site.map(|site| site.id.to_string());
    event.provider_site_name = matched_site.map(|site| site.name.clone());
    event.provider_site_domain = request_hostname(request)
        .or_else(|| matched_site.map(|site| site.primary_hostname.clone()));
    event.http_method = Some(request.method.clone());
    event.uri = Some(request.uri.clone());
    event.http_version = Some(request.version.to_string());

    store.enqueue_security_event(event);
}

fn persist_safeline_intercept_blocked_ip(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    block_duration_secs: u64,
    provider_event_id: Option<&str>,
) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    let blocked_at = unix_timestamp();
    let ip = request
        .client_ip
        .clone()
        .unwrap_or_else(|| packet.source_ip.to_string());
    let reason = provider_event_id
        .map(|event_id| format!("safeline upstream intercept: event_id={event_id}"))
        .unwrap_or_else(|| "safeline upstream intercept".to_string());

    store.enqueue_blocked_ip(BlockedIpRecord::new(
        ip,
        reason,
        blocked_at,
        blocked_at + block_duration_secs as i64,
    ));
}

fn apply_client_identity(
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

fn prepare_request_for_routing(context: &WafContext, request: &mut UnifiedHttpRequest) {
    ensure_request_id(request);
    if context.config_snapshot().gateway_config.enable_ntlm && request_looks_like_ntlm(request) {
        request.add_metadata("proxy_connection_mode".to_string(), "keep-alive".to_string());
    }
    apply_standard_forwarding_headers(context, request);
}

fn prepare_request_for_proxy(context: &WafContext, request: &mut UnifiedHttpRequest) {
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

fn should_keep_client_connection_open(request: &UnifiedHttpRequest) -> bool {
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

    let preserve_forwarded_chain =
        preserve_forwarded_chain && !context.config_snapshot().gateway_config.rewrite_x_forwarded_for;
    let forwarded_for = match (preserve_forwarded_chain, request.get_header("x-forwarded-for")) {
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
        (false, Some(existing)) if !existing.trim().is_empty() => resolved_client_ip.to_string(),
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
    if !context.config_snapshot().gateway_config.add_x_forwarded_headers {
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

fn expand_request_template(template: &str, request: &UnifiedHttpRequest) -> String {
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

fn apply_response_policies(
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

fn infer_forwarded_proto(request: &UnifiedHttpRequest) -> String {
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

fn redirect_to_https_location(context: &WafContext, request: &UnifiedHttpRequest) -> Option<String> {
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

fn resolve_gateway_site(
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

fn apply_gateway_site_metadata(request: &mut UnifiedHttpRequest, site: &GatewaySiteRuntime) {
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

fn request_hostname(request: &UnifiedHttpRequest) -> Option<String> {
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

fn select_upstream_target(
    context: &WafContext,
    site: Option<&GatewaySiteRuntime>,
) -> Option<String> {
    site.and_then(|site| site.upstream_endpoint.clone())
        .or_else(|| context.config_snapshot().tcp_upstream_addr)
}

fn resolve_safeline_intercept_config<'a>(
    config: &'a crate::config::Config,
    site: Option<&'a GatewaySiteRuntime>,
) -> &'a crate::config::l7::SafeLineInterceptConfig {
    site.and_then(|item| item.safeline_intercept.as_ref())
        .unwrap_or(&config.l7_config.safeline_intercept)
}

fn should_reject_unmatched_site(context: &WafContext, request: &UnifiedHttpRequest) -> bool {
    context.gateway_runtime.has_sites() && request_hostname(request).is_some()
}

fn generate_request_id() -> String {
    let sequence = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}", unix_timestamp(), sequence)
}

fn enforce_upstream_policy(context: &WafContext) -> Result<()> {
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

#[cfg_attr(not(test), allow(dead_code))]
#[allow(dead_code)]
async fn probe_upstream_tcp(upstream_addr: &str, timeout_ms: u64) -> Result<()> {
    super::engine_maintenance::probe_upstream_tcp(upstream_addr, timeout_ms).await
}

fn resolve_client_ip(
    context: &WafContext,
    peer_addr: std::net::SocketAddr,
    request: &UnifiedHttpRequest,
) -> (std::net::IpAddr, &'static str) {
    if !peer_is_trusted_proxy(context, peer_addr.ip()) {
        return (peer_addr.ip(), "socket_peer");
    }

    let gateway = &context.config_snapshot().gateway_config;
    let resolved = match gateway.source_ip_strategy {
        crate::config::SourceIpStrategy::Connection => None,
        crate::config::SourceIpStrategy::XForwardedForFirst => request
            .get_header("x-forwarded-for")
            .and_then(|value| extract_forwarded_ip_by_strategy(value, 0)),
        crate::config::SourceIpStrategy::XForwardedForLast => request
            .get_header("x-forwarded-for")
            .and_then(|value| extract_forwarded_ip_from_right(value, 0)),
        crate::config::SourceIpStrategy::XForwardedForLastButOne => request
            .get_header("x-forwarded-for")
            .and_then(|value| extract_forwarded_ip_from_right(value, 1)),
        crate::config::SourceIpStrategy::XForwardedForLastButTwo => request
            .get_header("x-forwarded-for")
            .and_then(|value| extract_forwarded_ip_from_right(value, 2)),
        crate::config::SourceIpStrategy::Header => gateway
            .custom_source_ip_header
            .trim()
            .is_empty()
            .then_some(None)
            .unwrap_or_else(|| {
                request
                    .get_header(&gateway.custom_source_ip_header)
                    .and_then(|value| extract_forwarded_ip_by_strategy(value, 0))
            }),
        crate::config::SourceIpStrategy::ProxyProtocol => request
            .get_metadata("proxy_protocol_source_ip")
            .and_then(|value| value.parse::<std::net::IpAddr>().ok()),
    };

    if let Some(ip) = resolved {
        (ip, "forwarded_header")
    } else {
        (peer_addr.ip(), "socket_peer")
    }
}

fn peer_is_trusted_proxy(context: &WafContext, peer_ip: std::net::IpAddr) -> bool {
    if peer_ip.is_loopback() {
        return true;
    }

    let config = context.config_snapshot();
    config
        .l7_config
        .trusted_proxy_cidrs
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

fn extract_forwarded_ip_from_right(value: &str, index_from_right: usize) -> Option<std::net::IpAddr> {
    value
        .split(',')
        .rev()
        .nth(index_from_right)
        .and_then(|candidate| candidate.trim().parse::<std::net::IpAddr>().ok())
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::HttpVersion;

    #[test]
    fn rewrite_host_template_expands_http_host() {
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http2_0,
            "GET".to_string(),
            "/".to_string(),
        );
        request.add_header("host".to_string(), "wnluo.com:660".to_string());
        request.add_metadata("listener_port".to_string(), "660".to_string());
        request.add_metadata("scheme".to_string(), "https".to_string());

        let rendered = expand_request_template("$http_host", &request);
        assert_eq!(rendered, "wnluo.com:660");
    }

    #[test]
    fn rewrite_host_template_expands_host_without_port() {
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/".to_string(),
        );
        request.add_header("host".to_string(), "wnluo.com:660".to_string());

        let rendered = expand_request_template("$host", &request);
        assert_eq!(rendered, "wnluo.com");
    }

    #[tokio::test]
    async fn apply_response_policies_replaces_existing_hsts_header() {
        let mut config = crate::config::Config::default();
        config.gateway_config.enable_hsts = true;
        let context = WafContext::new(config).await.unwrap();
        let mut response = vec![
            (
                "strict-transport-security".to_string(),
                "max-age=123".to_string(),
            ),
            ("content-type".to_string(), "text/plain".to_string()),
        ];

        apply_response_policies(&context, &mut response, 200);

        let hsts: Vec<_> = response
            .iter()
            .filter(|(key, _)| key.eq_ignore_ascii_case("strict-transport-security"))
            .collect();
        assert_eq!(hsts.len(), 1);
        assert_eq!(hsts[0].1, "max-age=31536000; includeSubDomains");
    }
}
