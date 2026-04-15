use super::*;
use serde_json::json;

pub(crate) fn inspect_application_layers(
    context: &WafContext,
    packet: &PacketInfo,
    _request: &UnifiedHttpRequest,
    serialized_request: &str,
) -> InspectionResult {
    let rule_result = inspect_l7_rules(context, packet, serialized_request);
    if rule_result.blocked || !rule_result.reason.is_empty() {
        return rule_result;
    }

    InspectionResult::allow(InspectionLayer::L7)
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

pub(crate) fn inspect_transport_layers(
    context: &WafContext,
    packet: &PacketInfo,
    trusted_proxy_peer: bool,
) -> InspectionResult {
    if let Some(l4_inspector) = context.l4_inspector() {
        let l4_result = l4_inspector.inspect_packet(packet, trusted_proxy_peer);
        if l4_result.blocked || l4_result.should_persist_event() {
            return l4_result;
        }
    }

    inspect_l4_rules(context, packet)
}

pub(crate) fn persist_l4_inspection_event(
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

pub(crate) fn persist_http_inspection_event(
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
    event.details_json = build_request_identity_details(context, request, packet);

    store.enqueue_security_event(event);

    if result.persist_blocked_ip {
        let blocked_at = unix_timestamp();
        let ip = request
            .client_ip
            .clone()
            .unwrap_or_else(|| packet.source_ip.to_string());
        store.enqueue_blocked_ip(BlockedIpRecord::new(
            ip,
            result.reason.clone(),
            blocked_at,
            blocked_at + crate::l7::behavior_guard::AUTO_BLOCK_DURATION_SECS as i64,
        ));
    }
}

pub(crate) fn persist_http_identity_debug_event(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
) {
    if !context
        .config_snapshot()
        .console_settings
        .client_identity_debug_enabled
    {
        return;
    }

    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };
    let configured_header = context
        .config_snapshot()
        .gateway_config
        .custom_source_ip_header;

    let mut event = SecurityEventRecord::now(
        "L7",
        "log",
        "client identity debug".to_string(),
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
    event.details_json =
        build_request_identity_details_with_header(&configured_header, request, packet);

    store.enqueue_security_event(event);
}

pub(crate) fn persist_upstream_http2_debug_event(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    stage: &str,
    details: serde_json::Value,
) {
    if !context
        .config_snapshot()
        .console_settings
        .client_identity_debug_enabled
    {
        return;
    }

    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    let mut event = SecurityEventRecord::now(
        "L7",
        "log",
        format!("upstream http2 debug ({stage})"),
        request
            .client_ip
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        "upstream".to_string(),
        0,
        0,
        "HTTP/2".to_string(),
    );
    event.http_method = Some(request.method.clone());
    event.uri = Some(request.uri.clone());
    event.http_version = Some(request.version.to_string());
    event.details_json = serde_json::to_string_pretty(&details).ok();

    store.enqueue_security_event(event);
}

pub(crate) fn persist_safeline_intercept_event(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    matched_site: Option<&GatewaySiteRuntime>,
    provider_event_id: Option<&str>,
    evidence: &str,
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
            evidence, upstream_status_code, local_action
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
    event.provider_event_id = provider_event_id.map(ToOwned::to_owned);
    event.provider_site_id = matched_site.map(|site| site.id.to_string());
    event.provider_site_name = matched_site.map(|site| site.name.clone());
    event.provider_site_domain = request_hostname(request)
        .or_else(|| matched_site.map(|site| site.primary_hostname.clone()));
    event.http_method = Some(request.method.clone());
    event.uri = Some(request.uri.clone());
    event.http_version = Some(request.version.to_string());
    event.details_json = build_request_identity_details(context, request, packet);

    store.enqueue_security_event(event);
}

pub(crate) fn persist_safeline_intercept_blocked_ip(
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

pub(crate) fn enforce_runtime_http_block_if_needed(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    result: &InspectionResult,
) {
    if !result.persist_blocked_ip {
        return;
    }

    let Some(inspector) = context.l4_inspector() else {
        return;
    };

    let ip = request
        .client_ip
        .as_deref()
        .and_then(|value| value.parse::<std::net::IpAddr>().ok())
        .unwrap_or(packet.source_ip);

    inspector.block_ip(
        &ip,
        &result.reason,
        std::time::Duration::from_secs(crate::l7::behavior_guard::AUTO_BLOCK_DURATION_SECS),
    );
}

fn build_request_identity_details(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    packet: &PacketInfo,
) -> Option<String> {
    let configured_header = context
        .config_snapshot()
        .gateway_config
        .custom_source_ip_header;
    build_request_identity_details_with_header(&configured_header, request, packet)
}

fn build_request_identity_details_with_header(
    configured_header: &str,
    request: &UnifiedHttpRequest,
    packet: &PacketInfo,
) -> Option<String> {
    let client_ip = request
        .client_ip
        .clone()
        .unwrap_or_else(|| packet.source_ip.to_string());
    let source_header_value = if configured_header.trim().is_empty() {
        None
    } else {
        request.get_header(&configured_header).cloned()
    };
    let mut headers = request
        .headers
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    headers.sort_by(|left, right| left.0.cmp(&right.0));
    let payload = json!({
        "client_identity": {
            "resolved_client_ip": client_ip,
            "source_ip": packet.source_ip.to_string(),
            "peer_ip": request.get_metadata("network.peer_ip").cloned().unwrap_or_else(|| packet.source_ip.to_string()),
            "client_ip_source": request.get_metadata("network.client_ip_source").cloned().unwrap_or_else(|| "unknown".to_string()),
            "client_ip_unresolved": request.get_metadata("network.client_ip_unresolved").cloned().unwrap_or_else(|| "false".to_string()),
            "trusted_proxy_peer": request.get_metadata("network.trusted_proxy_peer").cloned().unwrap_or_else(|| "false".to_string()),
            "identity_state": request.get_metadata("network.identity_state").cloned().unwrap_or_else(|| "unknown".to_string()),
            "forward_header_present": request.get_metadata("network.forward_header_present").cloned().unwrap_or_else(|| "false".to_string()),
            "forward_header_valid": request.get_metadata("network.forward_header_valid").cloned().unwrap_or_else(|| "false".to_string()),
            "configured_real_ip_header": configured_header,
            "configured_real_ip_header_value": source_header_value,
            "x_real_ip": request.get_header("x-real-ip").cloned(),
            "x_forwarded_for": request.get_header("x-forwarded-for").cloned(),
            "http_version": request.version.to_string(),
            "headers": headers,
        },
        "l7_cc": {
            "action": request.get_metadata("l7.cc.action").cloned(),
            "request_kind": request.get_metadata("l7.cc.request_kind").cloned(),
            "route": request.get_metadata("l7.cc.route").cloned(),
            "host": request.get_metadata("l7.cc.host").cloned(),
            "route_weighted": request.get_metadata("l7.cc.route_weighted").cloned(),
            "hot_path_weighted": request.get_metadata("l7.cc.hot_path_weighted").cloned(),
            "hot_path_clients": request.get_metadata("l7.cc.hot_path_clients").cloned(),
            "challenge_verified": request.get_metadata("l7.cc.challenge_verified").cloned(),
        },
        "l7_behavior": {
            "action": request.get_metadata("l7.behavior.action").cloned(),
            "score": request.get_metadata("l7.behavior.score").cloned(),
            "identity": request.get_metadata("l7.behavior.identity").cloned(),
            "dominant_route": request.get_metadata("l7.behavior.dominant_route").cloned(),
            "focused_document_route": request.get_metadata("l7.behavior.focused_document_route").cloned(),
            "distinct_routes": request.get_metadata("l7.behavior.distinct_routes").cloned(),
            "repeated_ratio": request.get_metadata("l7.behavior.repeated_ratio").cloned(),
            "document_repeated_ratio": request.get_metadata("l7.behavior.document_repeated_ratio").cloned(),
            "interval_jitter_ms": request.get_metadata("l7.behavior.interval_jitter_ms").cloned(),
            "document_requests": request.get_metadata("l7.behavior.document_requests").cloned(),
            "non_document_requests": request.get_metadata("l7.behavior.non_document_requests").cloned(),
            "challenge_count_window": request.get_metadata("l7.behavior.challenge_count_window").cloned(),
            "session_span_secs": request.get_metadata("l7.behavior.session_span_secs").cloned(),
            "flags": request.get_metadata("l7.behavior.flags").cloned(),
        },
        "l4_runtime": {
            "identity_state": request.get_metadata("l4.identity_state").cloned(),
            "bucket_risk": request.get_metadata("l4.bucket_risk").cloned(),
            "bucket_score": request.get_metadata("l4.bucket_score").cloned(),
            "overload_level": request.get_metadata("l4.overload_level").cloned(),
            "force_close": request.get_metadata("l4.force_close").cloned(),
            "suggested_delay_ms": request.get_metadata("l4.suggested_delay_ms").cloned(),
        },
        "inspection_runtime": {
            "rule_inspection_mode": request.get_metadata("l7.rule_inspection_mode").cloned(),
            "cc_identity_state": request.get_metadata("l7.cc.identity_state").cloned(),
        }
    });

    serde_json::to_string_pretty(&payload).ok()
}
