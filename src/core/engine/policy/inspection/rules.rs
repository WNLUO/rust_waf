use super::super::*;

pub(crate) fn inspect_application_layers(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    serialized_request: &str,
) -> InspectionResult {
    if request_is_server_public_ip_exempt(context, packet, request) {
        return InspectionResult::allow(InspectionLayer::L7);
    }
    let rule_result = inspect_l7_rules(context, packet, serialized_request);
    if rule_result.blocked || !rule_result.reason.is_empty() {
        return rule_result;
    }

    InspectionResult::allow(InspectionLayer::L7)
}

pub(crate) fn inspect_l7_bloom_filter(
    context: &WafContext,
    request: &mut UnifiedHttpRequest,
    include_body: bool,
) -> Option<InspectionResult> {
    if request
        .get_metadata("network.server_public_ip_exempt")
        .map(|value| value == "true")
        .unwrap_or(false)
    {
        request.add_metadata(
            "l7.bloom.skipped".to_string(),
            "server_public_ip".to_string(),
        );
        return None;
    }
    let bloom = context.l7_bloom_filter()?;
    if !bloom.is_enabled() {
        return None;
    }

    let mut matched = None::<(&'static str, String)>;
    if bloom.check_http_method(&request.method) {
        matched = Some(("method", request.method.clone()));
    } else if bloom.check_url(&request.uri) {
        matched = Some(("url", request.uri.clone()));
    } else if let Some(user_agent) = request.get_header("user-agent") {
        if bloom.check_user_agent(user_agent) {
            matched = Some(("user_agent", summarize_bloom_value(user_agent)));
        }
    }

    if matched.is_none() {
        if let Some(cookie) = request.get_header("cookie") {
            if bloom.check_cookie(cookie) {
                matched = Some(("cookie", "[redacted]".to_string()));
            }
        }
    }

    if matched.is_none() {
        let headers = request
            .headers
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect::<Vec<_>>();
        if bloom.check_headers(&headers) {
            matched = Some(("headers", "header_signature".to_string()));
        }
    }

    if matched.is_none() && include_body && !request.body.is_empty() {
        let payload = String::from_utf8_lossy(&request.body);
        if bloom.check_payload(payload.as_ref()) {
            matched = Some(("payload", summarize_bloom_value(payload.as_ref())));
        }
    }

    let (category, value) = matched?;
    request.add_metadata("l7.bloom.action".to_string(), "drop".to_string());
    request.add_metadata("l7.bloom.category".to_string(), category.to_string());
    request.add_metadata("l7.bloom.matched".to_string(), value.clone());
    request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
    request.add_metadata("l7.drop_reason".to_string(), "l7_bloom_filter".to_string());
    request.add_metadata("l4.force_close".to_string(), "true".to_string());

    Some(InspectionResult::drop(
        InspectionLayer::L7,
        format!("l7 bloom filter matched {category}: {value}"),
    ))
}

fn summarize_bloom_value(value: &str) -> String {
    let normalized = value.trim().replace('\n', " ").replace('\r', " ");
    if normalized.len() <= 160 {
        normalized
    } else {
        format!("{}...", &normalized[..160])
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
            InspectionAction::Drop => {
                debug!("L4 drop rule matched: {}", rule_result.reason);
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
            InspectionAction::Drop => {
                debug!("L7 drop rule matched: {}", rule_result.reason);
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
    if context.is_server_public_ip(packet.source_ip) {
        return InspectionResult::allow(InspectionLayer::L4);
    }
    if let Some(l4_inspector) = context.l4_inspector() {
        let l4_result = l4_inspector.inspect_packet(packet, trusted_proxy_peer);
        if l4_result.blocked || l4_result.should_persist_event() {
            return l4_result;
        }
    }

    inspect_l4_rules(context, packet)
}

fn request_is_server_public_ip_exempt(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
) -> bool {
    request
        .get_metadata("network.server_public_ip_exempt")
        .map(|value| value == "true")
        .unwrap_or(false)
        || request
            .client_ip
            .as_deref()
            .map(|ip| context.is_server_public_ip_str(ip))
            .unwrap_or(false)
        || context.is_server_public_ip(packet.source_ip)
}
