use super::super::*;
use serde_json::json;

pub(super) fn build_request_identity_details(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    packet: &PacketInfo,
    result: Option<&InspectionResult>,
) -> Option<String> {
    let configured_header = context
        .config_snapshot()
        .gateway_config
        .custom_source_ip_header;
    build_request_identity_details_with_header(&configured_header, request, packet, result)
}

pub(super) fn build_request_identity_details_with_header(
    configured_header: &str,
    request: &UnifiedHttpRequest,
    packet: &PacketInfo,
    result: Option<&InspectionResult>,
) -> Option<String> {
    let client_ip = request
        .client_ip
        .clone()
        .unwrap_or_else(|| packet.source_ip.to_string());
    let source_header_value = if configured_header.trim().is_empty() {
        None
    } else {
        request
            .get_header(&configured_header)
            .map(|value| summarize_header_value(configured_header, value))
    };
    let mut headers = summarized_request_headers(request);
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
            "x_real_ip": request.get_header("x-real-ip").map(|value| summarize_header_value("x-real-ip", value)),
            "x_forwarded_for": request.get_header("x-forwarded-for").map(|value| summarize_header_value("x-forwarded-for", value)),
            "http_version": request.version.to_string(),
            "headers": headers,
        },
        "client_trust": {
            "trust_class": request.get_metadata("client.trust_class").cloned(),
            "policy": request.get_metadata("client.policy").cloned(),
            "reason": request.get_metadata("client.trust_reason").cloned(),
            "internal_task": request.get_metadata("internal.task").cloned(),
        },
        "bot": {
            "known": request.get_metadata("bot.known").cloned(),
            "name": request.get_metadata("bot.name").cloned(),
            "provider": request.get_metadata("bot.provider").cloned(),
            "category": request.get_metadata("bot.category").cloned(),
            "verification": request.get_metadata("bot.verification").cloned(),
            "policy": request.get_metadata("bot.policy").cloned(),
        },
        "ip_access": {
            "enabled": request.get_metadata("ip_access.enabled").cloned(),
            "mode": request.get_metadata("ip_access.mode").cloned(),
            "action": request.get_metadata("ip_access.action").cloned(),
            "reason": request.get_metadata("ip_access.reason").cloned(),
            "client_ip": request.get_metadata("ip_access.client_ip").cloned(),
            "country_code": request.get_metadata("ip_access.country_code").cloned(),
            "region": request.get_metadata("ip_access.region").cloned(),
            "city": request.get_metadata("ip_access.city").cloned(),
            "geo_source": request.get_metadata("ip_access.geo.source").cloned(),
            "geo_trusted": request.get_metadata("ip_access.geo.trusted").cloned(),
            "geo_header": request.get_metadata("ip_access.geo.header").cloned(),
            "geo_header_ignored": request.get_metadata("ip_access.geo.header_ignored").cloned(),
            "bot_trust_class": request.get_metadata("ip_access.bot.trust_class").cloned(),
            "bot_category": request.get_metadata("ip_access.bot.category").cloned(),
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
            "known_bot_threshold_multiplier": request.get_metadata("l7.cc.known_bot_threshold_multiplier").cloned(),
            "bot_threshold_scale_percent": request.get_metadata("l7.cc.bot_threshold_scale_percent").cloned(),
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
        "l7_bloom": {
            "action": request.get_metadata("l7.bloom.action").cloned(),
            "category": request.get_metadata("l7.bloom.category").cloned(),
            "matched": request.get_metadata("l7.bloom.matched").cloned(),
        },
        "ai_temp_policy": {
            "action": request.get_metadata("ai.policy.action").cloned(),
            "matched_count": request.get_metadata("ai.policy.matched_count").cloned(),
            "matched_ids": request.get_metadata("ai.policy.matched_ids").cloned(),
            "matched_actions": request.get_metadata("ai.policy.matched_actions").cloned(),
            "temp_block_duration_secs": request.get_metadata("ai.temp_block_duration_secs").cloned(),
            "cc_route_threshold_scale_percent": request.get_metadata("ai.cc.route_threshold_scale_percent").cloned(),
            "cc_host_threshold_scale_percent": request.get_metadata("ai.cc.host_threshold_scale_percent").cloned(),
            "cc_extra_delay_ms": request.get_metadata("ai.cc.extra_delay_ms").cloned(),
            "cc_force_challenge": request.get_metadata("ai.cc.force_challenge").cloned(),
            "behavior_score_boost": request.get_metadata("ai.behavior.score_boost").cloned(),
            "behavior_force_watch": request.get_metadata("ai.behavior.force_watch").cloned(),
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
            "decision_action": result.map(InspectionResult::event_action),
            "decision_layer": result.map(|result| match &result.layer { InspectionLayer::L4 => "L4", InspectionLayer::L7 => "L7" }),
            "decision_persist_blocked_ip": result.map(|result| result.persist_blocked_ip),
            "decision_reason": result.map(|result| result.reason.clone()),
            "enforcement": request.get_metadata("l7.enforcement").cloned(),
            "drop_reason": request.get_metadata("l7.drop_reason").cloned(),
            "rule_inspection_mode": request.get_metadata("l7.rule_inspection_mode").cloned(),
            "cc_identity_state": request.get_metadata("l7.cc.identity_state").cloned(),
            "runtime_pressure_level": request.get_metadata("runtime.pressure.level").cloned(),
            "runtime_pressure_storage_queue_percent": request.get_metadata("runtime.pressure.storage_queue_percent").cloned(),
            "runtime_pressure_drop_delay": request.get_metadata("runtime.pressure.drop_delay").cloned(),
            "runtime_pressure_trim_event_persistence": request.get_metadata("runtime.pressure.trim_event_persistence").cloned(),
            "runtime_capacity_class": request.get_metadata("runtime.capacity.class").cloned(),
            "runtime_defense_depth": request.get_metadata("runtime.defense.depth").cloned(),
            "runtime_site_defense_depth": request.get_metadata("runtime.site.defense_depth").cloned(),
            "runtime_site_defense_reason": request.get_metadata("runtime.site.defense_reason").cloned(),
            "runtime_route_defense_depth": request.get_metadata("runtime.route.defense_depth").cloned(),
            "runtime_route_defense_route": request.get_metadata("runtime.route.defense_route").cloned(),
            "runtime_route_cc_threshold_scale_percent": request.get_metadata("runtime.route.cc_threshold_scale_percent").cloned(),
            "runtime_aggregate_events": request.get_metadata("runtime.aggregate_events").cloned(),
        }
    });

    serde_json::to_string_pretty(&payload).ok()
}

fn summarized_request_headers(request: &UnifiedHttpRequest) -> Vec<(String, String)> {
    const ALLOWED_HEADERS: &[&str] = &[
        "host",
        "user-agent",
        "accept",
        "accept-language",
        "accept-encoding",
        "referer",
        "origin",
        "cache-control",
        "content-type",
        "content-length",
        "x-forwarded-for",
        "x-real-ip",
        "cf-connecting-ip",
        "x-request-id",
    ];

    request
        .headers
        .iter()
        .filter_map(|(key, value)| {
            ALLOWED_HEADERS
                .iter()
                .any(|candidate| key.eq_ignore_ascii_case(candidate))
                .then(|| (key.clone(), summarize_header_value(key, value)))
        })
        .collect()
}

fn summarize_header_value(name: &str, value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if name.eq_ignore_ascii_case("cookie") || name.eq_ignore_ascii_case("authorization") {
        return "[redacted]".to_string();
    }

    let normalized = trimmed.replace('\n', " ").replace('\r', " ");
    if normalized.len() <= 160 {
        normalized
    } else {
        format!("{}...", &normalized[..160])
    }
}
