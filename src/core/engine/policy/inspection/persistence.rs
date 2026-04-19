use super::super::*;
use super::identity_details::build_request_identity_details;

pub(crate) fn persist_l4_inspection_event(
    context: &WafContext,
    packet: &PacketInfo,
    result: &InspectionResult,
) {
    if should_skip_persisting_result_event(context, result, None) {
        return;
    }
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    context.adaptive_enqueue_security_event(
        store.as_ref(),
        SecurityEventRecord::now(
            "L4",
            result.event_action(),
            result.reason.clone(),
            packet.source_ip.to_string(),
            packet.dest_ip.to_string(),
            packet.source_port,
            packet.dest_port,
            format!("{:?}", packet.protocol),
        ),
        "resource_sentinel_l4",
    );

    if result.persist_blocked_ip {
        let blocked_at = unix_timestamp();
        if context.is_server_public_ip(packet.source_ip) {
            return;
        }
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
    context.note_site_defense_signal(request, result);
    if should_skip_persisting_result_event(context, result, Some(request)) {
        return;
    }
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

    if should_aggregate_runtime_event(context, request, result) {
        context
            .resource_sentinel
            .note_security_event_aggregated(&event);
        store.enqueue_security_event_aggregated(event, "runtime_budget");
    } else {
        event.details_json = build_request_identity_details(context, request, packet, Some(result));
        context.adaptive_enqueue_security_event(store.as_ref(), event, "resource_sentinel_http");
    }

    if result.persist_blocked_ip {
        let blocked_at = unix_timestamp();
        let ip = request
            .client_ip
            .clone()
            .unwrap_or_else(|| packet.source_ip.to_string());
        if context.is_server_public_ip_str(&ip) {
            return;
        }
        store.enqueue_blocked_ip(BlockedIpRecord::new(
            ip,
            result.reason.clone(),
            blocked_at,
            blocked_at + crate::l7::behavior_guard::AUTO_BLOCK_DURATION_SECS as i64,
        ));
    }
}

fn should_aggregate_runtime_event(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    result: &InspectionResult,
) -> bool {
    let request_aggregate = request
        .get_metadata("runtime.aggregate_events")
        .map(|value| value == "true")
        .unwrap_or(false);
    let request_trim = request
        .get_metadata("runtime.pressure.trim_event_persistence")
        .map(|value| value == "true")
        .unwrap_or(false);
    if !(request_aggregate
        || request_trim
        || context.runtime_pressure_snapshot().trim_event_persistence)
    {
        return false;
    }

    matches!(
        result.action,
        InspectionAction::Alert
            | InspectionAction::Respond
            | InspectionAction::Block
            | InspectionAction::Drop
    )
}

pub(crate) fn persist_http_identity_debug_event(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
) {
    let _ = (context, packet, request);
}

pub(crate) fn persist_upstream_http2_debug_event(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    stage: &str,
    details: serde_json::Value,
) {
    let _ = (context, request, stage, details);
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
    if let Some(site) = matched_site {
        context.note_site_hard_defense_signal(&site.id.to_string());
    }
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

    if request
        .get_metadata("runtime.aggregate_events")
        .map(|value| value == "true")
        .unwrap_or(false)
        || context.runtime_pressure_snapshot().trim_event_persistence
    {
        context
            .resource_sentinel
            .note_security_event_aggregated(&event);
        store.enqueue_security_event_aggregated(event, "runtime_budget_safeline");
    } else {
        event.details_json = build_request_identity_details(context, request, packet, None);
        context.adaptive_enqueue_security_event(
            store.as_ref(),
            event,
            "resource_sentinel_safeline",
        );
    }
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
    if context.is_server_public_ip_str(&ip) {
        return;
    }
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

fn should_skip_persisting_result_event(
    context: &WafContext,
    result: &InspectionResult,
    request: Option<&UnifiedHttpRequest>,
) -> bool {
    if result.persist_blocked_ip
        || matches!(
            result.action,
            InspectionAction::Block | InspectionAction::Drop
        )
    {
        return false;
    }

    if matches!(result.action, InspectionAction::Alert) {
        return should_trim_event_persistence(context, request);
    }

    if matches!(result.action, InspectionAction::Respond)
        && should_trim_event_persistence(context, request)
    {
        return request
            .and_then(|request| {
                request
                    .get_metadata("l7.cc.action")
                    .or_else(|| request.get_metadata("l7.behavior.action"))
                    .cloned()
            })
            .map(|action| {
                action == "challenge"
                    || action == "api_friction"
                    || action.starts_with("delay:")
                    || action.starts_with("skip_delay:")
            })
            .unwrap_or(true);
    }

    false
}

fn should_trim_event_persistence(
    context: &WafContext,
    request: Option<&UnifiedHttpRequest>,
) -> bool {
    if request
        .and_then(|request| request.get_metadata("runtime.pressure.trim_event_persistence"))
        .map(|value| value == "true")
        .unwrap_or(false)
    {
        return true;
    }

    context.runtime_pressure_snapshot().trim_event_persistence
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
    if context.is_server_public_ip(ip) {
        return;
    }

    inspector.block_ip(
        &ip,
        &result.reason,
        std::time::Duration::from_secs(
            request
                .get_metadata("ai.temp_block_duration_secs")
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(crate::l7::behavior_guard::AUTO_BLOCK_DURATION_SECS),
        ),
    );
}
