use super::*;
use std::collections::BTreeMap;

pub(super) async fn health_handler(State(state): State<ApiState>) -> Json<HealthResponse> {
    let upstream = state.context.upstream_health_snapshot();
    Json(HealthResponse {
        status: if upstream.healthy {
            "healthy".to_string()
        } else {
            "degraded".to_string()
        },
        version: env!("CARGO_PKG_VERSION").to_string(),
        upstream_healthy: upstream.healthy,
        upstream_last_check_at: upstream.last_check_at,
        upstream_last_error: upstream.last_error,
    })
}

pub(super) async fn metrics_handler(State(state): State<ApiState>) -> Json<MetricsResponse> {
    let metrics = state.context.metrics_snapshot();
    let storage_summary = if let Some(store) = state.context.sqlite_store.as_ref() {
        match store.metrics_summary().await {
            Ok(summary) => Some(summary),
            Err(err) => {
                log::warn!("Failed to query SQLite metrics summary: {}", err);
                None
            }
        }
    } else {
        None
    };

    Json(build_metrics_response(
        metrics,
        state.context.active_rule_count(),
        storage_summary,
        state
            .context
            .l4_inspector()
            .map(|inspector| inspector.get_statistics().behavior.overview),
    ))
}

pub(super) async fn traffic_map_handler(
    State(state): State<ApiState>,
    Query(params): Query<TrafficMapQueryParams>,
) -> Json<TrafficMapResponse> {
    let snapshot = state
        .context
        .traffic_map_snapshot(params.window_seconds.unwrap_or(60))
        .await;

    Json(TrafficMapResponse {
        scope: snapshot.scope,
        window_seconds: snapshot.window_seconds,
        generated_at: snapshot.generated_at,
        origin_node: TrafficMapNodeResponse {
            id: snapshot.origin_node.id,
            name: snapshot.origin_node.name,
            region: snapshot.origin_node.region,
            role: snapshot.origin_node.role,
            lat: snapshot.origin_node.lat,
            lng: snapshot.origin_node.lng,
            traffic_weight: snapshot.origin_node.traffic_weight,
            request_count: snapshot.origin_node.request_count,
            blocked_count: snapshot.origin_node.blocked_count,
            bandwidth_mbps: snapshot.origin_node.bandwidth_mbps,
            last_seen_at: snapshot.origin_node.last_seen_at,
        },
        nodes: snapshot
            .nodes
            .into_iter()
            .map(|item| TrafficMapNodeResponse {
                id: item.id,
                name: item.name,
                region: item.region,
                role: item.role,
                lat: item.lat,
                lng: item.lng,
                traffic_weight: item.traffic_weight,
                request_count: item.request_count,
                blocked_count: item.blocked_count,
                bandwidth_mbps: item.bandwidth_mbps,
                last_seen_at: item.last_seen_at,
            })
            .collect(),
        flows: snapshot
            .flows
            .into_iter()
            .map(|item| TrafficMapFlowResponse {
                id: item.id,
                node_id: item.node_id,
                direction: item.direction,
                decision: item.decision,
                request_count: item.request_count,
                bytes: item.bytes,
                bandwidth_mbps: item.bandwidth_mbps,
                average_latency_ms: item.average_latency_ms,
                last_seen_at: item.last_seen_at,
            })
            .collect(),
        active_node_count: snapshot.active_node_count,
        peak_bandwidth_mbps: snapshot.peak_bandwidth_mbps,
        allowed_flow_count: snapshot.allowed_flow_count,
        blocked_flow_count: snapshot.blocked_flow_count,
        live_traffic_score: snapshot.live_traffic_score,
    })
}

pub(super) async fn ai_audit_summary_handler(
    State(state): State<ApiState>,
    Query(params): Query<AiAuditSummaryQueryParams>,
) -> ApiResult<Json<AiAuditSummaryResponse>> {
    let store = sqlite_store(&state)?;
    let now = unix_timestamp();
    let window_seconds = params.window_seconds.unwrap_or(3600).clamp(60, 24 * 3600);
    let sample_limit = params.sample_limit.unwrap_or(200).clamp(20, 1000);
    let recent_limit = params.recent_limit.unwrap_or(20).clamp(5, 100);
    let created_from = now.saturating_sub(window_seconds as i64);

    let result = store
        .list_security_events(&crate::storage::SecurityEventQuery {
            limit: sample_limit,
            offset: 0,
            created_from: Some(created_from),
            sort_by: crate::storage::EventSortField::CreatedAt,
            sort_direction: crate::storage::SortDirection::Desc,
            ..crate::storage::SecurityEventQuery::default()
        })
        .await
        .map_err(ApiError::internal)?;

    let metrics = state.context.metrics_snapshot().unwrap_or_default();
    let auto = state.context.auto_tuning_snapshot();
    let adaptive = state.context.adaptive_protection_snapshot();

    let mut identity_states = BTreeMap::new();
    let mut primary_signals = BTreeMap::new();
    let mut labels = BTreeMap::new();
    let mut top_source_ips = BTreeMap::new();
    let mut top_routes = BTreeMap::new();
    let mut top_hosts = BTreeMap::new();

    let sampled_events = result.items.len() as u32;
    let mut recent_events = Vec::new();

    for event in result.items.into_iter().map(SecurityEventResponse::from) {
        if recent_events.len() < recent_limit as usize {
            recent_events.push(AiAuditEventSampleResponse::from(event.clone()));
        }
        increment_map(&mut top_source_ips, &event.source_ip);
        if let Some(uri) = event.uri.as_deref() {
            increment_map(&mut top_routes, uri);
        }
        if let Some(host) = event.provider_site_domain.as_deref() {
            increment_map(&mut top_hosts, host);
        }
        if let Some(summary) = event.decision_summary.as_ref() {
            if let Some(identity_state) = summary.identity_state.as_deref() {
                increment_map(&mut identity_states, identity_state);
            }
            increment_map(&mut primary_signals, &summary.primary_signal);
            for label in &summary.labels {
                increment_map(&mut labels, label);
            }
        }
    }

    Ok(Json(AiAuditSummaryResponse {
        generated_at: now,
        window_seconds,
        sampled_events,
        total_events: result.total,
        active_rules: state.context.active_rule_count(),
        current: AiAuditCurrentStateResponse {
            adaptive_system_pressure: adaptive.system_pressure,
            adaptive_reasons: adaptive.reasons,
            l4_overload_level: metrics_l4_overload_level(&metrics),
            auto_tuning_controller_state: auto.controller_state,
            auto_tuning_last_adjust_reason: auto.last_adjust_reason,
            auto_tuning_last_adjust_diff: auto.last_adjust_diff,
            identity_pressure_percent: auto.last_observed_identity_resolution_pressure_percent,
            l7_friction_pressure_percent: auto.last_observed_l7_friction_pressure_percent,
            slow_attack_pressure_percent: auto.last_observed_slow_attack_pressure_percent,
        },
        counters: AiAuditCountersResponse {
            proxied_requests: metrics.proxied_requests,
            blocked_packets: metrics.blocked_packets,
            blocked_l4: metrics.blocked_l4,
            blocked_l7: metrics.blocked_l7,
            l7_cc_challenges: metrics.l7_cc_challenges,
            l7_cc_blocks: metrics.l7_cc_blocks,
            l7_cc_delays: metrics.l7_cc_delays,
            l7_behavior_challenges: metrics.l7_behavior_challenges,
            l7_behavior_blocks: metrics.l7_behavior_blocks,
            l7_behavior_delays: metrics.l7_behavior_delays,
            trusted_proxy_permit_drops: metrics.trusted_proxy_permit_drops,
            trusted_proxy_l4_degrade_actions: metrics.trusted_proxy_l4_degrade_actions,
            slow_attack_hits: metrics.slow_attack_idle_timeouts
                + metrics.slow_attack_header_timeouts
                + metrics.slow_attack_body_timeouts
                + metrics.slow_attack_tls_handshake_hits
                + metrics.slow_attack_blocks,
            average_proxy_latency_micros: metrics.average_proxy_latency_micros,
        },
        identity_states: top_count_items(identity_states, 8),
        primary_signals: top_count_items(primary_signals, 8),
        labels: top_count_items(labels, 12),
        top_source_ips: top_count_items(top_source_ips, 8),
        top_routes: top_count_items(top_routes, 8),
        top_hosts: top_count_items(top_hosts, 8),
        recent_events,
    }))
}

fn increment_map(map: &mut BTreeMap<String, u64>, key: &str) {
    *map.entry(key.to_string()).or_insert(0) += 1;
}

fn top_count_items(map: BTreeMap<String, u64>, limit: usize) -> Vec<AiAuditCountItem> {
    let mut items = map
        .into_iter()
        .map(|(key, count)| AiAuditCountItem { key, count })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| right.count.cmp(&left.count).then(left.key.cmp(&right.key)));
    items.truncate(limit);
    items
}

fn metrics_l4_overload_level(metrics: &crate::metrics::MetricsSnapshot) -> String {
    if metrics.trusted_proxy_l4_degrade_actions > 0 || metrics.l4_bucket_budget_rejections > 0 {
        "high".to_string()
    } else {
        "normal".to_string()
    }
}
