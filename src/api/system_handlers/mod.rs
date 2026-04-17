use super::*;

#[derive(Debug, Clone)]
pub(super) struct ManagementRuntimePolicy {
    pressure_level: String,
    window_divisor: u32,
    sample_divisor: u32,
    recent_divisor: u32,
    force_local_rules: bool,
}

pub(super) fn management_runtime_policy(context: &WafContext) -> ManagementRuntimePolicy {
    let pressure = context.runtime_pressure_snapshot();
    match pressure.level {
        "attack" => ManagementRuntimePolicy {
            pressure_level: pressure.level.to_string(),
            window_divisor: 4,
            sample_divisor: 4,
            recent_divisor: 4,
            force_local_rules: true,
        },
        "high" => ManagementRuntimePolicy {
            pressure_level: pressure.level.to_string(),
            window_divisor: 2,
            sample_divisor: 2,
            recent_divisor: 2,
            force_local_rules: false,
        },
        _ => ManagementRuntimePolicy {
            pressure_level: pressure.level.to_string(),
            window_divisor: 1,
            sample_divisor: 1,
            recent_divisor: 1,
            force_local_rules: false,
        },
    }
}

pub(super) fn scaled_limit(value: u32, divisor: u32, min: u32) -> u32 {
    if divisor <= 1 {
        value.max(min)
    } else {
        value.saturating_div(divisor).max(min)
    }
}

pub(super) fn management_degraded_reason(enabled: bool, reason: &str) -> Vec<String> {
    enabled.then(|| reason.to_string()).into_iter().collect()
}

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
    let aggregation_insights = state
        .context
        .sqlite_store
        .as_ref()
        .map(|store| store.aggregation_insight_summary());

    Json(build_metrics_response(
        metrics,
        state.context.active_rule_count(),
        storage_summary,
        aggregation_insights,
        state
            .context
            .l4_inspector()
            .map(|inspector| inspector.get_statistics().behavior.overview),
        state.context.runtime_pressure_snapshot(),
    ))
}

pub(super) async fn traffic_map_handler(
    State(state): State<ApiState>,
    Query(params): Query<TrafficMapQueryParams>,
) -> Json<TrafficMapResponse> {
    let policy = management_runtime_policy(state.context.as_ref());
    let requested_window = params.window_seconds.unwrap_or(60);
    let effective_window = scaled_limit(requested_window, policy.window_divisor, 10);
    let snapshot = state.context.traffic_map_snapshot(effective_window).await;

    Json(TrafficMapResponse {
        scope: snapshot.scope,
        window_seconds: snapshot.window_seconds,
        generated_at: snapshot.generated_at,
        runtime_pressure_level: policy.pressure_level,
        degraded_reasons: management_degraded_reason(
            effective_window != requested_window,
            "management_traffic_map_window_reduced_under_runtime_pressure",
        ),
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

mod ai_audit;

pub(super) use ai_audit::{
    ai_audit_report_handler, ai_audit_summary_handler, ai_auto_audit_status_handler,
    ai_defense_snapshot_handler, ai_visitor_profiles_handler, delete_ai_temp_policy_handler,
    list_ai_audit_reports_handler, list_ai_route_profiles_handler, list_ai_temp_policies_handler,
    local_defense_recommendations_handler, run_ai_audit_report_handler,
    update_ai_audit_report_feedback_handler, update_ai_route_profile_status_handler,
    upsert_ai_route_profile_handler,
};
pub(crate) use ai_audit::{build_ai_audit_summary_for_context, run_ai_audit_report_for_context};
