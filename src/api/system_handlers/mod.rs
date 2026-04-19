use super::*;
use std::collections::BTreeMap;

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
        state.context.resource_sentinel_snapshot(),
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
            country_code: snapshot.origin_node.country_code,
            country_name: snapshot.origin_node.country_name,
            geo_scope: snapshot.origin_node.geo_scope,
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
                country_code: item.country_code,
                country_name: item.country_name,
                geo_scope: item.geo_scope,
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

pub(super) async fn bot_verifier_status_handler(
    State(state): State<ApiState>,
) -> Json<BotVerifierStatusResponse> {
    let snapshot = state.context.bot_verifier_snapshot();
    Json(BotVerifierStatusResponse {
        generated_at: snapshot.generated_at,
        providers: snapshot
            .providers
            .into_iter()
            .map(|provider| BotVerifierProviderStatusResponse {
                provider: provider.provider,
                range_count: provider.range_count,
                last_refresh_at: provider.last_refresh_at,
                last_success_at: provider.last_success_at,
                last_error: provider.last_error,
                status: provider.status,
            })
            .collect(),
    })
}

pub(super) async fn refresh_bot_verifier_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<BotVerifierStatusResponse>> {
    let verifier = state.context.bot_ip_verifier();
    let providers = state.context.config_snapshot().bot_detection.providers;
    verifier
        .refresh_once(&providers, state.context.sqlite_store.as_deref())
        .await;
    Ok(bot_verifier_status_handler(State(state)).await)
}

pub(super) async fn bot_insights_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<BotInsightsResponse>> {
    let store = sqlite_store(&state)?;
    let now = unix_timestamp();
    let window_start = now.saturating_sub(24 * 3600);
    let query = crate::storage::SecurityEventQuery {
        limit: 200,
        offset: 0,
        created_from: Some(window_start),
        sort_by: crate::storage::EventSortField::CreatedAt,
        sort_direction: crate::storage::SortDirection::Desc,
        ..Default::default()
    };
    let mut offset = 0;
    let mut by_trust_class = BTreeMap::new();
    let mut top_bot_names = BTreeMap::new();
    let mut top_mismatch_ips = BTreeMap::new();
    let mut top_routes = BTreeMap::new();
    let mut total_bot_events = 0_u64;

    loop {
        let mut page_query = query.clone();
        page_query.offset = offset;
        let page = store
            .list_security_events(&page_query)
            .await
            .map_err(ApiError::internal)?;
        let fetched = page.items.len();
        for event in page.items {
            let Some(details) = event
                .details_json
                .as_deref()
                .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            else {
                continue;
            };
            let bot_known =
                nested_str_value(&details, &["bot", "known"]) == Some("true".to_string());
            let bot_name = nested_str_value(&details, &["bot", "name"]);
            if !bot_known && bot_name.is_none() {
                continue;
            }
            total_bot_events = total_bot_events.saturating_add(1);
            let trust_class = nested_str_value(&details, &["client_trust", "trust_class"])
                .unwrap_or_else(|| "unknown".to_string());
            increment_count(&mut by_trust_class, trust_class.clone());
            increment_count(
                &mut top_bot_names,
                bot_name.unwrap_or_else(|| "unknown".to_string()),
            );
            if trust_class == "suspect_bot" {
                increment_count(&mut top_mismatch_ips, event.source_ip.clone());
            }
            let route = nested_str_value(&details, &["l7_cc", "route"])
                .or_else(|| nested_str_value(&details, &["l7_behavior", "dominant_route"]))
                .or_else(|| event.uri.clone())
                .unwrap_or_else(|| "-".to_string());
            increment_count(&mut top_routes, route);
        }
        if fetched < 200 || u64::from(offset) + fetched as u64 >= page.total {
            break;
        }
        offset = offset.saturating_add(200);
        if offset >= 5_000 {
            break;
        }
    }

    Ok(Json(BotInsightsResponse {
        generated_at: now,
        window_start,
        total_bot_events,
        by_trust_class: top_count_items(by_trust_class, 12),
        top_bot_names: top_count_items(top_bot_names, 12),
        top_mismatch_ips: top_count_items(top_mismatch_ips, 12),
        top_routes: top_count_items(top_routes, 12),
    }))
}

fn nested_str_value(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(ToOwned::to_owned)
}

fn increment_count(map: &mut BTreeMap<String, u64>, key: String) {
    *map.entry(key).or_insert(0) += 1;
}

fn top_count_items(map: BTreeMap<String, u64>, limit: usize) -> Vec<AiAuditCountItem> {
    let mut items = map
        .into_iter()
        .map(|(key, count)| AiAuditCountItem { key, count })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.key.cmp(&right.key))
    });
    items.truncate(limit);
    items
}

mod ai_audit;

pub(super) use ai_audit::{
    ai_audit_report_handler, ai_audit_summary_handler, ai_auto_audit_status_handler,
    ai_automation_overview_handler, ai_defense_snapshot_handler, ai_visitor_profiles_handler,
    delete_ai_temp_policy_handler, list_ai_audit_reports_handler, list_ai_route_profiles_handler,
    list_ai_temp_policies_handler, local_defense_recommendations_handler,
    run_ai_audit_report_handler, update_ai_audit_report_feedback_handler,
    update_ai_route_profile_status_handler, upsert_ai_route_profile_handler,
};
pub(crate) use ai_audit::{build_ai_audit_summary_for_context, run_ai_audit_report_for_context};
