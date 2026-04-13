use super::*;

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
