pub(crate) async fn ai_defense_snapshot_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<AiDefenseSnapshotResponse>> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let config = state.context.config_snapshot();
    let snapshot = state
        .context
        .ai_defense_signal_snapshot(now, Some("dashboard_snapshot".to_string()))
        .await
        .map_err(ApiError::internal)?;
    let summary =
        build_ai_audit_summary(state.context.as_ref(), Some(900), Some(120), Some(0)).await?;
    let active_policies = state
        .context
        .active_ai_temp_policies()
        .into_iter()
        .map(|item| ai_temp_policy_response_from_entry(item, &summary))
        .collect();

    Ok(Json(AiDefenseSnapshotResponse {
        generated_at: snapshot.generated_at,
        enabled: config.integrations.ai_audit.auto_defense_enabled,
        auto_apply: config.integrations.ai_audit.auto_defense_auto_apply,
        trigger_reason: snapshot.trigger_reason,
        trigger_pending_secs: snapshot.trigger_pending_secs,
        runtime_pressure: ai_defense_runtime_pressure_response(snapshot.runtime_pressure),
        l4_pressure: snapshot.l4_pressure.map(ai_defense_l4_pressure_response),
        upstream_health: AiDefenseUpstreamHealthResponse {
            healthy: snapshot.upstream_health.healthy,
            last_error: snapshot.upstream_health.last_error,
        },
        active_temp_policy_count: snapshot.active_temp_policy_count,
        max_active_temp_policy_count: snapshot.max_active_temp_policy_count,
        active_policies,
        route_effects: snapshot
            .route_effects
            .into_iter()
            .map(ai_defense_route_effect_response)
            .collect(),
        policy_effects: snapshot
            .policy_effects
            .into_iter()
            .map(ai_defense_policy_effect_response)
            .collect(),
        identity_summaries: snapshot
            .identity_summaries
            .into_iter()
            .map(ai_defense_identity_response)
            .collect(),
        route_profiles: snapshot
            .route_profiles
            .into_iter()
            .map(ai_defense_route_profile_signal_response)
            .collect(),
        local_recommendations: snapshot
            .local_recommendations
            .into_iter()
            .map(local_defense_recommendation_response)
            .collect(),
        server_public_ips: ServerPublicIpSnapshotResponse {
            ips: snapshot.server_public_ips.ips,
            last_refresh_at: snapshot.server_public_ips.last_refresh_at,
            last_success_at: snapshot.server_public_ips.last_success_at,
            last_error: snapshot.server_public_ips.last_error,
        },
        visitor_intelligence: visitor_intelligence_response(snapshot.visitor_intelligence),
    }))
}

pub(crate) async fn ai_visitor_profiles_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<AiVisitorIntelligenceResponse>> {
    Ok(Json(visitor_intelligence_response(
        state.context.visitor_intelligence_snapshot(50),
    )))
}

pub(crate) async fn local_defense_recommendations_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<LocalDefenseRecommendationsResponse>> {
    let recommendations = state.context.local_defense_recommendations(20);
    Ok(Json(LocalDefenseRecommendationsResponse {
        total: recommendations.len() as u32,
        recommendations: recommendations
            .into_iter()
            .map(local_defense_recommendation_response)
            .collect(),
    }))
}
use super::mappers::{
    ai_defense_identity_response, ai_defense_l4_pressure_response,
    ai_defense_policy_effect_response, ai_defense_route_effect_response,
    ai_defense_route_profile_signal_response, ai_defense_runtime_pressure_response,
    local_defense_recommendation_response, visitor_intelligence_response,
};
use super::*;
