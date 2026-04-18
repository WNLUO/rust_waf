pub(crate) async fn list_ai_route_profiles_handler(
    State(state): State<ApiState>,
    Query(params): Query<AiRouteProfilesQueryParams>,
) -> ApiResult<Json<AiRouteProfilesResponse>> {
    let store = sqlite_store(&state)?;
    let profiles = store
        .list_ai_route_profiles(
            params.site_id.as_deref(),
            params.status.as_deref(),
            params.limit.unwrap_or(100),
        )
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(AiRouteProfilesResponse {
        total: profiles.len() as u32,
        profiles: profiles
            .into_iter()
            .map(ai_route_profile_response)
            .collect(),
    }))
}

pub(crate) async fn upsert_ai_route_profile_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<AiRouteProfileUpsertRequest>,
) -> ApiResult<Json<AiRouteProfileResponse>> {
    let store = sqlite_store(&state)?;
    let upsert = ai_route_profile_upsert_from_request(payload)?;
    store
        .upsert_ai_route_profile(&upsert)
        .await
        .map_err(ApiError::internal)?;
    state
        .context
        .refresh_ai_route_profiles()
        .await
        .map_err(ApiError::internal)?;
    let profiles = store
        .list_ai_route_profiles(Some(&upsert.site_id), None, 500)
        .await
        .map_err(ApiError::internal)?;
    let profile = profiles
        .into_iter()
        .find(|item| {
            item.route_pattern == upsert.route_pattern && item.match_mode == upsert.match_mode
        })
        .ok_or_else(|| ApiError::internal("AI route profile was not found after upsert"))?;
    Ok(Json(ai_route_profile_response(profile)))
}

pub(crate) async fn update_ai_route_profile_status_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    ExtractJson(payload): ExtractJson<AiRouteProfileStatusUpdateRequest>,
) -> ApiResult<Json<AiRouteProfileResponse>> {
    let status = normalize_route_profile_enum(
        payload.status,
        &["candidate", "active", "approved", "rejected", "disabled"],
        "candidate",
    );
    let store = sqlite_store(&state)?;
    let profile = store
        .update_ai_route_profile_status(id, &status, payload.reviewed_at)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("未找到对应的 AI route profile"))?;
    state
        .context
        .refresh_ai_route_profiles()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(ai_route_profile_response(profile)))
}
fn ai_route_profile_upsert_from_request(
    payload: AiRouteProfileUpsertRequest,
) -> ApiResult<crate::storage::AiRouteProfileUpsert> {
    let site_id = payload.site_id.trim().to_string();
    let route_pattern = payload.route_pattern.trim().to_string();
    if site_id.is_empty() {
        return Err(ApiError::bad_request("site_id 不能为空"));
    }
    if route_pattern.is_empty() || !route_pattern.starts_with('/') {
        return Err(ApiError::bad_request("route_pattern 必须以 / 开头"));
    }
    let match_mode = normalize_route_profile_enum(
        payload.match_mode,
        &["exact", "prefix", "wildcard"],
        "exact",
    );
    let status = normalize_route_profile_enum(
        payload.status,
        &["candidate", "active", "approved", "rejected", "disabled"],
        "candidate",
    );
    Ok(crate::storage::AiRouteProfileUpsert {
        site_id,
        route_pattern,
        match_mode,
        route_type: compact_route_profile_value(payload.route_type, "unknown"),
        sensitivity: normalize_route_profile_enum(
            payload.sensitivity,
            &["unknown", "low", "medium", "high", "critical"],
            "unknown",
        ),
        auth_required: normalize_route_profile_enum(
            payload.auth_required,
            &["unknown", "true", "false", "mixed"],
            "unknown",
        ),
        normal_traffic_pattern: compact_route_profile_value(
            payload.normal_traffic_pattern,
            "unknown",
        ),
        recommended_actions: normalize_route_profile_actions(payload.recommended_actions),
        avoid_actions: normalize_route_profile_actions(payload.avoid_actions),
        evidence_json: serde_json::to_string(&payload.evidence)
            .unwrap_or_else(|_| "{}".to_string()),
        confidence: payload.confidence.clamp(0, 100),
        source: compact_route_profile_value(payload.source, "ai_observed"),
        status,
        rationale: payload.rationale.trim().chars().take(1_000).collect(),
        last_observed_at: payload.last_observed_at,
        reviewed_at: payload.reviewed_at,
    })
}

fn ai_route_profile_response(value: crate::storage::AiRouteProfileEntry) -> AiRouteProfileResponse {
    AiRouteProfileResponse {
        id: value.id,
        created_at: value.created_at,
        updated_at: value.updated_at,
        last_observed_at: value.last_observed_at,
        site_id: value.site_id,
        route_pattern: value.route_pattern,
        match_mode: value.match_mode,
        route_type: value.route_type,
        sensitivity: value.sensitivity,
        auth_required: value.auth_required,
        normal_traffic_pattern: value.normal_traffic_pattern,
        recommended_actions: serde_json::from_str(&value.recommended_actions_json)
            .unwrap_or_default(),
        avoid_actions: serde_json::from_str(&value.avoid_actions_json).unwrap_or_default(),
        evidence: serde_json::from_str(&value.evidence_json)
            .unwrap_or_else(|_| serde_json::json!({})),
        confidence: value.confidence,
        source: value.source,
        status: value.status,
        rationale: value.rationale,
        reviewed_at: value.reviewed_at,
    }
}

fn normalize_route_profile_enum(value: String, allowed: &[&str], fallback: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    if allowed.iter().any(|item| item == &normalized) {
        normalized
    } else {
        fallback.to_string()
    }
}

fn compact_route_profile_value(value: String, fallback: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.chars().take(120).collect()
    }
}

fn normalize_route_profile_actions(values: Vec<String>) -> Vec<String> {
    let mut values = values
        .into_iter()
        .map(|item| item.trim().to_ascii_lowercase())
        .filter(|item| {
            matches!(
                item.as_str(),
                "tighten_route_cc"
                    | "tighten_host_cc"
                    | "increase_delay"
                    | "increase_challenge"
                    | "raise_identity_risk"
                    | "add_behavior_watch"
                    | "manual_review_required"
            )
        })
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}
use super::*;
