use super::*;

pub(crate) async fn ai_audit_summary_handler(
    State(state): State<ApiState>,
    Query(params): Query<AiAuditSummaryQueryParams>,
) -> ApiResult<Json<AiAuditSummaryResponse>> {
    Ok(Json(
        build_ai_audit_summary(
            state.context.as_ref(),
            params.window_seconds,
            params.sample_limit,
            params.recent_limit,
        )
        .await?,
    ))
}

pub(crate) async fn ai_audit_report_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<AiAuditReportResponse>> {
    let store = sqlite_store(&state)?;
    let result = store
        .list_ai_audit_reports(&crate::storage::AiAuditReportQuery {
            limit: 1,
            offset: 0,
            feedback_status: None,
        })
        .await
        .map_err(ApiError::internal)?;
    let Some(entry) = result.items.into_iter().next() else {
        return Err(ApiError::not_found(
            "暂无 AI 审计历史，请先执行一次 AI 审计",
        ));
    };
    let report = crate::api::ai_audit::history_item_from_entry(entry)
        .map_err(ApiError::internal)?
        .report;
    Ok(Json(report))
}

pub(crate) async fn ai_auto_audit_status_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<AiAutoAuditStatusResponse>> {
    let config = state.context.config_snapshot();
    let runtime = state.context.ai_auto_audit_runtime_snapshot().await;
    Ok(Json(AiAutoAuditStatusResponse {
        enabled: config.integrations.ai_audit.auto_audit_enabled,
        interval_secs: config.integrations.ai_audit.auto_audit_interval_secs,
        cooldown_secs: config.integrations.ai_audit.auto_audit_cooldown_secs,
        on_pressure_high: config.integrations.ai_audit.auto_audit_on_pressure_high,
        on_attack_mode: config.integrations.ai_audit.auto_audit_on_attack_mode,
        on_hotspot_shift: config.integrations.ai_audit.auto_audit_on_hotspot_shift,
        force_local_rules_under_attack: config
            .integrations
            .ai_audit
            .auto_audit_force_local_rules_under_attack,
        last_run_at: runtime.last_run_at,
        last_completed_at: runtime.last_completed_at,
        last_trigger_signature: runtime.last_trigger_signature,
        last_observed_signature: runtime.last_observed_signature,
        last_trigger_reason: runtime.last_trigger_reason,
        last_report_id: runtime.last_report_id,
    }))
}

pub(crate) async fn run_ai_audit_report_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<AiAuditRunRequest>,
) -> ApiResult<Json<AiAuditReportResponse>> {
    let runtime_policy = management_runtime_policy(state.context.as_ref());
    let params = AiAuditReportQueryParams {
        window_seconds: payload.window_seconds,
        sample_limit: payload.sample_limit,
        recent_limit: payload.recent_limit,
        provider: payload.provider,
        fallback_to_rules: payload.fallback_to_rules,
    };
    Ok(Json(
        run_ai_audit_report_for_context(
            Arc::clone(&state.context),
            params,
            runtime_policy.force_local_rules,
            None,
        )
        .await
        .map_err(ApiError::internal)?,
    ))
}

pub(crate) async fn run_ai_audit_report_for_context(
    context: Arc<WafContext>,
    params: AiAuditReportQueryParams,
    force_local_rules: bool,
    trigger_reason: Option<String>,
) -> anyhow::Result<AiAuditReportResponse> {
    let config = context.config_snapshot();
    let mut execution = crate::api::ai_audit::resolve_report_execution(&config, &params);
    if force_local_rules && execution.provider != crate::api::ai_audit::AiAuditProvider::LocalRules
    {
        execution.provider = crate::api::ai_audit::AiAuditProvider::LocalRules;
        execution
            .execution_notes
            .push("runtime pressure forced ai audit into local_rules mode".to_string());
    }
    if let Some(reason) = trigger_reason {
        execution
            .execution_notes
            .push(format!("auto audit trigger reason: {}", reason));
    }
    let summary_query = crate::api::ai_audit::summary_query_from_report(&params);
    let summary = build_ai_audit_summary(
        context.as_ref(),
        summary_query.window_seconds,
        summary_query.sample_limit,
        summary_query.recent_limit,
    )
    .await
    .map_err(|err| anyhow::anyhow!("build ai audit summary failed: {:?}", err))?;
    let mut report =
        crate::api::ai_audit::execute_report(execution, summary, build_ai_audit_report)
            .await
            .map_err(|err| anyhow::anyhow!("execute ai audit report failed: {:?}", err))?;
    if force_local_rules {
        report
            .degraded_reasons
            .push("management_ai_audit_forced_local_rules_under_runtime_pressure".to_string());
    }
    if let Some(store) = context.sqlite_store.as_ref() {
        let persist_result = match serde_json::to_string(&report) {
            Ok(report_json) => store
                .create_ai_audit_report(
                    report.generated_at,
                    &report.provider_used,
                    report.fallback_used,
                    &report.risk_level,
                    &report.headline,
                    &report_json,
                )
                .await
                .map_err(anyhow::Error::from),
            Err(err) => Err(anyhow::Error::from(err)),
        };
        match persist_result {
            Ok(id) => report.report_id = Some(id),
            Err(err) => {
                log::warn!("Failed to persist AI audit report: {:?}", err);
                report
                    .execution_notes
                    .push("failed to persist ai audit report snapshot".to_string());
            }
        }
        if config.integrations.ai_audit.auto_apply_temp_policies {
            match apply_ai_temp_policies_from_report(
                store,
                report.report_id,
                &report,
                &config.integrations.ai_audit,
            )
            .await
            {
                Ok(applied) => {
                    if applied > 0 {
                        report.execution_notes.push(format!(
                            "auto applied {} temporary cc/behavior policies",
                            applied
                        ));
                    }
                }
                Err(err) => {
                    log::warn!("Failed to auto-apply AI temp policies: {:?}", err);
                    report
                        .execution_notes
                        .push("failed to auto apply ai temporary policies".to_string());
                }
            }
            let _ = context.refresh_ai_temp_policies().await;
        }
    }
    Ok(report)
}

pub(crate) async fn list_ai_audit_reports_handler(
    State(state): State<ApiState>,
    Query(params): Query<AiAuditReportsQueryParams>,
) -> ApiResult<Json<AiAuditReportsResponse>> {
    let store = sqlite_store(&state)?;
    let result = store
        .list_ai_audit_reports(&crate::storage::AiAuditReportQuery {
            limit: params.limit.unwrap_or(20),
            offset: params.offset.unwrap_or(0),
            feedback_status: params.feedback_status,
        })
        .await
        .map_err(ApiError::internal)?;

    let reports = result
        .items
        .into_iter()
        .map(crate::api::ai_audit::history_item_from_entry)
        .collect::<Result<Vec<_>, _>>()
        .map_err(ApiError::internal)?;

    Ok(Json(AiAuditReportsResponse {
        total: result.total,
        limit: result.limit,
        offset: result.offset,
        reports,
    }))
}

pub(crate) async fn list_ai_temp_policies_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<AiTempPoliciesResponse>> {
    let items = state.context.active_ai_temp_policies();
    let summary =
        build_ai_audit_summary(state.context.as_ref(), Some(900), Some(120), Some(0)).await?;
    Ok(Json(AiTempPoliciesResponse {
        total: items.len() as u32,
        policies: items
            .into_iter()
            .map(|item| ai_temp_policy_response_from_entry(item, &summary))
            .collect(),
    }))
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

fn local_defense_recommendation_response(
    item: crate::core::LocalDefenseRecommendation,
) -> LocalDefenseRecommendationResponse {
    let title = format!("Tighten route CC for {}", item.route);
    LocalDefenseRecommendationResponse {
        key: item.key.clone(),
        title: title.clone(),
        site_id: item.site_id.clone(),
        route: item.route.clone(),
        defense_depth: item.defense_depth.clone(),
        soft_events: item.soft_events,
        hard_events: item.hard_events,
        total_events: item.total_events,
        confidence: item.confidence,
        suggested_rule: AiAuditSuggestedRuleResponse {
            key: item.key,
            title,
            policy_type: "tighten_route_cc".to_string(),
            layer: "L7".to_string(),
            scope_type: "route".to_string(),
            scope_value: item.route,
            target: format!("site:{}", item.site_id),
            action: item.action,
            operator: "exact".to_string(),
            suggested_value: item.suggested_value,
            ttl_secs: item.ttl_secs,
            auto_apply: false,
            rationale: item.rationale,
        },
    }
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

pub(crate) async fn delete_ai_temp_policy_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let deleted = store
        .delete_ai_temp_policy(id)
        .await
        .map_err(ApiError::internal)?;
    if !deleted {
        return Err(ApiError::not_found("未找到对应的 AI 临时策略"));
    }
    state
        .context
        .refresh_ai_temp_policies()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(WriteStatusResponse {
        success: true,
        message: "AI 临时策略已撤销".to_string(),
    }))
}

pub(crate) async fn update_ai_audit_report_feedback_handler(
    State(state): State<ApiState>,
    Path(id): Path<i64>,
    ExtractJson(payload): ExtractJson<AiAuditFeedbackUpdateRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let feedback_status = payload
        .feedback_status
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(status) = feedback_status {
        let normalized = status.to_ascii_lowercase();
        if !matches!(
            normalized.as_str(),
            "confirmed" | "false_positive" | "follow_up"
        ) {
            return Err(ApiError::bad_request(
                "feedback_status 仅支持 confirmed / false_positive / follow_up",
            ));
        }
    }
    let updated = store
        .update_ai_audit_report_feedback(
            id,
            feedback_status,
            payload
                .feedback_notes
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty()),
        )
        .await
        .map_err(ApiError::internal)?;
    if !updated {
        return Err(ApiError::not_found("未找到对应的 AI 审计报告"));
    }

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "AI 审计反馈已更新".to_string(),
    }))
}

mod report;
mod summary;
mod temp_policies;

use report::build_ai_audit_report;
use summary::build_ai_audit_summary;
use temp_policies::{
    ai_audit_policy_feedback_from_entry, ai_temp_policy_response_from_entry,
    apply_ai_temp_policies_from_report,
};

pub(crate) use summary::build_ai_audit_summary_for_context;
