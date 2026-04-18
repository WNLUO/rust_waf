use super::*;

pub(super) async fn apply_ai_temp_policies_from_report(
    store: &crate::storage::SqliteStore,
    report_id: Option<i64>,
    report: &AiAuditReportResponse,
    ai_config: &crate::config::AiAuditConfig,
) -> anyhow::Result<usize> {
    if report.summary.data_quality.analysis_confidence == "low" {
        return Ok(0);
    }
    let now = unix_timestamp();
    let mut applied = 0usize;
    let active_count = store.list_active_ai_temp_policies(now).await?.len() as u32;
    let confidence = match report.risk_level.as_str() {
        "critical" => 95,
        "high" => 85,
        "medium" => 70,
        _ => 55,
    };
    if active_count >= ai_config.max_active_temp_policies {
        return Ok(0);
    }
    for item in &report.suggested_local_rules {
        if !item.auto_apply {
            continue;
        }
        if !ai_audit_action_allowed_for_auto_apply(item.action.as_str()) {
            continue;
        }
        if confidence < ai_config.auto_apply_min_confidence as i64 {
            continue;
        }
        if (active_count + applied as u32) >= ai_config.max_active_temp_policies {
            break;
        }
        let ttl_secs = if item.action == "add_temp_block" {
            item.ttl_secs.max(ai_config.temp_block_ttl_secs)
        } else {
            item.ttl_secs.max(ai_config.temp_policy_ttl_secs)
        };
        store
            .upsert_ai_temp_policy(&crate::storage::AiTempPolicyUpsert {
                source_report_id: report_id,
                policy_key: item.key.clone(),
                title: item.title.clone(),
                policy_type: item.policy_type.clone(),
                layer: item.layer.clone(),
                scope_type: item.scope_type.clone(),
                scope_value: item.scope_value.clone(),
                action: item.action.clone(),
                operator: item.operator.clone(),
                suggested_value: item.suggested_value.clone(),
                rationale: item.rationale.clone(),
                confidence,
                auto_applied: true,
                expires_at: now.saturating_add(ttl_secs as i64),
                effect_stats: Some(crate::storage::AiTempPolicyEffectStats {
                    baseline_l7_friction_percent: Some(
                        report.summary.current.l7_friction_pressure_percent,
                    ),
                    baseline_identity_pressure_percent: Some(
                        report.summary.current.identity_pressure_percent,
                    ),
                    baseline_rust_persistence_percent: Some(
                        report.summary.safeline_correlation.rust_persistence_percent,
                    ),
                    ..crate::storage::AiTempPolicyEffectStats::default()
                }),
            })
            .await?;
        applied += 1;
    }
    Ok(applied)
}

pub(super) fn ai_audit_action_allowed_for_auto_apply(action: &str) -> bool {
    matches!(
        action,
        "increase_delay"
            | "tighten_route_cc"
            | "tighten_host_cc"
            | "raise_identity_risk"
            | "add_behavior_watch"
            | "increase_challenge"
    )
}

pub(super) fn ai_temp_policy_response_from_entry(
    value: crate::storage::AiTempPolicyEntry,
    summary: &AiAuditSummaryResponse,
) -> AiTempPolicyResponse {
    let effect =
        serde_json::from_str::<crate::storage::AiTempPolicyEffectStats>(&value.effect_json)
            .unwrap_or_default();
    let l7_friction_delta = effect
        .baseline_l7_friction_percent
        .map(|value| summary.current.l7_friction_pressure_percent - value);
    let identity_pressure_delta = effect
        .baseline_identity_pressure_percent
        .map(|value| summary.current.identity_pressure_percent - value);
    let rust_persistence_delta = effect
        .baseline_rust_persistence_percent
        .map(|value| summary.safeline_correlation.rust_persistence_percent - value);
    let (action_status, action_reason, governance_hint) = classify_ai_temp_policy_action(
        value.action.as_str(),
        value.hit_count,
        l7_friction_delta,
        identity_pressure_delta,
        rust_persistence_delta,
    );
    let (primary_object, primary_object_hits) = top_effect_object(&effect);

    AiTempPolicyResponse {
        id: value.id,
        created_at: value.created_at,
        updated_at: value.updated_at,
        expires_at: value.expires_at,
        policy_key: value.policy_key,
        title: value.title,
        policy_type: value.policy_type,
        layer: value.layer,
        scope_type: value.scope_type,
        scope_value: value.scope_value,
        action: value.action,
        operator: value.operator,
        suggested_value: value.suggested_value,
        rationale: value.rationale,
        confidence: value.confidence,
        auto_applied: value.auto_applied,
        hit_count: value.hit_count,
        last_hit_at: value.last_hit_at,
        effect: AiTempPolicyEffectResponse {
            baseline_l7_friction_percent: effect.baseline_l7_friction_percent,
            baseline_identity_pressure_percent: effect.baseline_identity_pressure_percent,
            baseline_rust_persistence_percent: effect.baseline_rust_persistence_percent,
            auto_extensions: effect.auto_extensions,
            auto_revoked: effect.auto_revoked,
            auto_revoke_reason: effect.auto_revoke_reason,
            last_effectiveness_check_at: effect.last_effectiveness_check_at,
            total_hits: effect.total_hits,
            first_hit_at: effect.first_hit_at,
            last_hit_at: effect.last_hit_at,
            last_scope_type: effect.last_scope_type,
            last_scope_value: effect.last_scope_value,
            last_matched_value: effect.last_matched_value,
            last_match_mode: effect.last_match_mode,
            action_hits: effect.action_hits,
            match_modes: effect.match_modes,
            scope_hits: effect.scope_hits,
            matched_value_hits: effect.matched_value_hits,
        },
        effectiveness: AiTempPolicyEffectivenessResponse {
            current_l7_friction_percent: summary.current.l7_friction_pressure_percent,
            current_identity_pressure_percent: summary.current.identity_pressure_percent,
            current_rust_persistence_percent: summary.safeline_correlation.rust_persistence_percent,
            l7_friction_delta,
            identity_pressure_delta,
            rust_persistence_delta,
            action_status,
            action_reason,
            governance_hint,
            primary_object,
            primary_object_hits,
        },
    }
}

fn top_effect_object(effect: &crate::storage::AiTempPolicyEffectStats) -> (Option<String>, i64) {
    effect
        .matched_value_hits
        .iter()
        .max_by(|left, right| left.1.cmp(right.1).then_with(|| right.0.cmp(left.0)))
        .map(|(key, value)| (Some(key.clone()), *value))
        .unwrap_or((effect.last_matched_value.clone(), 0))
}

pub(super) fn ai_audit_policy_feedback_from_entry(
    value: crate::storage::AiTempPolicyEntry,
) -> AiAuditPolicyFeedbackResponse {
    let effect =
        serde_json::from_str::<crate::storage::AiTempPolicyEffectStats>(&value.effect_json)
            .unwrap_or_default();
    let (action_status, action_reason, _) =
        classify_ai_temp_policy_action(value.action.as_str(), value.hit_count, None, None, None);
    let (primary_object, primary_object_hits) = top_effect_object(&effect);
    AiAuditPolicyFeedbackResponse {
        policy_key: value.policy_key,
        title: value.title,
        action: value.action,
        scope_type: value.scope_type,
        scope_value: value.scope_value,
        action_status,
        action_reason,
        primary_object,
        primary_object_hits,
        hit_count: value.hit_count,
        updated_at: value.updated_at,
    }
}

fn classify_ai_temp_policy_action(
    action: &str,
    hit_count: i64,
    l7_friction_delta: Option<f64>,
    identity_pressure_delta: Option<f64>,
    rust_persistence_delta: Option<f64>,
) -> (String, String, String) {
    let l7_improved = l7_friction_delta
        .map(|value| value <= -3.0)
        .unwrap_or(false);
    let identity_improved = identity_pressure_delta
        .map(|value| value <= -1.5)
        .unwrap_or(false);
    let persistence_improved = rust_persistence_delta
        .map(|value| value <= -10.0)
        .unwrap_or(false);

    match action {
        "increase_delay" => {
            if hit_count >= 3 && persistence_improved {
                (
                    "effective".to_string(),
                    "延迟策略已命中且雷池后持续压力明显回落。".to_string(),
                    "可短期续期，继续观察是否仍需升级为更强动作。".to_string(),
                )
            } else if hit_count == 0 {
                (
                    "cold".to_string(),
                    "延迟策略尚未命中，暂时无法说明对热点有真实覆盖。".to_string(),
                    "热身后若仍无命中，可优先清退。".to_string(),
                )
            } else {
                (
                    "watch".to_string(),
                    "延迟策略已有命中，但持续压力回落还不够明显。".to_string(),
                    "继续观察持续压力与命中数，必要时升级 challenge 或 route 收紧。".to_string(),
                )
            }
        }
        "tighten_route_cc" | "tighten_host_cc" | "increase_challenge" => {
            if hit_count >= 2 && l7_improved {
                (
                    "effective".to_string(),
                    "摩擦类策略已命中，并且 L7 摩擦压力相对基线下降。".to_string(),
                    "可有限续期，优先保持热点对象的短期收紧。".to_string(),
                )
            } else if hit_count == 0 {
                (
                    "cold".to_string(),
                    "摩擦类策略尚未命中，说明当前覆盖面可能偏窄。".to_string(),
                    "热身后若无命中，可考虑撤销或改用更合适的匹配范围。".to_string(),
                )
            } else {
                (
                    "watch".to_string(),
                    "摩擦类策略已有命中，但 L7 压力改善仍不充分。".to_string(),
                    "继续观察，若压力不降可升级为短时 block 或更严阈值。".to_string(),
                )
            }
        }
        "raise_identity_risk" | "add_behavior_watch" => {
            if hit_count >= 2 && identity_improved {
                (
                    "effective".to_string(),
                    "行为/身份策略已命中，并且身份压力相对基线回落。".to_string(),
                    "可短期保留，继续观察是否还有未解析身份回流。".to_string(),
                )
            } else if hit_count == 0 {
                (
                    "cold".to_string(),
                    "行为/身份策略尚未命中，当前无法证明其作用范围有效。".to_string(),
                    "若热身后仍无命中，应优先清退。".to_string(),
                )
            } else {
                (
                    "watch".to_string(),
                    "行为/身份策略已有命中，但身份压力改善不明显。".to_string(),
                    "继续观察，必要时结合真实 IP 链路或热点对象再收紧。".to_string(),
                )
            }
        }
        "add_temp_block" => {
            if hit_count >= 1 && persistence_improved {
                (
                    "effective".to_string(),
                    "临时封禁已命中，且雷池后持续压力明显下降。".to_string(),
                    "仅建议短时续期，避免过度阻断。".to_string(),
                )
            } else if hit_count == 0 {
                (
                    "cold".to_string(),
                    "临时封禁尚未命中，当前无法证明封禁对象仍然活跃。".to_string(),
                    "热身后若仍无命中，可自动退出。".to_string(),
                )
            } else {
                (
                    "watch".to_string(),
                    "临时封禁已有命中，但持续压力仍未明显下降。".to_string(),
                    "继续观察，必要时扩大匹配范围或转为 route 级策略。".to_string(),
                )
            }
        }
        _ => (
            "watch".to_string(),
            "当前策略动作缺少专项评估模型，先按通用观察处理。".to_string(),
            "建议结合命中和压力变化手动复核。".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_audit_auto_apply_whitelist_excludes_temp_block() {
        assert!(ai_audit_action_allowed_for_auto_apply("increase_delay"));
        assert!(ai_audit_action_allowed_for_auto_apply("tighten_route_cc"));
        assert!(!ai_audit_action_allowed_for_auto_apply("add_temp_block"));
        assert!(!ai_audit_action_allowed_for_auto_apply("watch_only"));
    }
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
