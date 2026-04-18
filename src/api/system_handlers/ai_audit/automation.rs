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

pub(crate) async fn ai_automation_overview_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<AiAutomationOverviewResponse>> {
    let config = state.context.config_snapshot();
    let ai_config = &config.integrations.ai_audit;
    let runtime = state.context.ai_auto_audit_runtime_snapshot().await;
    let active_policies = state.context.active_ai_temp_policies();
    let status = AiAutoAuditStatusResponse {
        enabled: ai_config.auto_audit_enabled,
        interval_secs: ai_config.auto_audit_interval_secs,
        cooldown_secs: ai_config.auto_audit_cooldown_secs,
        on_pressure_high: ai_config.auto_audit_on_pressure_high,
        on_attack_mode: ai_config.auto_audit_on_attack_mode,
        on_hotspot_shift: ai_config.auto_audit_on_hotspot_shift,
        force_local_rules_under_attack: ai_config.auto_audit_force_local_rules_under_attack,
        last_run_at: runtime.last_run_at,
        last_completed_at: runtime.last_completed_at,
        last_trigger_signature: runtime.last_trigger_signature,
        last_observed_signature: runtime.last_observed_signature,
        last_trigger_reason: runtime.last_trigger_reason,
        last_report_id: runtime.last_report_id,
    };
    let provider = match ai_config.provider {
        crate::config::AiAuditProviderConfig::LocalRules => "local_rules",
        crate::config::AiAuditProviderConfig::StubModel => "stub_model",
        crate::config::AiAuditProviderConfig::OpenAiCompatible => "openai_compatible",
        crate::config::AiAuditProviderConfig::XiaomiMimo => "xiaomi_mimo",
    }
    .to_string();

    let mut summary = AiAuditSummaryResponse::default();
    let mut available = false;
    let mut unavailable_reason = None;

    if state.context.sqlite_store.is_some() {
        match build_ai_audit_summary(state.context.as_ref(), Some(900), Some(120), Some(0)).await {
            Ok(value) => {
                summary = value;
                available = true;
            }
            Err(err) => {
                log::warn!("Failed to build AI automation overview summary: {:?}", err);
                unavailable_reason = Some("AI 摘要暂时不可用".to_string());
                summary.generated_at = unix_timestamp();
                summary
                    .degraded_reasons
                    .push("management_ai_overview_summary_unavailable".to_string());
            }
        }
    } else {
        unavailable_reason = Some("SQLite 未连接，AI 自动化缺少事件样本".to_string());
        summary.generated_at = unix_timestamp();
        summary
            .degraded_reasons
            .push("management_ai_overview_sqlite_unavailable".to_string());
    }

    Ok(Json(AiAutomationOverviewResponse {
        generated_at: summary.generated_at,
        available,
        unavailable_reason,
        provider,
        fallback_to_rules: ai_config.fallback_to_rules,
        auto_apply_temp_policies: ai_config.auto_apply_temp_policies,
        active_policy_count: active_policies.len() as u32,
        max_active_policy_count: ai_config.max_active_temp_policies,
        status,
        window_seconds: summary.window_seconds,
        sampled_events: summary.sampled_events,
        total_events: summary.total_events,
        active_rules: summary.active_rules,
        runtime_pressure_level: summary.runtime_pressure_level,
        degraded_reasons: summary.degraded_reasons,
        data_quality: summary.data_quality,
        current: summary.current,
        counters: summary.counters,
        trend_windows: summary.trend_windows.into_iter().take(4).collect(),
        top_signals: summary.primary_signals.into_iter().take(4).collect(),
        top_routes: summary.top_routes.into_iter().take(4).collect(),
        recent_policy_feedback: active_policies
            .into_iter()
            .take(3)
            .map(ai_audit_policy_feedback_from_entry)
            .collect(),
    }))
}
use super::*;
