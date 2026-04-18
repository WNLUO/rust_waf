use super::*;

impl WafEngine {
    #[cfg(feature = "api")]
    pub(super) async fn run_ai_auto_audit(&self, now: i64) -> Result<()> {
        let config = self.context.config_snapshot();
        let ai_config = config.integrations.ai_audit.clone();
        const SHORT_WINDOW_SECS: u32 = 3 * 60;
        const LONG_WINDOW_SECS: u32 = 15 * 60;
        if !ai_config.auto_audit_enabled {
            return Ok(());
        }
        if self.context.sqlite_store.is_none() {
            return Ok(());
        }

        let runtime = self.context.ai_auto_audit_runtime_snapshot().await;
        if runtime.last_run_at.is_some_and(|last| {
            now.saturating_sub(last) < ai_config.auto_audit_interval_secs as i64
        }) {
            return Ok(());
        }

        let trigger_summary = crate::api::build_ai_audit_summary_for_context(
            self.context.as_ref(),
            Some(SHORT_WINDOW_SECS),
            Some(ai_config.event_sample_limit.min(80)),
            Some(ai_config.recent_event_limit.min(8)),
        )
        .await?;
        if let Some(pause_reason) = ai_auto_audit_pause_reason(&trigger_summary) {
            info!("AI auto audit paused: {}", pause_reason);
            return Ok(());
        }

        let signature = ai_auto_audit_signature(&trigger_summary);
        self.context
            .note_ai_auto_audit_observed_signature(Some(signature.clone()))
            .await;

        let trigger_reasons = ai_auto_audit_trigger_reasons(
            &ai_config,
            &trigger_summary,
            runtime.last_observed_signature.as_deref(),
            &signature,
        );
        if trigger_reasons.is_empty() {
            return Ok(());
        }
        if runtime.last_run_at.is_some_and(|last| {
            now.saturating_sub(last) < ai_config.auto_audit_cooldown_secs as i64
        }) {
            return Ok(());
        }
        if runtime
            .last_trigger_signature
            .as_deref()
            .is_some_and(|previous| previous == signature)
        {
            return Ok(());
        }

        let reason = trigger_reasons.join("+");
        self.context
            .note_ai_auto_audit_run_started(signature, reason.clone(), now)
            .await;

        let report = crate::api::run_ai_audit_report_for_context(
            Arc::clone(&self.context),
            crate::api::AiAuditReportQueryParams {
                window_seconds: Some(LONG_WINDOW_SECS),
                sample_limit: Some(ai_config.event_sample_limit.min(120)),
                recent_limit: Some(ai_config.recent_event_limit.min(8)),
                provider: None,
                fallback_to_rules: Some(ai_config.fallback_to_rules),
            },
            ai_config.auto_audit_force_local_rules_under_attack
                && trigger_summary.runtime_pressure_level == "attack",
            Some(reason.clone()),
        )
        .await?;
        self.context
            .note_ai_auto_audit_run_completed(report.report_id, now)
            .await;
        info!(
            "AI auto audit completed: reason={} risk_level={} provider={}",
            reason, report.risk_level, report.provider_used
        );
        Ok(())
    }
}

#[cfg(feature = "api")]
fn ai_auto_audit_signature(summary: &crate::api::AiAuditSummaryResponse) -> String {
    let top_route = summary
        .top_routes
        .first()
        .map(|item| item.key.as_str())
        .unwrap_or("-");
    let top_source = summary
        .top_source_ips
        .first()
        .map(|item| item.key.as_str())
        .unwrap_or("-");
    let top_signal = summary
        .primary_signals
        .first()
        .map(|item| item.key.as_str())
        .unwrap_or("-");
    format!(
        "{}|{}|{}|{}|{}",
        summary.runtime_pressure_level, top_route, top_source, top_signal, summary.total_events
    )
}

#[cfg(feature = "api")]
fn ai_auto_audit_trigger_reasons(
    config: &crate::config::AiAuditConfig,
    summary: &crate::api::AiAuditSummaryResponse,
    previous_signature: Option<&str>,
    current_signature: &str,
) -> Vec<String> {
    let mut trigger_reasons = Vec::new();
    if config.auto_audit_on_attack_mode && summary.runtime_pressure_level == "attack" {
        trigger_reasons.push("attack_mode".to_string());
    } else if config.auto_audit_on_pressure_high
        && matches!(summary.runtime_pressure_level.as_str(), "high" | "attack")
    {
        trigger_reasons.push("pressure_high".to_string());
    }
    if config.auto_audit_on_hotspot_shift
        && previous_signature.is_some_and(|previous| previous != current_signature)
        && summary.sampled_events > 0
    {
        trigger_reasons.push("hotspot_shift".to_string());
    }
    if summary.data_quality.analysis_confidence == "medium"
        && (summary.data_quality.detail_slimming_active
            || summary.data_quality.sqlite_queue_usage_percent >= 75.0)
    {
        trigger_reasons.push("data_quality_degraded".to_string());
    }
    trigger_reasons
}

#[cfg(feature = "api")]
fn ai_auto_audit_pause_reason(summary: &crate::api::AiAuditSummaryResponse) -> Option<String> {
    if summary.data_quality.analysis_confidence != "low" {
        return None;
    }
    if summary.data_quality.dropped_security_events > 0 {
        return Some(format!(
            "data quality degraded: dropped_security_events={}",
            summary.data_quality.dropped_security_events
        ));
    }
    if summary.data_quality.persistence_coverage_ratio < 0.95 {
        return Some(format!(
            "data quality degraded: persistence_coverage_ratio={:.2}",
            summary.data_quality.persistence_coverage_ratio
        ));
    }
    if summary.data_quality.detail_slimming_active {
        return Some("data quality degraded: detail slimming active".to_string());
    }
    None
}

#[cfg(all(test, feature = "api"))]
mod tests {
    use super::*;

    fn sample_summary() -> crate::api::AiAuditSummaryResponse {
        crate::api::AiAuditSummaryResponse {
            generated_at: 1,
            window_seconds: 900,
            sampled_events: 10,
            total_events: 12,
            active_rules: 3,
            runtime_pressure_level: "high".to_string(),
            degraded_reasons: Vec::new(),
            data_quality: crate::api::AiAuditDataQualityResponse::default(),
            current: crate::api::AiAuditCurrentStateResponse::default(),
            counters: crate::api::AiAuditCountersResponse::default(),
            action_breakdown: Vec::new(),
            provider_breakdown: Vec::new(),
            identity_states: Vec::new(),
            primary_signals: vec![crate::api::AiAuditCountItem {
                key: "l7_cc:block".to_string(),
                count: 4,
            }],
            labels: Vec::new(),
            top_source_ips: vec![crate::api::AiAuditCountItem {
                key: "203.0.113.10".to_string(),
                count: 5,
            }],
            top_routes: vec![crate::api::AiAuditCountItem {
                key: "/login".to_string(),
                count: 6,
            }],
            top_hosts: Vec::new(),
            safeline_correlation: crate::api::AiAuditSafeLineCorrelationResponse::default(),
            trend_windows: Vec::new(),
            recent_policy_feedback: Vec::new(),
            recent_events: Vec::new(),
        }
    }

    #[test]
    fn ai_auto_audit_trigger_reasons_cover_pressure_and_hotspot_shift() {
        let config = crate::config::AiAuditConfig {
            auto_audit_enabled: true,
            auto_audit_on_pressure_high: true,
            auto_audit_on_attack_mode: true,
            auto_audit_on_hotspot_shift: true,
            ..crate::config::AiAuditConfig::default()
        };
        let summary = sample_summary();
        let signature = ai_auto_audit_signature(&summary);

        let reasons =
            ai_auto_audit_trigger_reasons(&config, &summary, Some("old|signature"), &signature);

        assert!(reasons.iter().any(|item| item == "pressure_high"));
        assert!(reasons.iter().any(|item| item == "hotspot_shift"));
    }

    #[test]
    fn ai_auto_audit_trigger_reasons_include_data_quality_degraded() {
        let config = crate::config::AiAuditConfig {
            auto_audit_enabled: true,
            auto_audit_on_pressure_high: true,
            auto_audit_on_attack_mode: true,
            auto_audit_on_hotspot_shift: true,
            ..crate::config::AiAuditConfig::default()
        };
        let mut summary = sample_summary();
        summary.data_quality.analysis_confidence = "medium".to_string();
        summary.data_quality.detail_slimming_active = true;
        summary.data_quality.sqlite_queue_usage_percent = 82.0;
        let signature = ai_auto_audit_signature(&summary);

        let reasons =
            ai_auto_audit_trigger_reasons(&config, &summary, Some(&signature), &signature);

        assert!(reasons.iter().any(|item| item == "data_quality_degraded"));
    }

    #[test]
    fn ai_auto_audit_pause_reason_blocks_low_confidence_data_quality() {
        let mut summary = sample_summary();
        summary.data_quality.analysis_confidence = "low".to_string();
        summary.data_quality.dropped_security_events = 3;

        let reason = ai_auto_audit_pause_reason(&summary);

        assert!(reason.is_some());
        assert!(reason.unwrap().contains("dropped_security_events"));
    }
}
