use super::*;
use crate::api::ai_audit::normalization::{
    model_output_needs_chinese_localization, parse_model_output, text_needs_chinese_localization,
};
use crate::api::ai_audit::prompts::{
    build_localization_system_prompt, build_system_prompt, build_user_prompt,
};
use crate::api::ai_audit::types::AiAuditModelOutput;
use crate::api::{
    AiAuditCountItem, AiAuditCountersResponse, AiAuditCurrentStateResponse,
    AiAuditDataQualityResponse, AiAuditEventSampleResponse, AiAuditReportResponse,
    AiAuditSafeLineCorrelationResponse, AiAuditTrendWindowResponse,
};

fn sample_summary() -> AiAuditSummaryResponse {
    AiAuditSummaryResponse {
        generated_at: 1,
        window_seconds: 300,
        sampled_events: 2,
        total_events: 2,
        active_rules: 4,
        runtime_pressure_level: "high".to_string(),
        degraded_reasons: vec![
            "management_ai_audit_sample_reduced_under_runtime_pressure".to_string()
        ],
        data_quality: AiAuditDataQualityResponse {
            persisted_security_events: 20,
            dropped_security_events: 0,
            sqlite_queue_depth: 2,
            sqlite_queue_capacity: 128,
            sqlite_queue_usage_percent: 1.6,
            detail_slimming_active: false,
            sample_coverage_ratio: 1.0,
            persistence_coverage_ratio: 1.0,
            raw_samples_included: false,
            recent_events_count: 0,
            analysis_confidence: "high".to_string(),
        },
        current: AiAuditCurrentStateResponse {
            adaptive_system_pressure: "elevated".to_string(),
            adaptive_reasons: vec!["identity_resolution_pressure".to_string()],
            l4_overload_level: "high".to_string(),
            auto_tuning_controller_state: "adjusted".to_string(),
            auto_tuning_last_adjust_reason: Some("adjust_for_identity".to_string()),
            auto_tuning_last_adjust_diff: vec!["tighten challenge".to_string()],
            identity_pressure_percent: 3.5,
            l7_friction_pressure_percent: 12.0,
            slow_attack_pressure_percent: 0.0,
        },
        counters: AiAuditCountersResponse {
            proxied_requests: 20,
            blocked_packets: 1,
            blocked_l4: 0,
            blocked_l7: 1,
            l7_cc_challenges: 3,
            l7_cc_blocks: 1,
            l7_cc_delays: 2,
            l7_behavior_challenges: 1,
            l7_behavior_blocks: 0,
            l7_behavior_delays: 0,
            l4_bucket_budget_rejections: 0,
            trusted_proxy_permit_drops: 0,
            trusted_proxy_l4_degrade_actions: 1,
            l4_request_budget_softened: 0,
            slow_attack_hits: 0,
            average_proxy_latency_micros: 500,
        },
        action_breakdown: vec![AiAuditCountItem {
            key: "challenge".to_string(),
            count: 1,
        }],
        provider_breakdown: vec![AiAuditCountItem {
            key: "local".to_string(),
            count: 2,
        }],
        identity_states: vec![AiAuditCountItem {
            key: "trusted_cdn_forwarded".to_string(),
            count: 2,
        }],
        primary_signals: vec![AiAuditCountItem {
            key: "l7_cc:challenge".to_string(),
            count: 1,
        }],
        labels: Vec::new(),
        top_source_ips: Vec::new(),
        top_routes: Vec::new(),
        top_hosts: Vec::new(),
        safeline_correlation: AiAuditSafeLineCorrelationResponse::default(),
        trend_windows: vec![AiAuditTrendWindowResponse {
            label: "last_5m".to_string(),
            window_seconds: 300,
            total_events: 2,
            sampled_events: 2,
            blocked_events: 1,
            challenged_events: 1,
            delayed_events: 0,
            action_breakdown: Vec::new(),
            top_source_ips: Vec::new(),
            top_routes: Vec::new(),
            top_hosts: Vec::new(),
        }],
        recent_policy_feedback: Vec::new(),
        recent_events: Vec::<AiAuditEventSampleResponse>::new(),
    }
}

#[test]
fn resolve_report_execution_uses_global_config_defaults() {
    let mut config = Config::default();
    config.integrations.ai_audit = AiAuditConfig {
        enabled: true,
        provider: AiAuditProviderConfig::OpenAiCompatible,
        model: "gpt-audit".to_string(),
        base_url: "https://audit.example.com/v1".to_string(),
        api_key: "secret".to_string(),
        timeout_ms: 9_000,
        fallback_to_rules: false,
        event_sample_limit: 64,
        recent_event_limit: 8,
        include_raw_event_samples: false,
        auto_apply_temp_policies: true,
        temp_policy_ttl_secs: 900,
        temp_block_ttl_secs: 1800,
        auto_apply_min_confidence: 70,
        max_active_temp_policies: 24,
        allow_auto_temp_block: true,
        allow_auto_extend_effective_policies: true,
        auto_revoke_warmup_secs: 300,
        ..AiAuditConfig::default()
    };

    let execution = resolve_report_execution(&config, &AiAuditReportQueryParams::default());

    assert_eq!(execution.provider, AiAuditProvider::OpenAiCompatible);
    assert!(!execution.fallback_to_rules);
    assert_eq!(execution.model.as_deref(), Some("gpt-audit"));
    assert_eq!(
        execution.base_url.as_deref(),
        Some("https://audit.example.com/v1")
    );
    assert_eq!(execution.timeout_ms, 9_000);
}

#[test]
fn resolve_report_execution_supports_xiaomi_mimo() {
    let mut config = Config::default();
    config.integrations.ai_audit = AiAuditConfig {
        enabled: true,
        provider: AiAuditProviderConfig::XiaomiMimo,
        model: "mimo-v2-flash".to_string(),
        base_url: String::new(),
        api_key: "secret".to_string(),
        timeout_ms: 8_000,
        fallback_to_rules: true,
        event_sample_limit: 64,
        recent_event_limit: 8,
        include_raw_event_samples: false,
        auto_apply_temp_policies: true,
        temp_policy_ttl_secs: 900,
        temp_block_ttl_secs: 1800,
        auto_apply_min_confidence: 70,
        max_active_temp_policies: 24,
        allow_auto_temp_block: true,
        allow_auto_extend_effective_policies: true,
        auto_revoke_warmup_secs: 300,
        ..AiAuditConfig::default()
    };

    let execution = resolve_report_execution(&config, &AiAuditReportQueryParams::default());

    assert_eq!(execution.provider, AiAuditProvider::XiaomiMimo);
    assert_eq!(execution.model.as_deref(), Some("mimo-v2-flash"));
    assert_eq!(execution.timeout_ms, 8_000);
}

#[test]
fn resolve_report_execution_forces_local_rules_when_disabled() {
    let mut config = Config::default();
    config.integrations.ai_audit.provider = AiAuditProviderConfig::OpenAiCompatible;
    let params = AiAuditReportQueryParams {
        provider: Some("openai_compatible".to_string()),
        ..AiAuditReportQueryParams::default()
    };

    let execution = resolve_report_execution(&config, &params);

    assert_eq!(execution.provider, AiAuditProvider::LocalRules);
    assert!(execution
        .execution_notes
        .iter()
        .any(|item| item.contains("disabled in global settings")));
}

#[test]
fn parse_model_output_accepts_markdown_json_fences() {
    let output = parse_model_output(
        r#"
```json
{"risk_level":"high","headline":"Need review","executive_summary":["a"],"findings":[{"key":"f1","severity":"high","title":"A","detail":"B","evidence":["c"]}],"recommendations":[{"key":"r1","priority":"high","title":"R","action":"Do","rationale":"Why"}]}
```
"#,
    )
    .unwrap();

    assert_eq!(output.risk_level, "high");
    assert_eq!(output.findings.len(), 1);
    assert_eq!(output.recommendations.len(), 1);
}

#[test]
fn parse_model_output_normalizes_string_summary_and_evidence() {
    let output = parse_model_output(
        r#"{
            "risk_level":"medium",
            "headline":"Need review",
            "executive_summary":"single summary line",
            "findings":[{"key":"f1","severity":"medium","title":"A","detail":"B","evidence":"one evidence line"}],
            "recommendations":[{"key":"r1","priority":"medium","title":"R","action":"Do","rationale":"Why"}]
        }"#,
    )
    .unwrap();

    assert_eq!(
        output.executive_summary,
        vec!["single summary line".to_string()]
    );
    assert_eq!(
        output.findings[0].evidence,
        vec!["one evidence line".to_string()]
    );
}

#[test]
fn parse_model_output_normalizes_non_string_scalar_fields() {
    let output = parse_model_output(
        r#"{
            "risk_level": 1,
            "headline": true,
            "executive_summary": ["ok"],
            "findings": [{
                "key": 123,
                "severity": false,
                "title": 456,
                "detail": {"a":1},
                "evidence": [1, "x"]
            }],
            "recommendations": [{
                "key": 789,
                "priority": 2,
                "title": 3,
                "action": 4,
                "rationale": 5,
                "action_type": 0,
                "rule_suggestion_key": 6
            }],
            "suggested_local_rules": [{
                "key": 1,
                "title": 2,
                "policy_type": 3,
                "layer": 4,
                "scope_type": 5,
                "scope_value": 6,
                "target": 7,
                "action": 8,
                "operator": 9,
                "suggested_value": 10,
                "ttl_secs": "500",
                "auto_apply": 1,
                "rationale": 11
            }]
        }"#,
    )
    .unwrap();

    assert_eq!(output.headline, "true");
    assert_eq!(output.findings[0].key, "123");
    assert_eq!(
        output.recommendations[0].rule_suggestion_key.as_deref(),
        Some("6")
    );
    assert_eq!(output.suggested_local_rules[0].ttl_secs, 500);
    assert!(output.suggested_local_rules[0].auto_apply);
}

#[test]
fn system_prompt_requires_chinese_natural_language_content() {
    let prompt = build_system_prompt();

    assert!(prompt.contains("所有面向人的自然语言内容必须使用简体中文"));
    assert!(prompt.contains("所有 JSON 键名、协议字段、枚举值、规则动作值保持英文"));
}

#[test]
fn user_prompt_requires_chinese_explanatory_text() {
    let prompt = build_user_prompt(&sample_summary(), false).unwrap();

    assert!(prompt.contains("所有说明性文本必须使用简体中文"));
    assert!(prompt.contains("JSON 键名和枚举值保持英文"));
}

#[test]
fn localization_prompt_preserves_keys_and_enums() {
    let prompt = build_localization_system_prompt();

    assert!(prompt.contains("英文枚举值"));
    assert!(prompt.contains("所有面向人的说明文本翻译为简体中文"));
}

#[test]
fn text_needs_chinese_localization_detects_english_and_ignores_chinese() {
    assert!(text_needs_chinese_localization(
        "Need review for suspicious login burst"
    ));
    assert!(!text_needs_chinese_localization("需要复核可疑登录突增"));
    assert!(!text_needs_chinese_localization(""));
}

#[test]
fn model_output_needs_chinese_localization_checks_human_fields() {
    let output = AiAuditModelOutput {
        risk_level: "high".to_string(),
        headline: "Need review".to_string(),
        executive_summary: vec!["中文".to_string()],
        findings: vec![],
        recommendations: vec![],
        suggested_local_rules: vec![],
    };

    assert!(model_output_needs_chinese_localization(&output));
}

#[tokio::test]
async fn openai_compatible_missing_credentials_can_fallback() {
    let execution = AiAuditExecutionSettings {
        provider: AiAuditProvider::OpenAiCompatible,
        fallback_to_rules: true,
        model: Some("gpt-audit".to_string()),
        base_url: Some("https://audit.example.com/v1".to_string()),
        api_key: None,
        timeout_ms: 2_000,
        include_raw_event_samples: false,
        execution_notes: vec!["configured model: gpt-audit".to_string()],
    };
    let report = execute_report(execution, sample_summary(), |summary| {
        AiAuditReportResponse {
            report_id: None,
            generated_at: summary.generated_at,
            runtime_pressure_level: summary.runtime_pressure_level.clone(),
            degraded_reasons: summary.degraded_reasons.clone(),
            provider_used: "local_rules".to_string(),
            fallback_used: false,
            analysis_mode: "analysis_only".to_string(),
            execution_notes: vec!["local report".to_string()],
            risk_level: "low".to_string(),
            headline: "fallback".to_string(),
            executive_summary: vec![],
            input_profile: AiAuditInputProfileResponse {
                source: "cc_behavior_joint_summary".to_string(),
                sampled_events: summary.sampled_events,
                included_recent_events: 0,
                raw_samples_included: false,
                recent_policy_feedback_count: summary.recent_policy_feedback.len() as u32,
            },
            findings: vec![],
            recommendations: vec![],
            suggested_local_rules: vec![],
            summary,
        }
    })
    .await
    .unwrap();

    assert!(report.fallback_used);
    assert_eq!(report.provider_used, "local_rules");
    assert!(report
        .execution_notes
        .iter()
        .any(|item| item.contains("缺少 api_key")));
}
