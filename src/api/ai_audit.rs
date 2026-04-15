use super::{
    AiAuditInputProfileResponse, AiAuditReportFinding, AiAuditReportHistoryItem,
    AiAuditReportQueryParams, AiAuditReportRecommendation, AiAuditReportResponse,
    AiAuditSuggestedRuleResponse, AiAuditSummaryQueryParams, AiAuditSummaryResponse, ApiError,
    ApiResult,
};
use crate::config::{AiAuditConfig, AiAuditProviderConfig, Config};
use crate::storage::AiAuditReportEntry;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AiAuditProvider {
    LocalRules,
    StubModel,
    OpenAiCompatible,
    XiaomiMimo,
}

impl AiAuditProvider {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::LocalRules => "local_rules",
            Self::StubModel => "stub_model",
            Self::OpenAiCompatible => "openai_compatible",
            Self::XiaomiMimo => "xiaomi_mimo",
        }
    }

    fn from_str(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "stub_model" => Self::StubModel,
            "openai_compatible" => Self::OpenAiCompatible,
            "xiaomi_mimo" => Self::XiaomiMimo,
            _ => Self::LocalRules,
        }
    }
}

#[derive(Debug, Clone)]
pub(super) struct AiAuditExecutionSettings {
    pub(super) provider: AiAuditProvider,
    pub(super) fallback_to_rules: bool,
    pub(super) model: Option<String>,
    pub(super) base_url: Option<String>,
    pub(super) api_key: Option<String>,
    pub(super) timeout_ms: u64,
    pub(super) include_raw_event_samples: bool,
    pub(super) execution_notes: Vec<String>,
}

pub(super) fn resolve_report_execution(
    config: &Config,
    params: &AiAuditReportQueryParams,
) -> AiAuditExecutionSettings {
    let ai_config = &config.integrations.ai_audit;
    let provider = params
        .provider
        .as_deref()
        .map(AiAuditProvider::from_str)
        .unwrap_or_else(|| provider_from_config(ai_config));
    let fallback_to_rules = params
        .fallback_to_rules
        .unwrap_or(ai_config.fallback_to_rules);
    let mut execution_notes = Vec::new();

    if !ai_config.enabled && provider != AiAuditProvider::LocalRules {
        execution_notes.push(
            "ai audit provider is disabled in global settings; using local_rules".to_string(),
        );
    }
    if provider != AiAuditProvider::LocalRules {
        if let Some(model) = non_empty(&ai_config.model) {
            execution_notes.push(format!("configured model: {}", model));
        }
        if let Some(base_url) = non_empty(&ai_config.base_url) {
            execution_notes.push(format!("configured endpoint: {}", base_url));
        }
        execution_notes.push(format!(
            "provider timeout budget set to {} ms",
            ai_config.timeout_ms
        ));
    }

    AiAuditExecutionSettings {
        provider: if !ai_config.enabled && provider != AiAuditProvider::LocalRules {
            AiAuditProvider::LocalRules
        } else {
            provider
        },
        fallback_to_rules,
        model: non_empty(&ai_config.model),
        base_url: non_empty(&ai_config.base_url),
        api_key: non_empty(&ai_config.api_key),
        timeout_ms: ai_config.timeout_ms,
        include_raw_event_samples: ai_config.include_raw_event_samples,
        execution_notes,
    }
}

pub(super) fn summary_query_from_report(
    params: &AiAuditReportQueryParams,
) -> AiAuditSummaryQueryParams {
    AiAuditSummaryQueryParams {
        window_seconds: params.window_seconds,
        sample_limit: params.sample_limit,
        recent_limit: params.recent_limit,
    }
}

pub(super) async fn execute_report(
    execution: AiAuditExecutionSettings,
    summary: AiAuditSummaryResponse,
    local_rules_builder: impl Fn(AiAuditSummaryResponse) -> AiAuditReportResponse,
) -> ApiResult<AiAuditReportResponse> {
    let fallback_report = summary.clone();
    match execution.provider {
        AiAuditProvider::LocalRules => {
            let mut report = local_rules_builder(summary);
            report.provider_used = AiAuditProvider::LocalRules.label().to_string();
            report.fallback_used = false;
            report.analysis_mode = "analysis_only".to_string();
            report.execution_notes.extend(execution.execution_notes);
            Ok(report)
        }
        AiAuditProvider::StubModel => {
            let mut report = local_rules_builder(summary);
            report.provider_used = if execution.fallback_to_rules {
                AiAuditProvider::LocalRules.label().to_string()
            } else {
                AiAuditProvider::StubModel.label().to_string()
            };
            report.fallback_used = execution.fallback_to_rules;
            report.analysis_mode = "analysis_only".to_string();
            report.execution_notes.extend(execution.execution_notes);
            if execution.fallback_to_rules {
                report.execution_notes.push(
                    "stub_model provider is not connected yet; fell back to local_rules"
                        .to_string(),
                );
            } else {
                report.execution_notes.push(
                    "stub_model provider requested without fallback; returning local skeleton output"
                        .to_string(),
                );
            }
            Ok(report)
        }
        AiAuditProvider::OpenAiCompatible => {
            match call_openai_compatible_report(&execution, &summary).await {
                Ok(output) => Ok(build_provider_report(
                    &execution,
                    summary,
                    output,
                    AiAuditProvider::OpenAiCompatible.label(),
                    false,
                    vec!["report generated by openai_compatible provider".to_string()],
                )),
                Err(err) if execution.fallback_to_rules => {
                    let mut report = local_rules_builder(fallback_report);
                    report.provider_used = AiAuditProvider::LocalRules.label().to_string();
                    report.fallback_used = true;
                    report.analysis_mode = "analysis_only".to_string();
                    report.execution_notes.extend(execution.execution_notes);
                    report.execution_notes.push(format!(
                        "openai_compatible provider failed; fell back to local_rules: {}",
                        err
                    ));
                    Ok(report)
                }
                Err(err) => Err(ApiError::internal(format!(
                    "AI 审计 provider 执行失败: {}",
                    err
                ))),
            }
        }
        AiAuditProvider::XiaomiMimo => match call_xiaomi_mimo_report(&execution, &summary).await {
            Ok(output) => Ok(build_provider_report(
                &execution,
                summary,
                output,
                AiAuditProvider::XiaomiMimo.label(),
                false,
                vec!["report generated by xiaomi_mimo provider".to_string()],
            )),
            Err(err) if execution.fallback_to_rules => {
                let mut report = local_rules_builder(fallback_report);
                report.provider_used = AiAuditProvider::LocalRules.label().to_string();
                report.fallback_used = true;
                report.analysis_mode = "analysis_only".to_string();
                report.execution_notes.extend(execution.execution_notes);
                report.execution_notes.push(format!(
                    "xiaomi_mimo provider failed; fell back to local_rules: {}",
                    err
                ));
                Ok(report)
            }
            Err(err) => Err(ApiError::internal(format!(
                "AI 审计 provider 执行失败: {}",
                err
            ))),
        },
    }
}

fn build_provider_report(
    execution: &AiAuditExecutionSettings,
    summary: AiAuditSummaryResponse,
    output: AiAuditModelOutput,
    provider_used: &str,
    fallback_used: bool,
    mut execution_notes: Vec<String>,
) -> AiAuditReportResponse {
    execution_notes.extend(execution.execution_notes.clone());

    AiAuditReportResponse {
        report_id: None,
        generated_at: summary.generated_at,
        runtime_pressure_level: summary.runtime_pressure_level.clone(),
        degraded_reasons: summary.degraded_reasons.clone(),
        provider_used: provider_used.to_string(),
        fallback_used,
        analysis_mode: "analysis_only".to_string(),
        execution_notes,
        risk_level: normalize_risk_level(&output.risk_level),
        headline: non_empty(&output.headline).unwrap_or_else(|| "AI 审计已完成".to_string()),
        executive_summary: output.executive_summary,
        input_profile: build_input_profile(&summary, execution.include_raw_event_samples),
        findings: output
            .findings
            .into_iter()
            .map(|item| AiAuditReportFinding {
                key: item.key,
                severity: normalize_severity(&item.severity),
                title: item.title,
                detail: item.detail,
                evidence: item.evidence,
            })
            .collect(),
        recommendations: output
            .recommendations
            .into_iter()
            .map(|item| AiAuditReportRecommendation {
                key: item.key,
                priority: normalize_priority(&item.priority),
                title: item.title,
                action: item.action,
                rationale: item.rationale,
                action_type: normalize_action_type(&item.action_type),
                rule_suggestion_key: item.rule_suggestion_key,
            })
            .collect(),
        suggested_local_rules: output
            .suggested_local_rules
            .into_iter()
            .map(|item| AiAuditSuggestedRuleResponse {
                key: item.key,
                title: item.title,
                policy_type: item.policy_type,
                layer: normalize_rule_layer(&item.layer),
                scope_type: item.scope_type,
                scope_value: item.scope_value,
                target: item.target,
                action: normalize_policy_action(&item.action),
                operator: item.operator,
                suggested_value: item.suggested_value,
                ttl_secs: item.ttl_secs.max(60),
                auto_apply: item.auto_apply,
                rationale: item.rationale,
            })
            .collect(),
        summary,
    }
}

async fn call_openai_compatible_report(
    execution: &AiAuditExecutionSettings,
    summary: &AiAuditSummaryResponse,
) -> anyhow::Result<AiAuditModelOutput> {
    let model = execution
        .model
        .as_deref()
        .filter(|item| !item.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("openai_compatible provider 缺少 model 配置"))?;
    let base_url = execution
        .base_url
        .as_deref()
        .filter(|item| !item.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("openai_compatible provider 缺少 base_url 配置"))?;
    let api_key = execution
        .api_key
        .as_deref()
        .filter(|item| !item.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("openai_compatible provider 缺少 api_key 配置"))?;

    let client = Client::builder()
        .timeout(Duration::from_millis(execution.timeout_ms))
        .build()?;
    let endpoint = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let request = OpenAiCompatibleChatRequest {
        model: model.to_string(),
        messages: vec![
            OpenAiCompatibleMessage {
                role: "system".to_string(),
                content: build_system_prompt(),
            },
            OpenAiCompatibleMessage {
                role: "user".to_string(),
                content: build_user_prompt(summary, execution.include_raw_event_samples)?,
            },
        ],
        temperature: 0.1,
    };

    let response = client
        .post(endpoint)
        .bearer_auth(api_key)
        .json(&request)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "provider returned {}: {}",
            status,
            truncate_for_error(&body)
        ));
    }

    let payload: OpenAiCompatibleChatResponse = serde_json::from_str(&body)?;
    let raw_content = extract_choice_content(&payload)?;
    parse_model_output(&raw_content)
}

async fn call_xiaomi_mimo_report(
    execution: &AiAuditExecutionSettings,
    summary: &AiAuditSummaryResponse,
) -> anyhow::Result<AiAuditModelOutput> {
    let model = execution
        .model
        .as_deref()
        .filter(|item| !item.trim().is_empty())
        .or(Some("mimo-v2-flash"))
        .ok_or_else(|| anyhow::anyhow!("xiaomi_mimo provider 缺少 model 配置"))?;
    let base_url = execution
        .base_url
        .as_deref()
        .filter(|item| !item.trim().is_empty())
        .unwrap_or("https://api.xiaomimimo.com/v1");
    let api_key = execution
        .api_key
        .as_deref()
        .filter(|item| !item.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("xiaomi_mimo provider 缺少 api_key 配置"))?;

    let client = Client::builder()
        .timeout(Duration::from_millis(execution.timeout_ms))
        .build()?;
    let endpoint = format!("{}/chat/completions", base_url.trim_end_matches('/'));
    let request = OpenAiCompatibleChatRequest {
        model: model.to_string(),
        messages: vec![
            OpenAiCompatibleMessage {
                role: "system".to_string(),
                content: build_system_prompt(),
            },
            OpenAiCompatibleMessage {
                role: "user".to_string(),
                content: build_user_prompt(summary, execution.include_raw_event_samples)?,
            },
        ],
        temperature: 0.1,
    };

    let response = client
        .post(endpoint)
        .header("api-key", api_key)
        .json(&request)
        .send()
        .await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "provider returned {}: {}",
            status,
            truncate_for_error(&body)
        ));
    }
    let payload: OpenAiCompatibleChatResponse = serde_json::from_str(&body)?;
    let raw_content = extract_choice_content(&payload)?;
    parse_model_output(&raw_content)
}

fn build_system_prompt() -> String {
    [
        "You are an application security audit assistant.",
        "Return only a JSON object with the keys:",
        "risk_level, headline, executive_summary, findings, recommendations, suggested_local_rules.",
        "risk_level must be one of: low, medium, high, critical.",
        "findings items must contain: key, severity, title, detail, evidence.",
        "recommendations items must contain: key, priority, title, action, rationale, action_type, rule_suggestion_key.",
        "action_type must be one of: observe, tune_threshold, add_rule, investigate.",
        "suggested_local_rules items must contain: key, title, policy_type, layer, scope_type, scope_value, target, action, operator, suggested_value, ttl_secs, auto_apply, rationale.",
        "layer must be one of: l4, l7.",
        "Do not include markdown fences or any extra commentary.",
        "This is an analysis-only task. Never claim that the model directly blocked traffic.",
        "Be conservative: avoid claiming certainty when the summary only supports a suspicion.",
        "If data_quality.analysis_confidence is low, keep conclusions cautious and prefer manual review.",
    ]
    .join(" ")
}

fn build_user_prompt(
    summary: &AiAuditSummaryResponse,
    include_raw_event_samples: bool,
) -> anyhow::Result<String> {
    Ok(format!(
        "Analyze the following WAF audit summary and produce the required JSON object.\nSummary JSON:\n{}",
        serde_json::to_string(&build_provider_input(summary, include_raw_event_samples))?
    ))
}

fn build_provider_input(
    summary: &AiAuditSummaryResponse,
    include_raw_event_samples: bool,
) -> serde_json::Value {
    serde_json::json!({
        "input_profile": build_input_profile(summary, include_raw_event_samples),
        "runtime_pressure_level": summary.runtime_pressure_level,
        "degraded_reasons": summary.degraded_reasons,
        "data_quality": summary.data_quality,
        "current": summary.current,
        "counters": summary.counters,
        "action_breakdown": summary.action_breakdown,
        "provider_breakdown": summary.provider_breakdown,
        "identity_states": summary.identity_states,
        "primary_signals": summary.primary_signals,
        "labels": summary.labels,
        "top_source_ips": summary.top_source_ips,
        "top_routes": summary.top_routes,
        "top_hosts": summary.top_hosts,
        "safeline_correlation": summary.safeline_correlation,
        "trend_windows": summary.trend_windows,
        "recent_policy_feedback": summary.recent_policy_feedback,
        "recent_events": if include_raw_event_samples {
            serde_json::to_value(&summary.recent_events).unwrap_or_else(|_| serde_json::Value::Array(Vec::new()))
        } else {
            serde_json::Value::Array(Vec::new())
        },
    })
}

fn build_input_profile(
    summary: &AiAuditSummaryResponse,
    raw_samples_included: bool,
) -> AiAuditInputProfileResponse {
    AiAuditInputProfileResponse {
        source: "cc_behavior_joint_summary".to_string(),
        sampled_events: summary.sampled_events,
        included_recent_events: if raw_samples_included {
            summary.recent_events.len() as u32
        } else {
            0
        },
        raw_samples_included,
        recent_policy_feedback_count: summary.recent_policy_feedback.len() as u32,
    }
}

fn extract_choice_content(payload: &OpenAiCompatibleChatResponse) -> anyhow::Result<String> {
    let first = payload
        .choices
        .first()
        .ok_or_else(|| anyhow::anyhow!("provider response did not contain choices"))?;
    first
        .message
        .content_as_text()
        .ok_or_else(|| anyhow::anyhow!("provider response did not contain text content"))
}

fn parse_model_output(content: &str) -> anyhow::Result<AiAuditModelOutput> {
    let normalized = strip_markdown_fences(content);
    let mut value = serde_json::from_str::<serde_json::Value>(normalized.trim())?;
    normalize_model_output_value(&mut value);
    Ok(serde_json::from_value::<AiAuditModelOutput>(value)?)
}

fn normalize_model_output_value(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };

    normalize_scalar_string_field(object, "risk_level");
    normalize_scalar_string_field(object, "headline");
    normalize_string_or_array_field(object, "executive_summary");

    if let Some(findings) = object
        .get_mut("findings")
        .and_then(|item| item.as_array_mut())
    {
        for finding in findings {
            if let Some(finding_object) = finding.as_object_mut() {
                normalize_scalar_string_field(finding_object, "key");
                normalize_scalar_string_field(finding_object, "severity");
                normalize_scalar_string_field(finding_object, "title");
                normalize_scalar_string_field(finding_object, "detail");
                normalize_string_or_array_field(finding_object, "evidence");
            }
        }
    }
    if let Some(recommendations) = object
        .get_mut("recommendations")
        .and_then(|item| item.as_array_mut())
    {
        for recommendation in recommendations {
            if let Some(recommendation_object) = recommendation.as_object_mut() {
                normalize_scalar_string_field(recommendation_object, "key");
                normalize_scalar_string_field(recommendation_object, "priority");
                normalize_scalar_string_field(recommendation_object, "title");
                normalize_scalar_string_field(recommendation_object, "action");
                normalize_scalar_string_field(recommendation_object, "rationale");
                if !recommendation_object.contains_key("action_type") {
                    recommendation_object.insert(
                        "action_type".to_string(),
                        serde_json::Value::String("observe".to_string()),
                    );
                }
                normalize_scalar_string_field(recommendation_object, "action_type");
                if !recommendation_object.contains_key("rule_suggestion_key") {
                    recommendation_object
                        .insert("rule_suggestion_key".to_string(), serde_json::Value::Null);
                }
                normalize_optional_string_field(recommendation_object, "rule_suggestion_key");
            }
        }
    }
    if !object.contains_key("suggested_local_rules") {
        object.insert(
            "suggested_local_rules".to_string(),
            serde_json::Value::Array(Vec::new()),
        );
    }
    if let Some(rules) = object
        .get_mut("suggested_local_rules")
        .and_then(|item| item.as_array_mut())
    {
        for rule in rules {
            if let Some(rule_object) = rule.as_object_mut() {
                normalize_scalar_string_field(rule_object, "key");
                normalize_scalar_string_field(rule_object, "title");
                normalize_scalar_string_field(rule_object, "policy_type");
                normalize_scalar_string_field(rule_object, "layer");
                normalize_scalar_string_field(rule_object, "scope_type");
                normalize_scalar_string_field(rule_object, "scope_value");
                normalize_scalar_string_field(rule_object, "target");
                normalize_scalar_string_field(rule_object, "action");
                normalize_scalar_string_field(rule_object, "operator");
                normalize_scalar_string_field(rule_object, "suggested_value");
                normalize_scalar_string_field(rule_object, "rationale");
                normalize_u64_field(rule_object, "ttl_secs");
                normalize_bool_field(rule_object, "auto_apply");
            }
        }
    }
}

fn normalize_string_or_array_field(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    let Some(value) = object.get_mut(key) else {
        return;
    };

    match value {
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                *value = serde_json::Value::Array(Vec::new());
            } else {
                *value =
                    serde_json::Value::Array(vec![serde_json::Value::String(trimmed.to_string())]);
            }
        }
        serde_json::Value::Array(items) => {
            let normalized = items
                .drain(..)
                .filter_map(|item| match item {
                    serde_json::Value::String(text) => {
                        let trimmed = text.trim().to_string();
                        (!trimmed.is_empty()).then(|| serde_json::Value::String(trimmed))
                    }
                    serde_json::Value::Null => None,
                    other => Some(serde_json::Value::String(
                        other.to_string().trim_matches('"').to_string(),
                    )),
                })
                .collect::<Vec<_>>();
            *items = normalized;
        }
        serde_json::Value::Null => {
            *value = serde_json::Value::Array(Vec::new());
        }
        other => {
            *other = serde_json::Value::Array(vec![serde_json::Value::String(other.to_string())]);
        }
    }
}

fn normalize_scalar_string_field(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    let Some(value) = object.get_mut(key) else {
        return;
    };

    match value {
        serde_json::Value::String(text) => {
            *text = text.trim().to_string();
        }
        serde_json::Value::Null => {
            *value = serde_json::Value::String(String::new());
        }
        other => {
            *other = serde_json::Value::String(other.to_string().trim_matches('"').to_string());
        }
    }
}

fn normalize_optional_string_field(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    let Some(value) = object.get_mut(key) else {
        return;
    };

    match value {
        serde_json::Value::Null => {}
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                *value = serde_json::Value::Null;
            } else {
                *text = trimmed.to_string();
            }
        }
        _ => {
            let normalized = value.to_string().trim_matches('"').trim().to_string();
            if normalized.is_empty() {
                *value = serde_json::Value::Null;
            } else {
                *value = serde_json::Value::String(normalized);
            }
        }
    }
}

fn normalize_u64_field(object: &mut serde_json::Map<String, serde_json::Value>, key: &str) {
    let Some(value) = object.get_mut(key) else {
        return;
    };

    let normalized = match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => text.trim().parse::<u64>().ok(),
        serde_json::Value::Bool(flag) => Some(u64::from(*flag)),
        _ => None,
    }
    .unwrap_or(0);

    *value = serde_json::Value::Number(serde_json::Number::from(normalized));
}

fn normalize_bool_field(object: &mut serde_json::Map<String, serde_json::Value>, key: &str) {
    let Some(value) = object.get_mut(key) else {
        return;
    };

    let normalized = match value {
        serde_json::Value::Bool(flag) => *flag,
        serde_json::Value::Number(number) => number.as_u64().map(|raw| raw != 0).unwrap_or(false),
        serde_json::Value::String(text) => matches!(
            text.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        _ => false,
    };

    *value = serde_json::Value::Bool(normalized);
}

fn provider_from_config(config: &AiAuditConfig) -> AiAuditProvider {
    match config.provider {
        AiAuditProviderConfig::StubModel => AiAuditProvider::StubModel,
        AiAuditProviderConfig::OpenAiCompatible => AiAuditProvider::OpenAiCompatible,
        AiAuditProviderConfig::XiaomiMimo => AiAuditProvider::XiaomiMimo,
        AiAuditProviderConfig::LocalRules => AiAuditProvider::LocalRules,
    }
}

fn normalize_risk_level(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" | "medium" | "high" | "critical" => value.trim().to_ascii_lowercase(),
        _ => "medium".to_string(),
    }
}

fn normalize_action_type(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "observe" | "tune_threshold" | "add_rule" | "investigate" => {
            value.trim().to_ascii_lowercase()
        }
        _ => "observe".to_string(),
    }
}

fn normalize_rule_layer(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "l4" | "l7" => value.trim().to_ascii_lowercase(),
        _ => "l7".to_string(),
    }
}

fn normalize_policy_action(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "tighten_route_cc"
        | "tighten_host_cc"
        | "raise_identity_risk"
        | "add_behavior_watch"
        | "add_temp_block"
        | "increase_challenge"
        | "increase_delay"
        | "watch_only" => value.trim().to_ascii_lowercase(),
        _ => "watch_only".to_string(),
    }
}

fn normalize_severity(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" | "medium" | "high" | "critical" => value.trim().to_ascii_lowercase(),
        _ => "medium".to_string(),
    }
}

fn normalize_priority(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" | "medium" | "high" | "urgent" => value.trim().to_ascii_lowercase(),
        _ => "medium".to_string(),
    }
}

fn strip_markdown_fences(content: &str) -> &str {
    let trimmed = content.trim();
    if let Some(stripped) = trimmed.strip_prefix("```json") {
        return stripped.strip_suffix("```").unwrap_or(stripped).trim();
    }
    if let Some(stripped) = trimmed.strip_prefix("```") {
        return stripped.strip_suffix("```").unwrap_or(stripped).trim();
    }
    trimmed
}

fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn truncate_for_error(body: &str) -> String {
    const MAX_LEN: usize = 240;
    let body = body.trim();
    if body.chars().count() <= MAX_LEN {
        body.to_string()
    } else {
        format!("{}...", body.chars().take(MAX_LEN).collect::<String>())
    }
}

pub(super) fn history_item_from_entry(
    entry: AiAuditReportEntry,
) -> anyhow::Result<AiAuditReportHistoryItem> {
    let mut report = serde_json::from_str::<AiAuditReportResponse>(&entry.report_json)?;
    report.report_id = Some(entry.id);
    Ok(AiAuditReportHistoryItem {
        id: entry.id,
        generated_at: entry.generated_at,
        provider_used: entry.provider_used,
        fallback_used: entry.fallback_used,
        risk_level: entry.risk_level,
        headline: entry.headline,
        feedback_status: entry.feedback_status,
        feedback_notes: entry.feedback_notes,
        feedback_updated_at: entry.feedback_updated_at,
        report,
    })
}

#[derive(Debug, Serialize)]
struct OpenAiCompatibleChatRequest {
    model: String,
    messages: Vec<OpenAiCompatibleMessage>,
    temperature: f32,
}

#[derive(Debug, Serialize)]
struct OpenAiCompatibleMessage {
    role: String,
    content: String,
}

#[derive(Debug, Deserialize)]
struct OpenAiCompatibleChatResponse {
    choices: Vec<OpenAiCompatibleChoice>,
}

#[derive(Debug, Deserialize)]
struct OpenAiCompatibleChoice {
    message: OpenAiCompatibleResponseMessage,
}

#[derive(Debug, Deserialize)]
struct OpenAiCompatibleResponseMessage {
    content: serde_json::Value,
}

impl OpenAiCompatibleResponseMessage {
    fn content_as_text(&self) -> Option<String> {
        match &self.content {
            serde_json::Value::String(value) => Some(value.clone()),
            serde_json::Value::Array(items) => Some(
                items
                    .iter()
                    .filter_map(|item| item.get("text").and_then(|text| text.as_str()))
                    .collect::<Vec<_>>()
                    .join(""),
            )
            .filter(|value| !value.is_empty()),
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct AiAuditModelOutput {
    risk_level: String,
    headline: String,
    #[serde(default)]
    executive_summary: Vec<String>,
    #[serde(default)]
    findings: Vec<AiAuditModelFinding>,
    #[serde(default)]
    recommendations: Vec<AiAuditModelRecommendation>,
    #[serde(default)]
    suggested_local_rules: Vec<AiAuditModelSuggestedRule>,
}

#[derive(Debug, Deserialize)]
struct AiAuditModelFinding {
    key: String,
    severity: String,
    title: String,
    detail: String,
    #[serde(default)]
    evidence: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct AiAuditModelRecommendation {
    key: String,
    priority: String,
    title: String,
    action: String,
    rationale: String,
    #[serde(default)]
    action_type: String,
    #[serde(default)]
    rule_suggestion_key: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AiAuditModelSuggestedRule {
    key: String,
    title: String,
    #[serde(default)]
    policy_type: String,
    layer: String,
    #[serde(default)]
    scope_type: String,
    #[serde(default)]
    scope_value: String,
    target: String,
    #[serde(default)]
    action: String,
    operator: String,
    suggested_value: String,
    #[serde(default)]
    ttl_secs: u64,
    #[serde(default)]
    auto_apply: bool,
    rationale: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{
        AiAuditCountItem, AiAuditCountersResponse, AiAuditCurrentStateResponse,
        AiAuditDataQualityResponse, AiAuditEventSampleResponse,
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
}
