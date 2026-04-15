use super::{
    AiAuditReportFinding, AiAuditReportHistoryItem, AiAuditReportQueryParams,
    AiAuditReportRecommendation, AiAuditReportResponse, AiAuditSummaryQueryParams,
    AiAuditSummaryResponse, ApiError, ApiResult,
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
        provider_used: provider_used.to_string(),
        fallback_used,
        execution_notes,
        risk_level: normalize_risk_level(&output.risk_level),
        headline: non_empty(&output.headline).unwrap_or_else(|| "AI 审计已完成".to_string()),
        executive_summary: output.executive_summary,
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
                content: build_user_prompt(summary)?,
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
                content: build_user_prompt(summary)?,
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
        "risk_level, headline, executive_summary, findings, recommendations.",
        "risk_level must be one of: low, medium, high, critical.",
        "findings items must contain: key, severity, title, detail, evidence.",
        "recommendations items must contain: key, priority, title, action, rationale.",
        "Do not include markdown fences or any extra commentary.",
        "Be conservative: avoid claiming certainty when the summary only supports a suspicion.",
    ]
    .join(" ")
}

fn build_user_prompt(summary: &AiAuditSummaryResponse) -> anyhow::Result<String> {
    Ok(format!(
        "Analyze the following WAF audit summary and produce the required JSON object.\nSummary JSON:\n{}",
        serde_json::to_string(summary)?
    ))
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

    normalize_string_or_array_field(object, "executive_summary");

    if let Some(findings) = object
        .get_mut("findings")
        .and_then(|item| item.as_array_mut())
    {
        for finding in findings {
            if let Some(finding_object) = finding.as_object_mut() {
                normalize_string_or_array_field(finding_object, "evidence");
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
            items.retain(|item| match item {
                serde_json::Value::String(text) => !text.trim().is_empty(),
                _ => true,
            });
        }
        serde_json::Value::Null => {
            *value = serde_json::Value::Array(Vec::new());
        }
        other => {
            *other = serde_json::Value::Array(vec![serde_json::Value::String(other.to_string())]);
        }
    }
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{
        AiAuditCountItem, AiAuditCountersResponse, AiAuditCurrentStateResponse,
        AiAuditEventSampleResponse,
    };

    fn sample_summary() -> AiAuditSummaryResponse {
        AiAuditSummaryResponse {
            generated_at: 1,
            window_seconds: 300,
            sampled_events: 2,
            total_events: 2,
            active_rules: 4,
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

    #[tokio::test]
    async fn openai_compatible_missing_credentials_can_fallback() {
        let execution = AiAuditExecutionSettings {
            provider: AiAuditProvider::OpenAiCompatible,
            fallback_to_rules: true,
            model: Some("gpt-audit".to_string()),
            base_url: Some("https://audit.example.com/v1".to_string()),
            api_key: None,
            timeout_ms: 2_000,
            execution_notes: vec!["configured model: gpt-audit".to_string()],
        };
        let report = execute_report(execution, sample_summary(), |summary| {
            AiAuditReportResponse {
                report_id: None,
                generated_at: summary.generated_at,
                provider_used: "local_rules".to_string(),
                fallback_used: false,
                execution_notes: vec!["local report".to_string()],
                risk_level: "low".to_string(),
                headline: "fallback".to_string(),
                executive_summary: vec![],
                findings: vec![],
                recommendations: vec![],
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
