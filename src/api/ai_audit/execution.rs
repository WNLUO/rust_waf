use super::normalization::{
    model_output_needs_chinese_localization, non_empty, normalize_action_type,
    normalize_policy_action, normalize_priority, normalize_risk_level, normalize_rule_layer,
    normalize_severity, parse_model_output, truncate_for_error,
};
use super::prompts::{
    build_input_profile, build_localization_system_prompt, build_localization_user_prompt,
    build_system_prompt, build_user_prompt,
};
use super::types::{
    AiAuditModelOutput, OpenAiCompatibleChatRequest, OpenAiCompatibleChatResponse,
    OpenAiCompatibleMessage, ProviderAuth,
};
use super::{AiAuditExecutionSettings, AiAuditProvider};
use crate::api::{
    AiAuditReportFinding, AiAuditReportRecommendation, AiAuditReportResponse,
    AiAuditSuggestedRuleResponse, AiAuditSummaryResponse, ApiError, ApiResult,
};
use reqwest::Client;
use std::time::Duration;

pub(in crate::api) async fn execute_report(
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
                Ok((output, notes)) => Ok(build_provider_report(
                    &execution,
                    summary,
                    output,
                    AiAuditProvider::OpenAiCompatible.label(),
                    false,
                    notes,
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
            Ok((output, notes)) => Ok(build_provider_report(
                &execution,
                summary,
                output,
                AiAuditProvider::XiaomiMimo.label(),
                false,
                notes,
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
) -> anyhow::Result<(AiAuditModelOutput, Vec<String>)> {
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
    let raw_content = send_chat_request(
        &client,
        &endpoint,
        ProviderAuth::Bearer(api_key),
        &OpenAiCompatibleChatRequest {
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
        },
    )
    .await?;

    let output = parse_model_output(&raw_content)?;
    let mut notes = vec!["报告由 openai_compatible provider 生成".to_string()];
    match localize_model_output_if_needed(
        &client,
        &endpoint,
        ProviderAuth::Bearer(api_key),
        model,
        output.clone(),
    )
    .await
    {
        Ok((localized_output, true)) => {
            notes.push("检测到英文说明文本，已追加一次中文本地化转换".to_string());
            Ok((localized_output, notes))
        }
        Ok((localized_output, false)) => Ok((localized_output, notes)),
        Err(err) => {
            notes.push(format!(
                "中文本地化转换失败，保留原始输出：{}",
                truncate_for_error(&err.to_string())
            ));
            Ok((output, notes))
        }
    }
}

async fn call_xiaomi_mimo_report(
    execution: &AiAuditExecutionSettings,
    summary: &AiAuditSummaryResponse,
) -> anyhow::Result<(AiAuditModelOutput, Vec<String>)> {
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
    let raw_content = send_chat_request(
        &client,
        &endpoint,
        ProviderAuth::Header("api-key", api_key),
        &OpenAiCompatibleChatRequest {
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
        },
    )
    .await?;

    let output = parse_model_output(&raw_content)?;
    let mut notes = vec!["报告由 xiaomi_mimo provider 生成".to_string()];
    match localize_model_output_if_needed(
        &client,
        &endpoint,
        ProviderAuth::Header("api-key", api_key),
        model,
        output.clone(),
    )
    .await
    {
        Ok((localized_output, true)) => {
            notes.push("检测到英文说明文本，已追加一次中文本地化转换".to_string());
            Ok((localized_output, notes))
        }
        Ok((localized_output, false)) => Ok((localized_output, notes)),
        Err(err) => {
            notes.push(format!(
                "中文本地化转换失败，保留原始输出：{}",
                truncate_for_error(&err.to_string())
            ));
            Ok((output, notes))
        }
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

async fn send_chat_request(
    client: &Client,
    endpoint: &str,
    auth: ProviderAuth<'_>,
    request: &OpenAiCompatibleChatRequest,
) -> anyhow::Result<String> {
    let response = match auth {
        ProviderAuth::Bearer(token) => {
            client
                .post(endpoint)
                .bearer_auth(token)
                .json(request)
                .send()
                .await?
        }
        ProviderAuth::Header(name, value) => {
            client
                .post(endpoint)
                .header(name, value)
                .json(request)
                .send()
                .await?
        }
    };
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
    extract_choice_content(&payload)
}

async fn localize_model_output_if_needed(
    client: &Client,
    endpoint: &str,
    auth: ProviderAuth<'_>,
    model: &str,
    output: AiAuditModelOutput,
) -> anyhow::Result<(AiAuditModelOutput, bool)> {
    if !model_output_needs_chinese_localization(&output) {
        return Ok((output, false));
    }

    let raw_content = send_chat_request(
        client,
        endpoint,
        auth,
        &OpenAiCompatibleChatRequest {
            model: model.to_string(),
            messages: vec![
                OpenAiCompatibleMessage {
                    role: "system".to_string(),
                    content: build_localization_system_prompt(),
                },
                OpenAiCompatibleMessage {
                    role: "user".to_string(),
                    content: build_localization_user_prompt(&output)?,
                },
            ],
            temperature: 0.0,
        },
    )
    .await?;
    Ok((parse_model_output(&raw_content)?, true))
}
