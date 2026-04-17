use super::{
    AiAuditInputProfileResponse, AiAuditReportHistoryItem, AiAuditReportQueryParams,
    AiAuditReportResponse, AiAuditSummaryQueryParams, AiAuditSummaryResponse,
};
use crate::config::{AiAuditConfig, AiAuditProviderConfig, Config};
use crate::storage::AiAuditReportEntry;

mod execution;
mod normalization;
mod prompts;
mod types;

pub(super) use execution::execute_report;
use normalization::{non_empty, provider_from_config};

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

pub(super) fn history_item_from_entry(
    entry: AiAuditReportEntry,
) -> anyhow::Result<AiAuditReportHistoryItem> {
    let mut report = serde_json::from_str::<AiAuditReportResponse>(&entry.report_json)?;
    report.report_id = Some(entry.id);
    let auto_trigger_reason = report.execution_notes.iter().find_map(|note| {
        note.strip_prefix("auto audit trigger reason: ")
            .map(|value| value.trim().to_string())
    });
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
        auto_generated: auto_trigger_reason.is_some(),
        auto_trigger_reason,
        report,
    })
}

#[cfg(test)]
mod tests;
