use super::{
    AiAuditReportQueryParams, AiAuditReportResponse, AiAuditSummaryQueryParams,
    AiAuditSummaryResponse,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AiAuditProvider {
    LocalRules,
    StubModel,
}

impl AiAuditProvider {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::LocalRules => "local_rules",
            Self::StubModel => "stub_model",
        }
    }
}

pub(super) fn provider_from_report_query(params: &AiAuditReportQueryParams) -> AiAuditProvider {
    match params
        .provider
        .as_deref()
        .unwrap_or("local_rules")
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "stub_model" => AiAuditProvider::StubModel,
        _ => AiAuditProvider::LocalRules,
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

pub(super) fn finalize_report_execution(
    provider: AiAuditProvider,
    fallback_to_rules: bool,
    summary: AiAuditSummaryResponse,
    local_rules_builder: impl FnOnce(AiAuditSummaryResponse) -> AiAuditReportResponse,
) -> AiAuditReportResponse {
    match provider {
        AiAuditProvider::LocalRules => {
            let mut report = local_rules_builder(summary);
            report.provider_used = AiAuditProvider::LocalRules.label().to_string();
            report.fallback_used = false;
            report
        }
        AiAuditProvider::StubModel => {
            let mut report = local_rules_builder(summary);
            report.provider_used = if fallback_to_rules {
                AiAuditProvider::LocalRules.label().to_string()
            } else {
                AiAuditProvider::StubModel.label().to_string()
            };
            report.fallback_used = fallback_to_rules;
            if fallback_to_rules {
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
            report
        }
    }
}
