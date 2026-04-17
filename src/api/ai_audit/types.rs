use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub(super) struct OpenAiCompatibleChatRequest {
    pub(super) model: String,
    pub(super) messages: Vec<OpenAiCompatibleMessage>,
    pub(super) temperature: f32,
}

#[derive(Debug, Serialize)]
pub(super) struct OpenAiCompatibleMessage {
    pub(super) role: String,
    pub(super) content: String,
}

#[derive(Clone, Copy)]
pub(super) enum ProviderAuth<'a> {
    Bearer(&'a str),
    Header(&'a str, &'a str),
}

#[derive(Debug, Deserialize)]
pub(super) struct OpenAiCompatibleChatResponse {
    pub(super) choices: Vec<OpenAiCompatibleChoice>,
}

#[derive(Debug, Deserialize)]
pub(super) struct OpenAiCompatibleChoice {
    pub(super) message: OpenAiCompatibleResponseMessage,
}

#[derive(Debug, Deserialize)]
pub(super) struct OpenAiCompatibleResponseMessage {
    pub(super) content: serde_json::Value,
}

impl OpenAiCompatibleResponseMessage {
    pub(super) fn content_as_text(&self) -> Option<String> {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AiAuditModelOutput {
    pub(super) risk_level: String,
    pub(super) headline: String,
    #[serde(default)]
    pub(super) executive_summary: Vec<String>,
    #[serde(default)]
    pub(super) findings: Vec<AiAuditModelFinding>,
    #[serde(default)]
    pub(super) recommendations: Vec<AiAuditModelRecommendation>,
    #[serde(default)]
    pub(super) suggested_local_rules: Vec<AiAuditModelSuggestedRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AiAuditModelFinding {
    pub(super) key: String,
    pub(super) severity: String,
    pub(super) title: String,
    pub(super) detail: String,
    #[serde(default)]
    pub(super) evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AiAuditModelRecommendation {
    pub(super) key: String,
    pub(super) priority: String,
    pub(super) title: String,
    pub(super) action: String,
    pub(super) rationale: String,
    #[serde(default)]
    pub(super) action_type: String,
    #[serde(default)]
    pub(super) rule_suggestion_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct AiAuditModelSuggestedRule {
    pub(super) key: String,
    pub(super) title: String,
    #[serde(default)]
    pub(super) policy_type: String,
    pub(super) layer: String,
    #[serde(default)]
    pub(super) scope_type: String,
    #[serde(default)]
    pub(super) scope_value: String,
    pub(super) target: String,
    #[serde(default)]
    pub(super) action: String,
    pub(super) operator: String,
    pub(super) suggested_value: String,
    #[serde(default)]
    pub(super) ttl_secs: u64,
    #[serde(default)]
    pub(super) auto_apply: bool,
    pub(super) rationale: String,
}
