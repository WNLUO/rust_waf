use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct RulesListResponse {
    pub(crate) rules: Vec<RuleResponse>,
}

#[derive(Debug, Serialize)]
pub struct RuleResponse {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) enabled: bool,
    pub(crate) layer: String,
    pub(crate) pattern: String,
    pub(crate) action: String,
    pub(crate) severity: String,
    pub(crate) plugin_template_id: Option<String>,
    pub(crate) response_template: Option<RuleResponseTemplatePayload>,
}

#[derive(Debug, Deserialize)]
pub struct RuleUpsertRequest {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) enabled: bool,
    pub(crate) layer: String,
    pub(crate) pattern: String,
    pub(crate) action: String,
    pub(crate) severity: String,
    pub(crate) plugin_template_id: Option<String>,
    pub(crate) response_template: Option<RuleResponseTemplatePayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResponseTemplatePayload {
    pub(crate) status_code: u16,
    pub(crate) content_type: String,
    pub(crate) body_source: String,
    pub(crate) gzip: bool,
    pub(crate) body_text: String,
    pub(crate) body_file_path: String,
    #[serde(default)]
    pub(crate) headers: Vec<RuleResponseHeaderPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResponseHeaderPayload {
    pub(crate) key: String,
    pub(crate) value: String,
}

#[derive(Debug, Serialize)]
pub struct RuleActionPluginsResponse {
    pub(crate) total: u32,
    pub(crate) plugins: Vec<RuleActionPluginResponse>,
}

#[derive(Debug, Serialize)]
pub struct RuleActionPluginResponse {
    pub(crate) plugin_id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) description: String,
    pub(crate) enabled: bool,
    pub(crate) installed_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct RuleActionTemplatesResponse {
    pub(crate) total: u32,
    pub(crate) templates: Vec<RuleActionTemplateResponse>,
}

#[derive(Debug, Serialize)]
pub struct RuleActionTemplateResponse {
    pub(crate) template_id: String,
    pub(crate) plugin_id: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) layer: String,
    pub(crate) action: String,
    pub(crate) pattern: String,
    pub(crate) severity: String,
    pub(crate) response_template: RuleResponseTemplatePayload,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct RuleActionTemplatePreviewResponse {
    pub(crate) template_id: String,
    pub(crate) name: String,
    pub(crate) content_type: String,
    pub(crate) status_code: u16,
    pub(crate) gzip: bool,
    pub(crate) body_source: String,
    pub(crate) body_preview: String,
    pub(crate) truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct ActionIdeaPresetsResponse {
    pub(crate) total: u32,
    pub(crate) ideas: Vec<ActionIdeaPresetResponse>,
}

#[derive(Debug, Serialize)]
pub struct ActionIdeaPresetResponse {
    pub(crate) id: String,
    pub(crate) title: String,
    pub(crate) mood: String,
    pub(crate) summary: String,
    pub(crate) mechanism: String,
    pub(crate) performance: String,
    pub(crate) fallback_path: String,
    pub(crate) plugin_id: String,
    pub(crate) file_name: String,
    pub(crate) response_file_path: String,
    pub(crate) plugin_name: String,
    pub(crate) plugin_description: String,
    pub(crate) template_local_id: String,
    pub(crate) template_name: String,
    pub(crate) template_description: String,
    pub(crate) pattern: String,
    pub(crate) severity: String,
    pub(crate) content_type: String,
    pub(crate) status_code: u16,
    pub(crate) gzip: bool,
    pub(crate) body_source: String,
    pub(crate) runtime_body_file_path: String,
    pub(crate) headers: Vec<RuleResponseHeaderPayload>,
    pub(crate) response_content: String,
    pub(crate) requires_upload: bool,
    pub(crate) uploaded_file_name: Option<String>,
    pub(crate) uploaded_file_ready: bool,
    pub(crate) uploaded_body_preview: Option<String>,
    pub(crate) uploaded_body_preview_notice: Option<String>,
    pub(crate) uploaded_body_truncated: bool,
    pub(crate) has_overrides: bool,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct UpdateActionIdeaPresetRequest {
    pub(crate) title: String,
    pub(crate) status_code: u16,
    pub(crate) content_type: String,
    pub(crate) response_content: String,
}

#[derive(Debug, Serialize)]
pub struct ActionIdeaUploadResponse {
    pub(crate) idea: ActionIdeaPresetResponse,
}

#[derive(Debug, Deserialize)]
pub struct InstallRuleActionPluginRequest {
    pub(crate) package_url: String,
    #[serde(default)]
    pub(crate) sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRuleActionPluginRequest {
    pub(crate) enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct WriteStatusResponse {
    pub(crate) success: bool,
    pub(crate) message: String,
}
