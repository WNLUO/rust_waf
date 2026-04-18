use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub(in crate::api::rules::ideas) struct BuiltinActionIdeaPreset {
    pub(in crate::api::rules::ideas) id: &'static str,
    pub(in crate::api::rules::ideas) title: &'static str,
    pub(in crate::api::rules::ideas) mood: &'static str,
    pub(in crate::api::rules::ideas) summary: &'static str,
    pub(in crate::api::rules::ideas) mechanism: &'static str,
    pub(in crate::api::rules::ideas) performance: &'static str,
    pub(in crate::api::rules::ideas) fallback_path: &'static str,
    pub(in crate::api::rules::ideas) plugin_id: &'static str,
    pub(in crate::api::rules::ideas) file_name: &'static str,
    pub(in crate::api::rules::ideas) response_file_path: &'static str,
    pub(in crate::api::rules::ideas) plugin_name: &'static str,
    pub(in crate::api::rules::ideas) plugin_description: &'static str,
    pub(in crate::api::rules::ideas) template_local_id: &'static str,
    pub(in crate::api::rules::ideas) template_description: &'static str,
    pub(in crate::api::rules::ideas) pattern: &'static str,
    pub(in crate::api::rules::ideas) severity: &'static str,
    pub(in crate::api::rules::ideas) content_type: &'static str,
    pub(in crate::api::rules::ideas) status_code: u16,
    pub(in crate::api::rules::ideas) gzip: bool,
    pub(in crate::api::rules::ideas) body_source: &'static str,
    pub(in crate::api::rules::ideas) response_content: &'static str,
    pub(in crate::api::rules::ideas) requires_upload: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::api::rules::ideas) struct TarpitIdeaConfig {
    pub(in crate::api::rules::ideas) bytes_per_chunk: usize,
    pub(in crate::api::rules::ideas) chunk_interval_ms: u64,
    pub(in crate::api::rules::ideas) body_text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in crate::api::rules::ideas) struct RandomErrorIdeaConfig {
    pub(in crate::api::rules::ideas) failure_statuses: Vec<u16>,
    pub(in crate::api::rules::ideas) success_rate_percent: u8,
    pub(in crate::api::rules::ideas) success_body: String,
    pub(in crate::api::rules::ideas) failure_body: String,
}

#[derive(Debug, Clone, Default)]
pub(in crate::api::rules::ideas) struct UploadedBodyPreview {
    pub(in crate::api::rules::ideas) body_preview: Option<String>,
    pub(in crate::api::rules::ideas) body_preview_notice: Option<String>,
    pub(in crate::api::rules::ideas) truncated: bool,
}

pub(in crate::api::rules::ideas) fn is_redirect_action_idea(idea_id: &str) -> bool {
    idea_id == "redirect-302"
}

pub(in crate::api::rules::ideas) fn is_tarpit_action_idea(idea_id: &str) -> bool {
    idea_id == "smart-tarpit"
}

pub(in crate::api::rules::ideas) fn is_random_error_action_idea(idea_id: &str) -> bool {
    idea_id == "random-error-system"
}

pub(in crate::api::rules::ideas) fn default_redirect_target() -> &'static str {
    "https://www.war.gov/"
}

fn default_tarpit_idea_config() -> TarpitIdeaConfig {
    TarpitIdeaConfig {
        bytes_per_chunk: 1,
        chunk_interval_ms: 1000,
        body_text: "processing request, please wait...".to_string(),
    }
}

pub(in crate::api::rules::ideas) fn parse_tarpit_idea_config(value: &str) -> TarpitIdeaConfig {
    let parsed = serde_json::from_str::<TarpitIdeaConfig>(value).ok();
    let default = default_tarpit_idea_config();
    let Some(parsed) = parsed else {
        return if value.trim().is_empty() {
            default
        } else {
            TarpitIdeaConfig {
                body_text: value.trim().to_string(),
                ..default
            }
        };
    };

    TarpitIdeaConfig {
        bytes_per_chunk: parsed.bytes_per_chunk.max(1),
        chunk_interval_ms: parsed.chunk_interval_ms.max(1),
        body_text: if parsed.body_text.trim().is_empty() {
            default.body_text
        } else {
            parsed.body_text.trim().to_string()
        },
    }
}

pub(in crate::api::rules::ideas) fn serialize_tarpit_idea_config(
    config: &TarpitIdeaConfig,
) -> String {
    serde_json::to_string(config).unwrap_or_else(|_| {
        serde_json::json!({
            "bytes_per_chunk": config.bytes_per_chunk,
            "chunk_interval_ms": config.chunk_interval_ms,
            "body_text": config.body_text,
        })
        .to_string()
    })
}

fn default_random_error_idea_config() -> RandomErrorIdeaConfig {
    RandomErrorIdeaConfig {
        failure_statuses: vec![500, 502, 403],
        success_rate_percent: 25,
        success_body: "request completed successfully".to_string(),
        failure_body: "upstream system unstable, retry later".to_string(),
    }
}

pub(in crate::api::rules::ideas) fn parse_random_error_idea_config(
    value: &str,
) -> RandomErrorIdeaConfig {
    let parsed = serde_json::from_str::<RandomErrorIdeaConfig>(value).ok();
    let default = default_random_error_idea_config();
    let Some(parsed) = parsed else {
        return if value.trim().is_empty() {
            default
        } else {
            RandomErrorIdeaConfig {
                failure_body: value.trim().to_string(),
                ..default
            }
        };
    };

    let failure_statuses = parsed
        .failure_statuses
        .into_iter()
        .filter(|status| (100..=599).contains(status) && *status != 200)
        .collect::<Vec<_>>();

    RandomErrorIdeaConfig {
        failure_statuses: if failure_statuses.is_empty() {
            default.failure_statuses
        } else {
            failure_statuses
        },
        success_rate_percent: parsed.success_rate_percent.min(100),
        success_body: if parsed.success_body.trim().is_empty() {
            default.success_body
        } else {
            parsed.success_body.trim().to_string()
        },
        failure_body: if parsed.failure_body.trim().is_empty() {
            default.failure_body
        } else {
            parsed.failure_body.trim().to_string()
        },
    }
}

pub(in crate::api::rules::ideas) fn serialize_random_error_idea_config(
    config: &RandomErrorIdeaConfig,
) -> String {
    serde_json::to_string(config).unwrap_or_else(|_| {
        serde_json::json!({
            "failure_statuses": config.failure_statuses,
            "success_rate_percent": config.success_rate_percent,
            "success_body": config.success_body,
            "failure_body": config.failure_body,
        })
        .to_string()
    })
}
