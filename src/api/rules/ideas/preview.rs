use flate2::read::MultiGzDecoder;
use std::fs;
use std::io::Read;

use super::presets::{
    default_redirect_target, is_random_error_action_idea, is_redirect_action_idea,
    is_tarpit_action_idea, parse_random_error_idea_config, parse_tarpit_idea_config,
    serialize_random_error_idea_config, serialize_tarpit_idea_config, BuiltinActionIdeaPreset,
    UploadedBodyPreview,
};
use super::*;

pub(super) const ACTION_IDEA_MAX_DECOMPRESSED_BYTES: usize = 16 * 1024 * 1024;
const ACTION_IDEA_PREVIEW_LIMIT: usize = 16 * 1024;

fn action_idea_headers(
    builtin: &BuiltinActionIdeaPreset,
    response_content: &str,
) -> Vec<RuleResponseHeaderPayload> {
    let mut headers = vec![RuleResponseHeaderPayload {
        key: "cache-control".to_string(),
        value: "no-store".to_string(),
    }];
    if builtin.id == "maintenance-page" {
        headers.push(RuleResponseHeaderPayload {
            key: "retry-after".to_string(),
            value: "120".to_string(),
        });
    }
    if builtin.id == "gzip-response" {
        headers.push(RuleResponseHeaderPayload {
            key: "content-encoding".to_string(),
            value: "gzip".to_string(),
        });
    }
    if is_tarpit_action_idea(builtin.id) {
        let config = parse_tarpit_idea_config(response_content);
        headers.push(RuleResponseHeaderPayload {
            key: "x-rust-waf-tarpit-bytes-per-chunk".to_string(),
            value: config.bytes_per_chunk.to_string(),
        });
        headers.push(RuleResponseHeaderPayload {
            key: "x-rust-waf-tarpit-interval-ms".to_string(),
            value: config.chunk_interval_ms.to_string(),
        });
    }
    if is_random_error_action_idea(builtin.id) {
        let config = parse_random_error_idea_config(response_content);
        headers.push(RuleResponseHeaderPayload {
            key: "x-rust-waf-random-statuses".to_string(),
            value: config
                .failure_statuses
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(","),
        });
    }
    if is_redirect_action_idea(builtin.id) {
        let target = {
            let trimmed = response_content.trim();
            if trimmed.is_empty() {
                default_redirect_target()
            } else {
                trimmed
            }
        };
        headers.push(RuleResponseHeaderPayload {
            key: "location".to_string(),
            value: target.to_string(),
        });
    }
    headers
}

pub(super) fn action_idea_asset_relative_path(idea_id: &str) -> String {
    format!("action_ideas/{}/payload.gz", idea_id)
}

fn action_idea_file_exists(relative_path: &str) -> bool {
    crate::rules::resolve_response_file_path(relative_path)
        .ok()
        .and_then(|path| fs::metadata(path).ok())
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

pub(super) fn decode_gzip_payload(
    bytes: &[u8],
    max_output_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut reader = MultiGzDecoder::new(std::io::Cursor::new(bytes))
        .take(u64::try_from(max_output_bytes.saturating_add(1)).unwrap_or(u64::MAX));
    let mut decoded = Vec::new();
    reader
        .read_to_end(&mut decoded)
        .map_err(|err| format!("gzip 解压失败: {}", err))?;
    if decoded.len() > max_output_bytes {
        return Err(format!(
            "gzip 解压后不能超过 {}MB",
            max_output_bytes / 1024 / 1024
        ));
    }
    Ok(decoded)
}

fn is_text_like_content_type(content_type: &str) -> bool {
    let lowered = content_type.trim().to_ascii_lowercase();
    lowered.starts_with("text/")
        || lowered.contains("json")
        || lowered.contains("xml")
        || lowered.contains("javascript")
        || lowered.contains("ecmascript")
        || lowered.contains("html")
        || lowered.contains("svg")
        || lowered.contains("css")
}

fn preview_uploaded_body(relative_path: &str, content_type: &str) -> UploadedBodyPreview {
    let path = match crate::rules::resolve_response_file_path(relative_path) {
        Ok(path) => path,
        Err(err) => {
            return UploadedBodyPreview {
                body_preview: None,
                body_preview_notice: Some(format!("无法读取 gzip 文件: {}", err)),
                truncated: false,
            };
        }
    };
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) => {
            return UploadedBodyPreview {
                body_preview: None,
                body_preview_notice: Some(format!("无法读取 gzip 文件: {}", err)),
                truncated: false,
            };
        }
    };
    let decoded = match decode_gzip_payload(&bytes, ACTION_IDEA_MAX_DECOMPRESSED_BYTES) {
        Ok(decoded) => decoded,
        Err(err) => {
            return UploadedBodyPreview {
                body_preview: None,
                body_preview_notice: Some(err),
                truncated: false,
            };
        }
    };
    let text = match String::from_utf8(decoded) {
        Ok(text) => text,
        Err(_) => {
            return UploadedBodyPreview {
                body_preview: None,
                body_preview_notice: Some(if is_text_like_content_type(content_type) {
                    "gzip 解压成功，但内容不是有效的 UTF-8 文本，当前无法直接预览".to_string()
                } else {
                    "gzip 解压成功，但内容不是可直接预览的文本".to_string()
                }),
                truncated: false,
            };
        }
    };

    if !is_text_like_content_type(content_type) && text.contains('\u{0}') {
        return UploadedBodyPreview {
            body_preview: None,
            body_preview_notice: Some("gzip 解压成功，但内容不是可直接预览的文本".to_string()),
            truncated: false,
        };
    }

    let truncated = text.chars().count() > ACTION_IDEA_PREVIEW_LIMIT;
    let body_preview = if truncated {
        text.chars()
            .take(ACTION_IDEA_PREVIEW_LIMIT)
            .collect::<String>()
    } else {
        text
    };

    UploadedBodyPreview {
        body_preview: Some(body_preview),
        body_preview_notice: None,
        truncated,
    }
}

pub(super) fn build_action_idea_response(
    builtin: &BuiltinActionIdeaPreset,
    override_entry: Option<&crate::storage::ActionIdeaOverrideEntry>,
) -> ActionIdeaPresetResponse {
    let title = override_entry
        .and_then(|entry| entry.title.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| builtin.title.to_string());
    let response_content = if builtin.requires_upload {
        String::new()
    } else {
        override_entry
            .and_then(|entry| entry.response_content.clone())
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| builtin.response_content.to_string())
    };
    let response_content = if is_redirect_action_idea(builtin.id) {
        let trimmed = response_content.trim();
        if trimmed.is_empty() {
            default_redirect_target().to_string()
        } else {
            trimmed.to_string()
        }
    } else if is_tarpit_action_idea(builtin.id) {
        serialize_tarpit_idea_config(&parse_tarpit_idea_config(&response_content))
    } else if is_random_error_action_idea(builtin.id) {
        serialize_random_error_idea_config(&parse_random_error_idea_config(&response_content))
    } else {
        response_content
    };
    let status_code = override_entry
        .and_then(|entry| entry.status_code)
        .and_then(|value| u16::try_from(value).ok())
        .unwrap_or(builtin.status_code);
    let content_type = override_entry
        .and_then(|entry| entry.content_type.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| builtin.content_type.to_string());
    let runtime_body_file_path = if builtin.requires_upload {
        override_entry
            .and_then(|entry| entry.body_file_path.clone())
            .unwrap_or_else(|| action_idea_asset_relative_path(builtin.id))
    } else {
        String::new()
    };
    let uploaded_file_ready =
        builtin.requires_upload && action_idea_file_exists(&runtime_body_file_path);
    let uploaded_file_name = override_entry
        .and_then(|entry| entry.uploaded_file_name.clone())
        .or_else(|| {
            if uploaded_file_ready {
                Some("payload.gz".to_string())
            } else {
                None
            }
        });
    let uploaded_body_preview = if uploaded_file_ready {
        preview_uploaded_body(&runtime_body_file_path, &content_type)
    } else {
        UploadedBodyPreview::default()
    };

    ActionIdeaPresetResponse {
        id: builtin.id.to_string(),
        title: title.clone(),
        mood: builtin.mood.to_string(),
        summary: builtin.summary.to_string(),
        mechanism: builtin.mechanism.to_string(),
        performance: builtin.performance.to_string(),
        fallback_path: builtin.fallback_path.to_string(),
        plugin_id: builtin.plugin_id.to_string(),
        file_name: builtin.file_name.to_string(),
        response_file_path: builtin.response_file_path.to_string(),
        plugin_name: builtin.plugin_name.to_string(),
        plugin_description: builtin.plugin_description.to_string(),
        template_local_id: builtin.template_local_id.to_string(),
        template_name: title,
        template_description: builtin.template_description.to_string(),
        pattern: builtin.pattern.to_string(),
        severity: builtin.severity.to_string(),
        content_type,
        status_code,
        gzip: builtin.gzip,
        body_source: builtin.body_source.to_string(),
        runtime_body_file_path,
        headers: action_idea_headers(builtin, &response_content),
        response_content,
        requires_upload: builtin.requires_upload,
        uploaded_file_name,
        uploaded_file_ready,
        uploaded_body_preview: uploaded_body_preview.body_preview,
        uploaded_body_preview_notice: uploaded_body_preview.body_preview_notice,
        uploaded_body_truncated: uploaded_body_preview.truncated,
        has_overrides: override_entry.is_some(),
        updated_at: override_entry
            .map(|entry| entry.updated_at)
            .unwrap_or_default(),
    }
}
