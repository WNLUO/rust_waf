use axum::extract::Multipart;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use super::presets::builtin_action_idea_presets;
use super::preview::{
    action_idea_asset_relative_path, build_action_idea_response, decode_gzip_payload,
    ACTION_IDEA_MAX_DECOMPRESSED_BYTES,
};
use super::*;

pub(crate) async fn list_action_idea_presets_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<ActionIdeaPresetsResponse>> {
    let store = sqlite_store(&state)?;
    let overrides = store
        .list_action_idea_overrides()
        .await
        .map_err(ApiError::internal)?;
    let overrides_by_id: HashMap<_, _> = overrides
        .into_iter()
        .map(|entry| (entry.idea_id.clone(), entry))
        .collect();

    let ideas: Vec<_> = builtin_action_idea_presets()
        .into_iter()
        .map(|builtin| build_action_idea_response(&builtin, overrides_by_id.get(builtin.id)))
        .collect();

    Ok(Json(ActionIdeaPresetsResponse {
        total: ideas.len() as u32,
        ideas,
    }))
}

pub(crate) async fn update_action_idea_preset_handler(
    State(state): State<ApiState>,
    Path(idea_id): Path<String>,
    ExtractJson(payload): ExtractJson<UpdateActionIdeaPresetRequest>,
) -> ApiResult<Json<ActionIdeaPresetResponse>> {
    let builtin = builtin_action_idea_presets()
        .into_iter()
        .find(|item| item.id == idea_id)
        .ok_or_else(|| ApiError::not_found(format!("Action idea '{}' not found", idea_id)))?;

    let title = payload.title.trim().to_string();
    if title.is_empty() {
        return Err(ApiError::bad_request("动作名称不能为空".to_string()));
    }
    if !(100..=599).contains(&payload.status_code) {
        return Err(ApiError::bad_request(
            "状态码必须在 100 到 599 之间".to_string(),
        ));
    }
    let content_type = payload.content_type.trim().to_string();
    if content_type.is_empty() {
        return Err(ApiError::bad_request("内容类型不能为空".to_string()));
    }

    let response_content = payload.response_content.trim().to_string();
    if !builtin.requires_upload && response_content.is_empty() {
        return Err(ApiError::bad_request("原始内容不能为空".to_string()));
    }

    let store = sqlite_store(&state)?;
    let existing_override = store
        .list_action_idea_overrides()
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|entry| entry.idea_id == idea_id);
    store
        .upsert_action_idea_override(&crate::storage::ActionIdeaOverrideUpsert {
            idea_id: idea_id.clone(),
            title: Some(title.clone()),
            status_code: Some(i64::from(payload.status_code)),
            content_type: Some(content_type.clone()),
            response_content: if builtin.requires_upload {
                existing_override
                    .as_ref()
                    .and_then(|entry| entry.response_content.clone())
            } else {
                Some(payload.response_content)
            },
            body_file_path: existing_override
                .as_ref()
                .and_then(|entry| entry.body_file_path.clone()),
            uploaded_file_name: existing_override
                .as_ref()
                .and_then(|entry| entry.uploaded_file_name.clone()),
        })
        .await
        .map_err(ApiError::internal)?;

    let overrides = store
        .list_action_idea_overrides()
        .await
        .map_err(ApiError::internal)?;
    let updated_entry = overrides
        .into_iter()
        .find(|entry| entry.idea_id == idea_id)
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("动作方案覆盖写入后未找到记录")))?;

    Ok(Json(build_action_idea_response(
        &builtin,
        Some(&updated_entry),
    )))
}

pub(crate) async fn upload_action_idea_gzip_handler(
    State(state): State<ApiState>,
    Path(idea_id): Path<String>,
    mut multipart: Multipart,
) -> ApiResult<Json<ActionIdeaUploadResponse>> {
    let builtin = builtin_action_idea_presets()
        .into_iter()
        .find(|item| item.id == idea_id)
        .ok_or_else(|| ApiError::not_found(format!("Action idea '{}' not found", idea_id)))?;
    if !builtin.requires_upload {
        return Err(ApiError::bad_request(
            "这个动作不支持上传 gzip 文件".to_string(),
        ));
    }

    let mut upload_bytes = None;
    let mut upload_name = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| ApiError::bad_request(format!("读取上传字段失败: {}", err)))?
    {
        if field.name() != Some("file") {
            continue;
        }
        upload_name = field.file_name().map(|value| value.to_string());
        let bytes = field
            .bytes()
            .await
            .map_err(|err| ApiError::bad_request(format!("读取上传文件失败: {}", err)))?;
        upload_bytes = Some(bytes);
    }

    let upload_bytes =
        upload_bytes.ok_or_else(|| ApiError::bad_request("缺少 gzip 文件".to_string()))?;
    if upload_bytes.is_empty() {
        return Err(ApiError::bad_request("gzip 文件不能为空".to_string()));
    }
    if upload_bytes.len() > 8 * 1024 * 1024 {
        return Err(ApiError::bad_request("gzip 文件不能超过 8MB".to_string()));
    }
    if upload_bytes.len() < 2 || upload_bytes[0] != 0x1f || upload_bytes[1] != 0x8b {
        return Err(ApiError::bad_request(
            "上传文件不是有效的 gzip 文件".to_string(),
        ));
    }
    decode_gzip_payload(upload_bytes.as_ref(), ACTION_IDEA_MAX_DECOMPRESSED_BYTES)
        .map_err(ApiError::bad_request)?;

    let relative_path = action_idea_asset_relative_path(&idea_id);
    let absolute_path = crate::rules::resolve_response_file_path(&relative_path)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    let parent = absolute_path
        .parent()
        .map(PathBuf::from)
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("无法确定 gzip 资产目录")))?;
    fs::create_dir_all(&parent).map_err(ApiError::internal)?;
    fs::write(&absolute_path, upload_bytes.as_ref()).map_err(ApiError::internal)?;

    let store = sqlite_store(&state)?;
    let existing_override = store
        .list_action_idea_overrides()
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|entry| entry.idea_id == idea_id);

    store
        .upsert_action_idea_override(&crate::storage::ActionIdeaOverrideUpsert {
            idea_id: idea_id.clone(),
            title: existing_override
                .as_ref()
                .and_then(|entry| entry.title.clone()),
            status_code: existing_override
                .as_ref()
                .and_then(|entry| entry.status_code),
            content_type: existing_override
                .as_ref()
                .and_then(|entry| entry.content_type.clone()),
            response_content: existing_override
                .as_ref()
                .and_then(|entry| entry.response_content.clone()),
            body_file_path: Some(relative_path),
            uploaded_file_name: Some(
                upload_name
                    .filter(|name| !name.trim().is_empty())
                    .unwrap_or_else(|| "payload.gz".to_string()),
            ),
        })
        .await
        .map_err(ApiError::internal)?;

    let updated_override = store
        .list_action_idea_overrides()
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .find(|entry| entry.idea_id == idea_id)
        .ok_or_else(|| ApiError::internal(anyhow::anyhow!("上传 gzip 后未找到动作方案记录")))?;

    Ok(Json(ActionIdeaUploadResponse {
        idea: build_action_idea_response(&builtin, Some(&updated_override)),
    }))
}
