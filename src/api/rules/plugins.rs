use super::*;
use axum::extract::Multipart;

pub(super) async fn list_rule_action_plugins_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<RuleActionPluginsResponse>> {
    let store = sqlite_store(&state)?;
    let plugins = store
        .list_rule_action_plugins()
        .await
        .map_err(ApiError::internal)?;
    let plugins: Vec<_> = plugins.into_iter().map(Into::into).collect();

    Ok(Json(RuleActionPluginsResponse {
        total: plugins.len() as u32,
        plugins,
    }))
}

pub(super) async fn list_rule_action_templates_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<RuleActionTemplatesResponse>> {
    let store = sqlite_store(&state)?;
    let templates = store
        .list_rule_action_templates()
        .await
        .map_err(ApiError::internal)?;
    let templates: Result<Vec<_>, _> = templates
        .into_iter()
        .map(RuleActionTemplateResponse::try_from)
        .collect();
    let templates = templates.map_err(ApiError::internal)?;

    Ok(Json(RuleActionTemplatesResponse {
        total: templates.len() as u32,
        templates,
    }))
}

pub(super) async fn preview_rule_action_template_handler(
    State(state): State<ApiState>,
    Path(template_id): Path<String>,
) -> ApiResult<Json<RuleActionTemplatePreviewResponse>> {
    let store = sqlite_store(&state)?;
    let entry = store
        .get_rule_action_template(&template_id)
        .await
        .map_err(ApiError::internal)?;
    let entry = entry.ok_or_else(|| {
        ApiError::not_found(format!("Rule action template '{}' not found", template_id))
    })?;
    let response_template =
        serde_json::from_str::<crate::config::RuleResponseTemplate>(&entry.response_template_json)
            .map_err(ApiError::internal)?;

    let (body_preview, truncated) =
        read_rule_action_template_preview(&response_template).map_err(ApiError::internal)?;

    Ok(Json(RuleActionTemplatePreviewResponse {
        template_id: entry.template_id,
        name: entry.name,
        content_type: response_template.content_type,
        status_code: response_template.status_code,
        gzip: response_template.gzip,
        body_source: match response_template.body_source {
            crate::config::RuleResponseBodySource::InlineText => "inline_text".to_string(),
            crate::config::RuleResponseBodySource::File => "file".to_string(),
        },
        body_preview,
        truncated,
    }))
}

pub(super) async fn install_rule_action_plugin_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<InstallRuleActionPluginRequest>,
) -> ApiResult<(StatusCode, Json<WriteStatusResponse>)> {
    let store = sqlite_store(&state)?;
    install_rule_action_plugin_from_url(store, &payload.package_url, payload.sha256.as_deref())
        .await
        .map_err(ApiError::bad_request)?;

    Ok((
        StatusCode::CREATED,
        Json(WriteStatusResponse {
            success: true,
            message: "规则模板插件已安装".to_string(),
        }),
    ))
}

pub(super) async fn upload_rule_action_plugin_handler(
    State(state): State<ApiState>,
    mut multipart: Multipart,
) -> ApiResult<(StatusCode, Json<WriteStatusResponse>)> {
    let store = sqlite_store(&state)?;
    let mut package_bytes = None;
    let mut expected_sha256 = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| ApiError::bad_request(format!("读取上传字段失败: {}", err)))?
    {
        match field.name() {
            Some("package") => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|err| ApiError::bad_request(format!("读取上传文件失败: {}", err)))?;
                package_bytes = Some(bytes);
            }
            Some("sha256") => {
                let value = field
                    .text()
                    .await
                    .map_err(|err| ApiError::bad_request(format!("读取校验字段失败: {}", err)))?;
                expected_sha256 = Some(value);
            }
            _ => {}
        }
    }

    let package_bytes =
        package_bytes.ok_or_else(|| ApiError::bad_request("缺少插件 zip 文件".to_string()))?;
    install_rule_action_plugin_from_bytes(
        store,
        package_bytes.as_ref(),
        expected_sha256.as_deref(),
    )
    .await
    .map_err(ApiError::bad_request)?;

    Ok((
        StatusCode::CREATED,
        Json(WriteStatusResponse {
            success: true,
            message: "规则模板插件已上传并安装".to_string(),
        }),
    ))
}

pub(super) async fn update_rule_action_plugin_handler(
    State(state): State<ApiState>,
    Path(plugin_id): Path<String>,
    ExtractJson(payload): ExtractJson<UpdateRuleActionPluginRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let updated = store
        .set_rule_action_plugin_enabled(&plugin_id, payload.enabled)
        .await
        .map_err(ApiError::internal)?;

    if !updated {
        return Err(ApiError::not_found(format!(
            "Plugin '{}' not found",
            plugin_id
        )));
    }

    Ok(Json(WriteStatusResponse {
        success: true,
        message: if payload.enabled {
            "规则模板插件已启用".to_string()
        } else {
            "规则模板插件已停用，并已停用相关规则".to_string()
        },
    }))
}

pub(super) async fn delete_rule_action_plugin_handler(
    State(state): State<ApiState>,
    Path(plugin_id): Path<String>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = sqlite_store(&state)?;
    let deleted = store
        .delete_rule_action_plugin(&plugin_id)
        .await
        .map_err(ApiError::internal)?;

    if !deleted {
        return Err(ApiError::not_found(format!(
            "Plugin '{}' not found",
            plugin_id
        )));
    }

    Ok(Json(WriteStatusResponse {
        success: true,
        message: "规则模板插件已卸载，相关规则已停用".to_string(),
    }))
}

fn read_rule_action_template_preview(
    template: &crate::config::RuleResponseTemplate,
) -> anyhow::Result<(String, bool)> {
    const PREVIEW_LIMIT: usize = 16 * 1024;

    let body = match template.body_source {
        crate::config::RuleResponseBodySource::InlineText => template.body_text.clone(),
        crate::config::RuleResponseBodySource::File => {
            let path = crate::rules::resolve_response_file_path(template.body_file_path.trim())?;
            String::from_utf8_lossy(&std::fs::read(path)?).into_owned()
        }
    };

    let truncated = body.len() > PREVIEW_LIMIT;
    let preview = if truncated {
        body.chars().take(PREVIEW_LIMIT).collect::<String>()
    } else {
        body
    };

    Ok((preview, truncated))
}

