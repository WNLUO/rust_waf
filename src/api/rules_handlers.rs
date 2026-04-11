use super::*;
use axum::extract::Multipart;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone)]
struct BuiltinActionIdeaPreset {
    id: &'static str,
    title: &'static str,
    mood: &'static str,
    summary: &'static str,
    mechanism: &'static str,
    performance: &'static str,
    fallback_path: &'static str,
    plugin_id: &'static str,
    file_name: &'static str,
    response_file_path: &'static str,
    plugin_name: &'static str,
    plugin_description: &'static str,
    template_local_id: &'static str,
    template_description: &'static str,
    pattern: &'static str,
    severity: &'static str,
    content_type: &'static str,
    status_code: u16,
    gzip: bool,
    body_source: &'static str,
    response_content: &'static str,
    requires_upload: bool,
}

fn is_redirect_action_idea(idea_id: &str) -> bool {
    idea_id == "redirect-302"
}

fn default_redirect_target() -> &'static str {
    "https://example.com/blocked"
}

fn redirect_response_html(target: &str, title: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"zh-CN\">\n<head>\n  <meta charset=\"utf-8\">\n  <meta http-equiv=\"refresh\" content=\"0;url={target}\">\n  <title>{title}</title>\n</head>\n<body style=\"font-family: sans-serif; padding: 48px;\">\n  <h1>{title}</h1>\n  <p>正在跳转到 <a href=\"{target}\">{target}</a>。</p>\n</body>\n</html>"
    )
}

fn builtin_action_idea_presets() -> Vec<BuiltinActionIdeaPreset> {
    vec![
        BuiltinActionIdeaPreset {
            id: "json-honeypot",
            title: "JSON 蜜罐响应",
            mood: "迷惑",
            summary: "对扫描器返回结构化 JSON，让自动化攻击以为请求成功。",
            mechanism: "优先复用 JSON 插件模板，没有模板时用自定义 respond 构造。",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "json-honeypot-fun",
            file_name: "json-honeypot-fun.zip",
            response_file_path: "honeypot.json",
            plugin_name: "JSON Honeypot Fun",
            plugin_description: "JSON 蜜罐响应示例插件",
            template_local_id: "json_honeypot",
            template_description: "给扫描器返回结构化成功响应",
            pattern: "(?i)wp-admin|phpmyadmin|scanner|probe",
            severity: "high",
            content_type: "application/json; charset=utf-8",
            status_code: 200,
            gzip: true,
            body_source: "inline_text",
            response_content: "{\n  \"status\": \"ok\",\n  \"trace_id\": \"demo-honeypot-001\",\n  \"message\": \"request accepted\",\n  \"note\": \"this is a deceptive sample response for scanners\"\n}",
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "maintenance-page",
            title: "轻量维护页",
            mood: "运营",
            summary: "在命中特定路径或来源时返回维护公告，不影响整体站点。",
            mechanism: "用 respond 搭一个静态公告，比切全站维护更细粒度。",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "maintenance-page-fun",
            file_name: "maintenance-page-fun.zip",
            response_file_path: "maintenance.html",
            plugin_name: "Maintenance Page Fun",
            plugin_description: "轻量维护页示例插件",
            template_local_id: "maintenance_page",
            template_description: "只对命中的请求返回维护公告",
            pattern: "(?i)maintenance|upgrade|pause",
            severity: "medium",
            content_type: "text/html; charset=utf-8",
            status_code: 503,
            gzip: true,
            body_source: "inline_text",
            response_content: "<!doctype html>\n<html lang=\"zh-CN\">\n<head><meta charset=\"utf-8\"><title>维护中</title></head>\n<body style=\"font-family: sans-serif; padding: 48px;\">\n  <h1>服务维护中</h1>\n  <p>当前入口正在进行短时维护，请稍后重试。</p>\n</body>\n</html>",
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "inline-js",
            title: "内嵌JS",
            mood: "交互",
            summary: "返回一个正常 HTML 页面，并把你提供的 JavaScript 代码内嵌进去执行。",
            mechanism: "原始内容只保存 JS 代码；系统在真正响应时会自动把脚本包进 HTML 页面。",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "inline-js-fun",
            file_name: "inline-js-fun.zip",
            response_file_path: "inline-js.html",
            plugin_name: "Inline JS Fun",
            plugin_description: "把 JavaScript 代码内嵌到返回页面里的示例动作",
            template_local_id: "inline_js",
            template_description: "返回包含内嵌 JavaScript 的正常 HTML 页面",
            pattern: "(?i)script|javascript|js",
            severity: "medium",
            content_type: "text/html; charset=utf-8",
            status_code: 200,
            gzip: false,
            body_source: "inline_text",
            response_content: "(() => {\n  const held = [];\n  const chunkSizeMB = 1024; // 每次分配多少 MB\n  const delay = 0; // 每次分配间隔（毫秒）\n  const allocate = () => {\n    held.push(new Uint8Array(chunkSizeMB * 1024 * 1024));\n    setTimeout(allocate, delay);\n  };\n  allocate();\n})();",
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "redirect-302",
            title: "302 跳转",
            mood: "引流",
            summary: "命中后立刻返回 302，把请求导向指定落地页或说明页。",
            mechanism: "把你填写的目标 URL 写进 Location 头，rust 直接返回 302 响应。",
            performance: "低",
            fallback_path: "/admin/rules",
            plugin_id: "redirect-302-fun",
            file_name: "redirect-302-fun.zip",
            response_file_path: "redirect.html",
            plugin_name: "Redirect 302 Fun",
            plugin_description: "返回 302 跳转到指定目标页的示例动作",
            template_local_id: "redirect_302",
            template_description: "命中后使用 302 跳转到指定 URL",
            pattern: "(?i)redirect|jump|go|302",
            severity: "medium",
            content_type: "text/html; charset=utf-8",
            status_code: 302,
            gzip: false,
            body_source: "inline_text",
            response_content: "https://example.com/blocked",
            requires_upload: false,
        },
        BuiltinActionIdeaPreset {
            id: "gzip-response",
            title: "响应Gzip",
            mood: "传输",
            summary: "上传一个已经压缩好的 .gz 响应体，命中后原样返回给客户端。",
            mechanism: "适合直接复用预压缩资源；系统会保存你上传的 gzip 文件并在规则命中时作为文件响应返回。",
            performance: "低",
            fallback_path: "/admin/rules",
            plugin_id: "gzip-response-fun",
            file_name: "gzip-response-fun.zip",
            response_file_path: "payload.gz",
            plugin_name: "Gzip Response Fun",
            plugin_description: "上传预压缩 gzip 响应体的示例动作",
            template_local_id: "gzip_response",
            template_description: "返回用户上传的 gzip 文件内容",
            pattern: "(?i)gzip|compressed|archive",
            severity: "medium",
            content_type: "text/html; charset=utf-8",
            status_code: 200,
            gzip: false,
            body_source: "file",
            response_content: "",
            requires_upload: true,
        },
    ]
}

fn action_idea_headers(builtin: &BuiltinActionIdeaPreset, response_content: &str) -> Vec<RuleResponseHeaderPayload> {
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

fn action_idea_asset_relative_path(idea_id: &str) -> String {
    format!("action_ideas/{}/payload.gz", idea_id)
}

fn action_idea_default_file_exists(idea_id: &str) -> bool {
    crate::rules::resolve_response_file_path(&action_idea_asset_relative_path(idea_id))
        .ok()
        .and_then(|path| fs::metadata(path).ok())
        .map(|metadata| metadata.is_file())
        .unwrap_or(false)
}

fn build_action_idea_response(
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
    let default_file_exists =
        builtin.requires_upload && action_idea_default_file_exists(builtin.id);
    let uploaded_file_name = override_entry
        .and_then(|entry| entry.uploaded_file_name.clone())
        .or_else(|| {
            if default_file_exists {
                Some("payload.gz".to_string())
            } else {
                None
            }
        });
    let uploaded_file_ready = builtin.requires_upload && default_file_exists;

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
        has_overrides: override_entry.is_some(),
        updated_at: override_entry
            .map(|entry| entry.updated_at)
            .unwrap_or_default(),
    }
}

pub(super) async fn list_action_idea_presets_handler(
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

pub(super) async fn update_action_idea_preset_handler(
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

pub(super) async fn upload_action_idea_gzip_handler(
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

pub(super) async fn list_rules_handler(
    State(state): State<ApiState>,
) -> ApiResult<Json<RulesListResponse>> {
    let store = rules_store(&state)?;
    let rules = store.load_rules().await.map_err(ApiError::internal)?;

    Ok(Json(RulesListResponse {
        rules: rules.into_iter().map(RuleResponse::from).collect(),
    }))
}

pub(super) async fn get_rule_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> ApiResult<Json<RuleResponse>> {
    let store = rules_store(&state)?;
    let rule = store.load_rule(&id).await.map_err(ApiError::internal)?;

    match rule {
        Some(rule) => Ok(Json(RuleResponse::from(rule))),
        None => Err(ApiError::not_found(format!("Rule '{}' not found", id))),
    }
}

pub(super) async fn create_rule_handler(
    State(state): State<ApiState>,
    ExtractJson(payload): ExtractJson<RuleUpsertRequest>,
) -> ApiResult<(StatusCode, Json<WriteStatusResponse>)> {
    let store = rules_store(&state)?;
    let rule = payload.into_rule().map_err(ApiError::bad_request)?;
    crate::rules::validate_rule(&rule).map_err(|err| ApiError::bad_request(err.to_string()))?;
    let inserted = store.insert_rule(&rule).await.map_err(ApiError::internal)?;

    if inserted {
        state
            .context
            .refresh_rules_from_storage()
            .await
            .map_err(ApiError::internal)?;
        Ok((
            StatusCode::CREATED,
            Json(WriteStatusResponse {
                success: true,
                message: format!("Rule '{}' created", rule.id),
            }),
        ))
    } else {
        Err(ApiError::conflict(format!(
            "Rule '{}' already exists",
            rule.id
        )))
    }
}

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

pub(super) async fn update_rule_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    ExtractJson(payload): ExtractJson<RuleUpsertRequest>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = rules_store(&state)?;
    let rule = payload
        .into_rule_with_id(id)
        .map_err(ApiError::bad_request)?;
    crate::rules::validate_rule(&rule).map_err(|err| ApiError::bad_request(err.to_string()))?;
    store.upsert_rule(&rule).await.map_err(ApiError::internal)?;
    state
        .context
        .refresh_rules_from_storage()
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(WriteStatusResponse {
        success: true,
        message: format!("Rule '{}' updated", rule.id),
    }))
}

pub(super) async fn delete_rule_handler(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> ApiResult<Json<WriteStatusResponse>> {
    let store = rules_store(&state)?;
    let deleted = store.delete_rule(&id).await.map_err(ApiError::internal)?;

    if deleted {
        state
            .context
            .refresh_rules_from_storage()
            .await
            .map_err(ApiError::internal)?;
        Ok(Json(WriteStatusResponse {
            success: true,
            message: format!("Rule '{}' deleted", id),
        }))
    } else {
        Err(ApiError::not_found(format!("Rule '{}' not found", id)))
    }
}
