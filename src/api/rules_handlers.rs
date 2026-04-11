use super::*;
use axum::extract::Multipart;
use std::collections::HashMap;

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
    response_content: &'static str,
}

fn builtin_action_idea_presets() -> Vec<BuiltinActionIdeaPreset> {
    vec![
        BuiltinActionIdeaPreset {
            id: "brand-block",
            title: "品牌化拦截页",
            mood: "正式",
            summary: "把默认 403 升级为带品牌、联络入口和操作建议的页面。",
            mechanism: "优先复用 HTML 模板插件，没有模板时回退到自定义 respond。",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "brand-block-fun",
            file_name: "brand-block-fun.zip",
            response_file_path: "brand-block.html",
            plugin_name: "Brand Block Fun",
            plugin_description: "品牌化拦截页示例插件",
            template_local_id: "brand_block_page",
            template_description: "返回可品牌化的 HTML 拦截页",
            pattern: "(?i)forbidden|blocked|intercepted",
            severity: "high",
            content_type: "text/html; charset=utf-8",
            status_code: 403,
            gzip: true,
            response_content: r#"<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>访问已受控</title>
  <style>
    body { margin: 0; font-family: "Segoe UI", sans-serif; background: linear-gradient(135deg, #f8fafc, #e0f2fe); color: #0f172a; }
    .shell { min-height: 100vh; display: grid; place-items: center; padding: 24px; }
    .card { width: min(720px, 100%); background: rgba(255,255,255,0.9); border: 1px solid rgba(148,163,184,0.25); border-radius: 28px; padding: 32px; box-shadow: 0 24px 80px rgba(15,23,42,0.14); }
    .tag { display: inline-block; padding: 6px 12px; background: #0f172a; color: white; border-radius: 999px; font-size: 12px; letter-spacing: 0.1em; }
    h1 { margin: 18px 0 12px; font-size: 34px; }
    p { line-height: 1.8; color: #334155; }
  </style>
</head>
<body>
  <main class="shell">
    <section class="card">
      <span class="tag">SECURITY GATE</span>
      <h1>当前访问已被安全策略接管</h1>
      <p>这是一个适合生产场景的品牌化拦截页示例。</p>
      <p>你可以替换品牌名、工单入口、运维联系方式和恢复建议，让用户知道接下来该做什么。</p>
    </section>
  </main>
</body>
</html>"#,
        },
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
            response_content: "{\n  \"status\": \"ok\",\n  \"trace_id\": \"demo-honeypot-001\",\n  \"message\": \"request accepted\",\n  \"note\": \"this is a deceptive sample response for scanners\"\n}",
        },
        BuiltinActionIdeaPreset {
            id: "debug-echo",
            title: "调试回显页",
            mood: "调试",
            summary: "做一个简化回显页，用来验证规则是否按预期命中。",
            mechanism: "通过自定义 respond 快速搭一个内联文本或 HTML 页面。",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "debug-echo-fun",
            file_name: "debug-echo-fun.zip",
            response_file_path: "debug-echo.txt",
            plugin_name: "Debug Echo Fun",
            plugin_description: "调试回显页示例插件",
            template_local_id: "debug_echo",
            template_description: "返回简单文本回显页，用于调试规则命中",
            pattern: "(?i)debug|preview|echo",
            severity: "medium",
            content_type: "text/plain; charset=utf-8",
            status_code: 200,
            gzip: false,
            response_content: "Debug Echo Sample\n-----------------\nmethod={{method}}\nuri={{uri}}\nsource_ip={{source_ip}}\nmatched_rule={{rule_id}}\n\nUse this as a friendly placeholder page while you validate matching behavior.",
        },
        BuiltinActionIdeaPreset {
            id: "scanner-misdirection",
            title: "扫描器误导页",
            mood: "对抗",
            summary: "给自动化工具返回静态成功页或伪接口数据，降低即时反馈。",
            mechanism: "推荐用 HTML 或 JSON 模板动作来做低成本误导。",
            performance: "中",
            fallback_path: "/admin/rules",
            plugin_id: "scanner-misdirection-fun",
            file_name: "scanner-misdirection-fun.zip",
            response_file_path: "scanner-ok.html",
            plugin_name: "Scanner Misdirection Fun",
            plugin_description: "扫描器误导页示例插件",
            template_local_id: "scanner_ok",
            template_description: "对自动化工具返回看似正常的静态页面",
            pattern: "(?i)scan|crawler|nmap|nikto",
            severity: "medium",
            content_type: "text/html; charset=utf-8",
            status_code: 200,
            gzip: true,
            response_content: "<!doctype html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\"><title>OK</title></head>\n<body><h1>200 OK</h1><p>Resource indexed successfully.</p></body>\n</html>",
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
            response_content: "<!doctype html>\n<html lang=\"zh-CN\">\n<head><meta charset=\"utf-8\"><title>维护中</title></head>\n<body style=\"font-family: sans-serif; padding: 48px;\">\n  <h1>服务维护中</h1>\n  <p>当前入口正在进行短时维护，请稍后重试。</p>\n</body>\n</html>",
        },
    ]
}

fn action_idea_headers(idea_id: &str) -> Vec<RuleResponseHeaderPayload> {
    let mut headers = vec![RuleResponseHeaderPayload {
        key: "cache-control".to_string(),
        value: "no-store".to_string(),
    }];
    if idea_id == "maintenance-page" {
        headers.push(RuleResponseHeaderPayload {
            key: "retry-after".to_string(),
            value: "120".to_string(),
        });
    }
    headers
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
        .map(|builtin| {
            let override_entry = overrides_by_id.get(builtin.id);
            let title = override_entry
                .and_then(|entry| entry.title.clone())
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| builtin.title.to_string());
            let response_content = override_entry
                .and_then(|entry| entry.response_content.clone())
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| builtin.response_content.to_string());
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
                content_type: builtin.content_type.to_string(),
                status_code: builtin.status_code,
                gzip: builtin.gzip,
                headers: action_idea_headers(builtin.id),
                response_content,
                has_overrides: override_entry.is_some(),
                updated_at: override_entry
                    .map(|entry| entry.updated_at)
                    .unwrap_or_default(),
            }
        })
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

    let response_content = payload.response_content.trim().to_string();
    if response_content.is_empty() {
        return Err(ApiError::bad_request("原始内容不能为空".to_string()));
    }

    let store = sqlite_store(&state)?;
    store
        .upsert_action_idea_override(&crate::storage::ActionIdeaOverrideUpsert {
            idea_id: idea_id.clone(),
            title: Some(title.clone()),
            response_content: Some(payload.response_content),
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

    Ok(Json(ActionIdeaPresetResponse {
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
        content_type: builtin.content_type.to_string(),
        status_code: builtin.status_code,
        gzip: builtin.gzip,
        headers: action_idea_headers(builtin.id),
        response_content,
        has_overrides: true,
        updated_at: updated_entry.updated_at,
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
