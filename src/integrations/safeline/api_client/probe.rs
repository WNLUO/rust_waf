use super::*;

pub async fn probe(config: &SafeLineConfig) -> Result<SafeLineProbeResult> {
    let base_url = normalize_base_url(&config.base_url)?;
    let openapi_doc_path =
        normalized_or_default(&config.openapi_doc_path, DEFAULT_OPENAPI_DOC_PATH);
    let openapi_doc_url = format!("{base_url}{openapi_doc_path}");

    let client = client::build_client(config)?;

    let openapi_doc_response = client.get(&openapi_doc_url).send().await?;
    let openapi_doc_status = openapi_doc_response.status();
    let openapi_doc_reachable = openapi_doc_status.is_success();

    if !auth::has_any_auth(config) {
        return Ok(SafeLineProbeResult {
            status: if openapi_doc_reachable {
                "warning".to_string()
            } else {
                "error".to_string()
            },
            message: if openapi_doc_reachable {
                "已访问到雷池 OpenAPI 文档入口，但当前既未填写 API Token，也未配置雷池账号密码，无法继续验证鉴权。"
                    .to_string()
            } else {
                format!(
                    "无法访问雷池 OpenAPI 文档入口，HTTP 状态码 {}",
                    openapi_doc_status
                )
            },
            openapi_doc_reachable,
            openapi_doc_status: Some(openapi_doc_status.as_u16()),
            authenticated: false,
            auth_probe_status: None,
        });
    }

    let auth_probe_paths = candidate_paths(
        &config.auth_probe_path,
        &[DEFAULT_AUTH_PROBE_PATH, LEGACY_AUTH_PROBE_PATH],
    );
    let auth_probe = probe_authentication(&client, &base_url, config, &auth_probe_paths).await?;

    let (status, authenticated, message) = classify_probe_result(
        openapi_doc_reachable,
        openapi_doc_status,
        auth_probe.status,
        &auth_probe.path,
    );

    Ok(SafeLineProbeResult {
        status,
        message,
        openapi_doc_reachable,
        openapi_doc_status: Some(openapi_doc_status.as_u16()),
        authenticated,
        auth_probe_status: Some(auth_probe.status.as_u16()),
    })
}

pub async fn list_security_events(
    config: &SafeLineConfig,
) -> Result<Vec<SafeLineSecurityEventSummary>> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !auth::has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法读取雷池事件列表"
        ));
    }

    let client = client::build_client(config)?;
    let payload = client::get_json_with_fallback(
        &client,
        &base_url,
        config,
        &candidate_paths(
            &config.event_list_path,
            &[DEFAULT_EVENT_LIST_PATH, LEGACY_EVENT_LIST_PATH],
        ),
        "事件列表",
    )
    .await?;
    extract_security_events(&payload)
}

async fn probe_authentication(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
    paths: &[String],
) -> Result<ProbeAttempt> {
    let mut last_status = StatusCode::NOT_FOUND;
    let mut last_path = paths
        .first()
        .cloned()
        .unwrap_or_else(|| DEFAULT_AUTH_PROBE_PATH.to_string());

    for path in paths {
        let url = format!("{base_url}{path}");
        let (status, body) = client::send_with_auth(client, base_url, config, |auth| {
            auth::with_auth_headers(client.get(&url), auth)
        })
        .await?;
        last_status = status;
        last_path = path.clone();
        if status.is_success()
            || matches!(
                status,
                StatusCode::UNAUTHORIZED
                    | StatusCode::FORBIDDEN
                    | StatusCode::BAD_REQUEST
                    | StatusCode::METHOD_NOT_ALLOWED
                    | StatusCode::NOT_FOUND
            )
        {
            return Ok(ProbeAttempt {
                path: path.clone(),
                status,
            });
        }
        if body.contains("login-required") {
            return Ok(ProbeAttempt {
                path: path.clone(),
                status,
            });
        }
    }

    Ok(ProbeAttempt {
        path: last_path,
        status: last_status,
    })
}

fn classify_probe_result(
    openapi_doc_reachable: bool,
    openapi_doc_status: StatusCode,
    auth_probe_status: StatusCode,
    auth_probe_path: &str,
) -> (String, bool, String) {
    if !openapi_doc_reachable {
        return (
            "error".to_string(),
            false,
            format!(
                "雷池地址可连接，但 OpenAPI 文档入口返回 HTTP {}，请确认地址、TLS 证书或反向代理配置。",
                openapi_doc_status
            ),
        );
    }

    if auth_probe_status.is_success() {
        return (
            "ok".to_string(),
            true,
            "雷池 OpenAPI 文档和鉴权探测都已通过，可以继续对接 API。".to_string(),
        );
    }

    if matches!(
        auth_probe_status,
        StatusCode::BAD_REQUEST | StatusCode::METHOD_NOT_ALLOWED
    ) {
        return (
            "warning".to_string(),
            false,
            format!(
                "OpenAPI 文档已连通，鉴权探测接口 {} 返回 HTTP {}。这通常表示实例可达，但当前探测路径与版本不完全匹配，建议到目标实例的 openapi_doc 中确认接口路径。",
                auth_probe_path, auth_probe_status
            ),
        );
    }

    if matches!(
        auth_probe_status,
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN
    ) {
        return (
            "error".to_string(),
            false,
            "雷池已响应，但 API Token 校验失败，请检查 Token 是否正确且具备调用权限。".to_string(),
        );
    }

    if auth_probe_status == StatusCode::NOT_FOUND {
        return (
            "warning".to_string(),
            false,
            format!(
                "OpenAPI 文档已连通，但鉴权探测接口 {} 不存在。建议在目标雷池实例的 openapi_doc 中确认一个稳定的查询接口后再更新探测路径。",
                auth_probe_path
            ),
        );
    }

    (
        "warning".to_string(),
        false,
        format!(
            "OpenAPI 文档已连通，但鉴权探测接口返回 HTTP {}。可以继续保存配置，再根据目标实例文档调整探测路径。",
            auth_probe_status
        ),
    )
}
