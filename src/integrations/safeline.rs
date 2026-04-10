use crate::config::SafeLineConfig;
use anyhow::{anyhow, Result};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineProbeResult {
    pub status: String,
    pub message: String,
    pub openapi_doc_reachable: bool,
    pub openapi_doc_status: Option<u16>,
    pub authenticated: bool,
    pub auth_probe_status: Option<u16>,
}

pub async fn probe(config: &SafeLineConfig) -> Result<SafeLineProbeResult> {
    let base_url = config.base_url.trim().trim_end_matches('/').to_string();
    if base_url.is_empty() {
        return Err(anyhow!("雷池地址不能为空"));
    }

    let openapi_doc_url = format!("{base_url}{}", config.openapi_doc_path);
    let auth_probe_url = format!("{base_url}{}", config.auth_probe_path);

    let client = Client::builder()
        .danger_accept_invalid_certs(!config.verify_tls)
        .timeout(Duration::from_secs(10))
        .build()?;

    let openapi_doc_response = client.get(&openapi_doc_url).send().await?;
    let openapi_doc_status = openapi_doc_response.status();
    let openapi_doc_reachable = openapi_doc_status.is_success();

    if config.api_token.trim().is_empty() {
        return Ok(SafeLineProbeResult {
            status: if openapi_doc_reachable {
                "warning".to_string()
            } else {
                "error".to_string()
            },
            message: if openapi_doc_reachable {
                "已访问到雷池 OpenAPI 文档入口，但当前未填写 API Token，无法继续验证鉴权。"
                    .to_string()
            } else {
                format!("无法访问雷池 OpenAPI 文档入口，HTTP 状态码 {}", openapi_doc_status)
            },
            openapi_doc_reachable,
            openapi_doc_status: Some(openapi_doc_status.as_u16()),
            authenticated: false,
            auth_probe_status: None,
        });
    }

    let auth_probe_response = client
        .get(&auth_probe_url)
        .header("API-TOKEN", config.api_token.trim())
        .send()
        .await?;
    let auth_probe_status = auth_probe_response.status();

    let (status, authenticated, message) = classify_probe_result(
        openapi_doc_reachable,
        openapi_doc_status,
        auth_probe_status,
        &config.auth_probe_path,
    );

    Ok(SafeLineProbeResult {
        status,
        message,
        openapi_doc_reachable,
        openapi_doc_status: Some(openapi_doc_status.as_u16()),
        authenticated,
        auth_probe_status: Some(auth_probe_status.as_u16()),
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

    if matches!(auth_probe_status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN) {
        return (
            "error".to_string(),
            false,
            "雷池已响应，但 API Token 校验失败，请检查 Token 是否正确且具备调用权限。"
                .to_string(),
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
