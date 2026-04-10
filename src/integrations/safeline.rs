use crate::config::SafeLineConfig;
use crate::storage::{BlockedIpEntry, BlockedIpRecord, SecurityEventRecord};
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::time::Duration;

const DEFAULT_OPENAPI_DOC_PATH: &str = "/openapi_doc/";
const DEFAULT_AUTH_PROBE_PATH: &str = "/api/open/system/key";
const LEGACY_AUTH_PROBE_PATH: &str = "/api/IPGroupAPI";
const DEFAULT_SITE_LIST_PATH: &str = "/api/open/site";
const LEGACY_SITE_LIST_PATH: &str = "/api/WebsiteAPI";
const DEFAULT_EVENT_LIST_PATH: &str = "/api/open/records";
const LEGACY_EVENT_LIST_PATH: &str = "/api/AttackLogAPI";
const DEFAULT_BLOCKLIST_PATH: &str = "/api/open/ipgroup";
const LEGACY_BLOCKLIST_PATH: &str = "/api/IPGroupAPI";
const OPEN_BLOCKLIST_APPEND_SUFFIX: &str = "/append";
const OPEN_BLOCKLIST_REMOVE_SUFFIX: &str = "/remove";
const LOGIN_AES_KEY_PATH: &str = "/api/open/system/key";
const LOGIN_CSRF_PATH: &str = "/api/open/auth/csrf";
const LOGIN_PATH: &str = "/api/open/auth/login";

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineProbeResult {
    pub status: String,
    pub message: String,
    pub openapi_doc_reachable: bool,
    pub openapi_doc_status: Option<u16>,
    pub authenticated: bool,
    pub auth_probe_status: Option<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineSiteSummary {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub status: String,
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineSecurityEventSummary {
    pub provider_site_id: Option<String>,
    pub provider_site_name: Option<String>,
    pub provider_site_domain: Option<String>,
    pub action: String,
    pub reason: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: i64,
    pub dest_port: i64,
    pub protocol: String,
    pub http_method: Option<String>,
    pub uri: Option<String>,
    pub http_version: Option<String>,
    pub created_at: i64,
    pub raw: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineBlockedIpSyncSummary {
    pub ip: String,
    pub accepted: bool,
    pub status_code: u16,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineBlockedIpDeleteSummary {
    pub ip: String,
    pub accepted: bool,
    pub status_code: u16,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineBlockedIpSummary {
    pub remote_id: Option<String>,
    pub ip: String,
    pub reason: String,
    pub blocked_at: i64,
    pub expires_at: i64,
    pub raw: Value,
}

#[derive(Debug, Clone)]
struct AuthContext {
    api_token: Option<String>,
    bearer_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct SafeLineSystemKeyEnvelope {
    data: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SafeLineCsrfEnvelope {
    data: SafeLineCsrfPayload,
}

#[derive(Debug, Clone, Deserialize)]
struct SafeLineCsrfPayload {
    csrf_token: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SafeLineLoginEnvelope {
    data: SafeLineLoginPayload,
    #[allow(dead_code)]
    err: Option<String>,
    msg: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SafeLineLoginPayload {
    jwt: String,
}

pub async fn probe(config: &SafeLineConfig) -> Result<SafeLineProbeResult> {
    let base_url = normalize_base_url(&config.base_url)?;
    let openapi_doc_path =
        normalized_or_default(&config.openapi_doc_path, DEFAULT_OPENAPI_DOC_PATH);
    let openapi_doc_url = format!("{base_url}{openapi_doc_path}");

    let client = build_client(config)?;

    let openapi_doc_response = client.get(&openapi_doc_url).send().await?;
    let openapi_doc_status = openapi_doc_response.status();
    let openapi_doc_reachable = openapi_doc_status.is_success();

    if !has_any_auth(config) {
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

pub async fn list_sites(config: &SafeLineConfig) -> Result<Vec<SafeLineSiteSummary>> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法读取雷池站点列表"
        ));
    }

    let client = build_client(config)?;
    let payload = get_json_with_fallback(
        &client,
        &base_url,
        config,
        &candidate_paths(
            &config.site_list_path,
            &[DEFAULT_SITE_LIST_PATH, LEGACY_SITE_LIST_PATH],
        ),
        "站点列表",
    )
    .await?;
    extract_sites(&payload)
}

pub async fn list_security_events(
    config: &SafeLineConfig,
) -> Result<Vec<SafeLineSecurityEventSummary>> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法读取雷池事件列表"
        ));
    }

    let client = build_client(config)?;
    let payload = get_json_with_fallback(
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

pub async fn push_blocked_ip(
    config: &SafeLineConfig,
    blocked_ip: &BlockedIpEntry,
) -> Result<SafeLineBlockedIpSyncSummary> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法同步本地封禁到雷池"
        ));
    }

    let client = build_client(config)?;
    let path = normalized_or_default(&config.blocklist_sync_path, DEFAULT_BLOCKLIST_PATH);
    if path.contains("/open/ipgroup") {
        return push_blocked_ip_via_open_ipgroup(&client, &base_url, config, blocked_ip, &path)
            .await;
    }
    let url = format!("{base_url}{path}");
    let payload = serde_json::json!({
        "ip": blocked_ip.ip,
        "reason": blocked_ip.reason,
        "blocked_at": blocked_ip.blocked_at,
        "expires_at": blocked_ip.expires_at,
        "source": "waf-local",
    });
    let (status, body) = send_with_auth(&client, &base_url, config, |auth| {
        with_auth_headers(client.post(&url).json(&payload), auth)
    })
    .await?;
    let accepted = status.is_success() || status == StatusCode::CONFLICT;

    Ok(SafeLineBlockedIpSyncSummary {
        ip: blocked_ip.ip.clone(),
        accepted,
        status_code: status.as_u16(),
        message: if body.trim().is_empty() {
            status.to_string()
        } else {
            body
        },
    })
}

pub async fn list_blocked_ips(config: &SafeLineConfig) -> Result<Vec<SafeLineBlockedIpSummary>> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法读取雷池封禁列表"
        ));
    }

    let client = build_client(config)?;
    let payload = get_json_with_fallback(
        &client,
        &base_url,
        config,
        &candidate_paths(
            &config.blocklist_sync_path,
            &[DEFAULT_BLOCKLIST_PATH, LEGACY_BLOCKLIST_PATH],
        ),
        "封禁列表",
    )
    .await?;
    extract_blocked_ips(&payload)
}

pub async fn delete_blocked_ip(
    config: &SafeLineConfig,
    blocked_ip: &BlockedIpEntry,
) -> Result<SafeLineBlockedIpDeleteSummary> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法调用雷池远端解封"
        ));
    }

    let client = build_client(config)?;
    let path = if config.blocklist_delete_path.trim().is_empty() {
        &config.blocklist_sync_path
    } else {
        &config.blocklist_delete_path
    };
    let path = normalized_or_default(path, DEFAULT_BLOCKLIST_PATH);
    if path.contains("/open/ipgroup") {
        return delete_blocked_ip_via_open_ipgroup(&client, &base_url, config, blocked_ip, &path)
            .await;
    }
    let url = format!("{base_url}{path}");

    let payload = serde_json::json!({
        "id": blocked_ip.provider_remote_id.as_deref(),
        "remote_id": blocked_ip.provider_remote_id.as_deref(),
        "ip": &blocked_ip.ip,
        "address": &blocked_ip.ip,
        "reason": &blocked_ip.reason,
        "blocked_at": blocked_ip.blocked_at,
        "expires_at": blocked_ip.expires_at,
    });

    let mut last_status = StatusCode::BAD_GATEWAY;
    let mut last_message = String::new();

    let delete_action_payload = serde_json::json!({
        "action": "delete",
        "id": blocked_ip.provider_remote_id.as_deref(),
        "remote_id": blocked_ip.provider_remote_id.as_deref(),
        "ip": &blocked_ip.ip,
    });
    let mut request_kinds = Vec::new();
    if let Some(remote_id) = blocked_ip.provider_remote_id.as_deref() {
        request_kinds.push(DeleteAttempt::DeleteById(remote_id.to_string()));
    }
    request_kinds.push(DeleteAttempt::DeleteByBody(payload.clone()));
    request_kinds.push(DeleteAttempt::PostDelete(delete_action_payload));

    for attempt in request_kinds {
        let (status, body) = send_with_auth(&client, &base_url, config, |auth| match &attempt {
            DeleteAttempt::DeleteById(remote_id) => {
                with_auth_headers(client.delete(format!("{url}/{remote_id}")), auth)
            }
            DeleteAttempt::DeleteByBody(payload) => {
                with_auth_headers(client.delete(&url).json(payload), auth)
            }
            DeleteAttempt::PostDelete(payload) => {
                with_auth_headers(client.post(&url).json(payload), auth)
            }
        })
        .await?;

        if status.is_success() || status == StatusCode::NOT_FOUND {
            return Ok(SafeLineBlockedIpDeleteSummary {
                ip: blocked_ip.ip.clone(),
                accepted: true,
                status_code: status.as_u16(),
                message: if body.trim().is_empty() {
                    status.to_string()
                } else {
                    body
                },
            });
        }

        last_status = status;
        last_message = if body.trim().is_empty() {
            status.to_string()
        } else {
            body
        };
    }

    Ok(SafeLineBlockedIpDeleteSummary {
        ip: blocked_ip.ip.clone(),
        accepted: false,
        status_code: last_status.as_u16(),
        message: last_message,
    })
}

async fn push_blocked_ip_via_open_ipgroup(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
    blocked_ip: &BlockedIpEntry,
    path: &str,
) -> Result<SafeLineBlockedIpSyncSummary> {
    let ip_group_ids = configured_ip_group_ids(config)?;
    let payload = serde_json::json!({
        "ip_group_ids": ip_group_ids,
        "ips": [blocked_ip.ip.clone()],
    });

    let mut failures = Vec::new();
    for action_path in open_ipgroup_action_paths(path, OPEN_BLOCKLIST_APPEND_SUFFIX) {
        let url = format!("{base_url}{action_path}");
        let (status, body) = send_with_auth(client, base_url, config, |auth| {
            with_auth_headers(client.post(&url).json(&payload), auth)
        })
        .await?;

        if status.is_success() || status == StatusCode::CONFLICT {
            return Ok(SafeLineBlockedIpSyncSummary {
                ip: blocked_ip.ip.clone(),
                accepted: true,
                status_code: status.as_u16(),
                message: if body.trim().is_empty() {
                    status.to_string()
                } else {
                    body
                },
            });
        }

        failures.push(format_failure(&action_path, status, &body));
    }

    Err(anyhow!(
        "调用新版雷池 IP 组追加接口失败。已尝试：{}",
        failures.join("；")
    ))
}

async fn delete_blocked_ip_via_open_ipgroup(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
    blocked_ip: &BlockedIpEntry,
    path: &str,
) -> Result<SafeLineBlockedIpDeleteSummary> {
    let ip_group_ids = configured_ip_group_ids(config)?;
    let payload = serde_json::json!({
        "ip_group_ids": ip_group_ids.clone(),
        "ips": [blocked_ip.ip.clone()],
    });

    let mut attempts = Vec::new();
    for action_path in open_ipgroup_action_paths(path, OPEN_BLOCKLIST_REMOVE_SUFFIX) {
        attempts.push(OpenIpGroupDeleteAttempt::PostRemove(
            action_path.clone(),
            payload.clone(),
        ));
        attempts.push(OpenIpGroupDeleteAttempt::DeleteRemove(
            action_path.clone(),
            payload.clone(),
        ));
    }

    let base_path = open_ipgroup_base_path(path);
    attempts.push(OpenIpGroupDeleteAttempt::PostAction(
        base_path.clone(),
        serde_json::json!({
            "action": "remove",
            "ip_group_ids": ip_group_ids.clone(),
            "ips": [blocked_ip.ip.clone()],
        }),
    ));
    attempts.push(OpenIpGroupDeleteAttempt::PostAction(
        base_path,
        serde_json::json!({
            "action": "delete",
            "ip_group_ids": ip_group_ids,
            "ips": [blocked_ip.ip.clone()],
        }),
    ));

    let mut failures = Vec::new();
    for attempt in attempts {
        let path = attempt.path().to_string();
        let (status, body) = send_with_auth(client, base_url, config, |auth| {
            let url = format!("{base_url}{path}");
            match &attempt {
                OpenIpGroupDeleteAttempt::PostRemove(_, payload)
                | OpenIpGroupDeleteAttempt::PostAction(_, payload) => {
                    with_auth_headers(client.post(&url).json(payload), auth)
                }
                OpenIpGroupDeleteAttempt::DeleteRemove(_, payload) => {
                    with_auth_headers(client.delete(&url).json(payload), auth)
                }
            }
        })
        .await?;

        if status.is_success() || status == StatusCode::NOT_FOUND || status == StatusCode::CONFLICT
        {
            return Ok(SafeLineBlockedIpDeleteSummary {
                ip: blocked_ip.ip.clone(),
                accepted: true,
                status_code: status.as_u16(),
                message: if body.trim().is_empty() {
                    status.to_string()
                } else {
                    body
                },
            });
        }

        failures.push(format_failure(&path, status, &body));
    }

    Err(anyhow!(
        "调用新版雷池 IP 组移除接口失败。已尝试：{}",
        failures.join("；")
    ))
}

fn build_client(config: &SafeLineConfig) -> Result<Client> {
    Ok(Client::builder()
        .danger_accept_invalid_certs(!config.verify_tls)
        .timeout(Duration::from_secs(10))
        .build()?)
}

#[derive(Debug, Clone)]
struct ProbeAttempt {
    path: String,
    status: StatusCode,
}

enum DeleteAttempt {
    DeleteById(String),
    DeleteByBody(Value),
    PostDelete(Value),
}

enum OpenIpGroupDeleteAttempt {
    PostRemove(String, Value),
    DeleteRemove(String, Value),
    PostAction(String, Value),
}

impl OpenIpGroupDeleteAttempt {
    fn path(&self) -> &str {
        match self {
            Self::PostRemove(path, _) | Self::DeleteRemove(path, _) | Self::PostAction(path, _) => {
                path
            }
        }
    }
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
        let (status, body) = send_with_auth(client, base_url, config, |auth| {
            with_auth_headers(client.get(&url), auth)
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

async fn get_json_with_fallback(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
    paths: &[String],
    resource_name: &str,
) -> Result<Value> {
    let mut failures = Vec::new();

    for path in paths {
        let url = format!("{base_url}{path}");
        let (status, body) = send_with_auth(client, base_url, config, |auth| {
            with_auth_headers(client.get(&url), auth)
        })
        .await?;

        if status.is_success() {
            if looks_like_html(&body) {
                failures.push(format!(
                    "{path} -> HTTP {status}（返回了前端页面而不是 JSON）"
                ));
                continue;
            }

            let payload = serde_json::from_str::<Value>(&body).map_err(|err| {
                anyhow!(
                    "雷池{resource_name}接口 {} 返回了不可解析的 JSON：{}",
                    path,
                    err
                )
            })?;
            return Ok(payload);
        }

        if body.contains("login-required") || body.contains("Login required") {
            return Err(anyhow!(
                "雷池{}接口 {} 返回 login-required。当前 Token 可访问部分 OpenAPI，但该接口仍要求登录态 Bearer 授权，说明接入尚未完全完成。",
                resource_name,
                path
            ));
        }

        if body.contains("commerce license required") {
            return Err(anyhow!(
                "雷池{}接口 {} 返回 commerce license required，当前实例版本或授权不支持该能力。",
                resource_name,
                path
            ));
        }

        failures.push(format!("{path} -> HTTP {status}"));
    }

    Err(anyhow!(
        "雷池{}接口均未成功返回，请检查路径是否与实例版本匹配。已尝试：{}",
        resource_name,
        failures.join("，")
    ))
}

async fn send_with_auth<F>(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
    build_request: F,
) -> Result<(StatusCode, String)>
where
    F: Fn(&AuthContext) -> RequestBuilder,
{
    let auth_contexts = resolve_auth_contexts(client, base_url, config).await?;
    let mut last_status = StatusCode::UNAUTHORIZED;
    let mut last_body = String::new();

    for auth in &auth_contexts {
        let response = build_request(auth).send().await?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        let login_required = body.contains("login-required") || body.contains("Login required");
        last_status = status;
        last_body = body.clone();
        if status.is_success() || !login_required {
            return Ok((status, body));
        }
    }

    Ok((last_status, last_body))
}

async fn resolve_auth_contexts(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
) -> Result<Vec<AuthContext>> {
    let mut contexts = Vec::new();
    let token = config.api_token.trim();
    if !token.is_empty() {
        contexts.push(AuthContext {
            api_token: Some(token.to_string()),
            bearer_token: Some(token.to_string()),
        });
    }

    if has_username_password(config) {
        let jwt = login_with_password(client, base_url, config).await?;
        if !jwt.trim().is_empty() {
            contexts.push(AuthContext {
                api_token: None,
                bearer_token: Some(jwt),
            });
        }
    }

    if contexts.is_empty() {
        contexts.push(AuthContext {
            api_token: None,
            bearer_token: None,
        });
    }

    Ok(contexts)
}

fn with_auth_headers(request: RequestBuilder, auth: &AuthContext) -> RequestBuilder {
    let request = if let Some(api_token) = auth.api_token.as_deref() {
        request.header("API-TOKEN", api_token)
    } else {
        request
    };

    if let Some(bearer_token) = auth.bearer_token.as_deref() {
        request.header("Authorization", format!("Bearer {bearer_token}"))
    } else {
        request
    }
}

fn has_any_auth(config: &SafeLineConfig) -> bool {
    !config.api_token.trim().is_empty() || has_username_password(config)
}

fn has_username_password(config: &SafeLineConfig) -> bool {
    !config.username.trim().is_empty() && !config.password.trim().is_empty()
}

async fn login_with_password(
    client: &Client,
    base_url: &str,
    config: &SafeLineConfig,
) -> Result<String> {
    let aes_key_url = format!("{base_url}{LOGIN_AES_KEY_PATH}");
    let csrf_url = format!("{base_url}{LOGIN_CSRF_PATH}");
    let login_url = format!("{base_url}{LOGIN_PATH}");

    let aes_key = client
        .get(&aes_key_url)
        .send()
        .await?
        .json::<SafeLineSystemKeyEnvelope>()
        .await?
        .data;
    if aes_key.len() != 16 {
        return Err(anyhow!(
            "雷池登录加密密钥长度异常，期望 16 字节，实际 {}",
            aes_key.len()
        ));
    }

    let csrf_token = client
        .get(&csrf_url)
        .send()
        .await?
        .json::<SafeLineCsrfEnvelope>()
        .await?
        .data
        .csrf_token;

    let iv = random_iv();
    let encrypted_password = encrypt_password(&aes_key, &iv, config.password.trim())?;
    let payload = serde_json::json!({
        "username": config.username.trim(),
        "password": encrypted_password,
        "csrf_token": csrf_token,
    });

    let response = client.post(&login_url).json(&payload).send().await?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(anyhow!("雷池登录失败，HTTP {}：{}", status, body));
    }

    let envelope = serde_json::from_str::<SafeLineLoginEnvelope>(&body)
        .map_err(|err| anyhow!("雷池登录返回了不可解析的 JSON：{}", err))?;
    if envelope.data.jwt.trim().is_empty() {
        return Err(anyhow!(
            "雷池登录未返回 JWT：{}",
            if envelope.msg.trim().is_empty() {
                "空响应".to_string()
            } else {
                envelope.msg
            }
        ));
    }

    Ok(envelope.data.jwt)
}

fn random_iv() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

fn encrypt_password(aes_key: &str, iv: &str, password: &str) -> Result<String> {
    let encrypted = encrypt_password_with_openssl(aes_key, iv, password)?;
    let mut mixed = Vec::with_capacity(iv.len() + encrypted.len());
    mixed.extend_from_slice(iv.as_bytes());
    mixed.extend_from_slice(&encrypted);
    Ok(BASE64.encode(mixed))
}

fn encrypt_password_with_openssl(aes_key: &str, iv: &str, password: &str) -> Result<Vec<u8>> {
    let output = Command::new("/usr/bin/openssl")
        .arg("enc")
        .arg("-aes-128-cbc")
        .arg("-K")
        .arg(bytes_to_hex(aes_key.as_bytes()))
        .arg("-iv")
        .arg(bytes_to_hex(iv.as_bytes()))
        .arg("-nosalt")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(password.as_bytes())?;
            }
            child.wait_with_output()
        })
        .map_err(|err| anyhow!("调用 openssl 进行雷池密码加密失败：{}", err))?;

    if !output.status.success() {
        return Err(anyhow!(
            "openssl 加密失败：{}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    Ok(output.stdout)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn normalize_base_url(value: &str) -> Result<String> {
    let base_url = value.trim().trim_end_matches('/').to_string();
    if base_url.is_empty() {
        return Err(anyhow!("雷池地址不能为空"));
    }
    Ok(base_url)
}

fn normalized_or_default(value: &str, default: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn configured_ip_group_ids(config: &SafeLineConfig) -> Result<Vec<String>> {
    let mut ids = Vec::new();
    for item in &config.blocklist_ip_group_ids {
        let trimmed = item.trim();
        if trimmed.is_empty() || ids.iter().any(|value| value == trimmed) {
            continue;
        }
        ids.push(trimmed.to_string());
    }
    if ids.is_empty() {
        return Err(anyhow!(
            "当前封禁路径使用新版雷池 IP 组接口，但还没有配置 blocklist_ip_group_ids，无法确定要操作的目标 IP 组。"
        ));
    }
    Ok(ids)
}

fn open_ipgroup_base_path(path: &str) -> String {
    let normalized = normalized_or_default(path, DEFAULT_BLOCKLIST_PATH);
    if let Some(base) = normalized.strip_suffix(OPEN_BLOCKLIST_APPEND_SUFFIX) {
        return base.to_string();
    }
    if let Some(base) = normalized.strip_suffix(OPEN_BLOCKLIST_REMOVE_SUFFIX) {
        return base.to_string();
    }
    normalized
}

fn open_ipgroup_action_paths(path: &str, suffix: &str) -> Vec<String> {
    let current = normalized_or_default(path, DEFAULT_BLOCKLIST_PATH);
    let base = open_ipgroup_base_path(&current);
    let mut seen = HashSet::new();
    let mut paths = Vec::new();

    for candidate in [format!("{base}{suffix}"), current, base] {
        if seen.insert(candidate.clone()) {
            paths.push(candidate);
        }
    }

    paths
}

fn format_failure(path: &str, status: StatusCode, body: &str) -> String {
    if body.trim().is_empty() {
        format!("{path} -> HTTP {status}")
    } else {
        format!("{path} -> HTTP {status}: {}", body.trim())
    }
}

fn candidate_paths(current: &str, fallbacks: &[&str]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut paths = Vec::new();

    for value in std::iter::once(current).chain(fallbacks.iter().copied()) {
        let normalized = normalized_or_default(value, "");
        if normalized.is_empty() || !seen.insert(normalized.clone()) {
            continue;
        }
        paths.push(normalized);
    }

    paths
}

fn looks_like_html(value: &str) -> bool {
    let trimmed = value.trim_start();
    trimmed.starts_with("<!DOCTYPE html") || trimmed.starts_with("<html")
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

fn extract_sites(payload: &Value) -> Result<Vec<SafeLineSiteSummary>> {
    let candidates = find_array_candidates(payload);
    for candidate in candidates {
        let sites = candidate
            .iter()
            .filter_map(parse_site_summary)
            .collect::<Vec<_>>();
        if !sites.is_empty() {
            return Ok(sites);
        }
    }

    Err(anyhow!(
        "已拿到雷池响应，但未能从 JSON 中识别站点数组。请检查 site_list_path 是否正确，或根据目标实例实际返回结构补充解析规则。"
    ))
}

fn extract_security_events(payload: &Value) -> Result<Vec<SafeLineSecurityEventSummary>> {
    let candidates = find_array_candidates(payload);
    for candidate in candidates {
        let events = candidate
            .iter()
            .filter_map(parse_security_event_summary)
            .collect::<Vec<_>>();
        if !events.is_empty() {
            return Ok(events);
        }
    }

    Err(anyhow!(
        "已拿到雷池响应，但未能从 JSON 中识别事件数组。请检查 event_list_path 是否正确，或根据目标实例实际返回结构补充解析规则。"
    ))
}

fn extract_blocked_ips(payload: &Value) -> Result<Vec<SafeLineBlockedIpSummary>> {
    let candidates = find_array_candidates(payload);
    for candidate in candidates {
        let recognized_candidate = candidate.iter().any(looks_like_blocked_ip_summary);
        let records = candidate
            .iter()
            .flat_map(parse_blocked_ip_summaries)
            .collect::<Vec<_>>();
        if !records.is_empty() || recognized_candidate {
            return Ok(records);
        }
    }

    Err(anyhow!(
        "已拿到雷池响应，但未能从 JSON 中识别封禁列表数组。请检查 blocklist_sync_path 是否正确，或根据目标实例实际返回结构补充解析规则。"
    ))
}

fn find_array_candidates<'a>(value: &'a Value) -> Vec<&'a Vec<Value>> {
    let mut candidates = Vec::new();
    collect_array_candidates(value, &mut candidates);
    candidates
}

fn collect_array_candidates<'a>(value: &'a Value, candidates: &mut Vec<&'a Vec<Value>>) {
    if let Some(array) = value.as_array() {
        candidates.push(array);
        for item in array {
            collect_array_candidates(item, candidates);
        }
        return;
    }

    let Some(object) = value.as_object() else {
        return;
    };

    for key in [
        "data", "list", "items", "nodes", "results", "rows", "records", "objs", "objects",
    ] {
        if let Some(child) = object.get(key) {
            collect_array_candidates(child, candidates);
        }
    }

    for child in object.values() {
        if child.is_object() {
            collect_array_candidates(child, candidates);
        }
    }
}

fn parse_site_summary(value: &Value) -> Option<SafeLineSiteSummary> {
    let object = value.as_object()?;
    let id = pick_string(
        object,
        &["id", "uuid", "site_id", "siteId", "website_id", "uid"],
    )
    .unwrap_or_default();
    let name = pick_string(
        object,
        &[
            "name",
            "title",
            "comment",
            "site_name",
            "siteName",
            "domain",
            "website",
            "host",
        ],
    )
    .unwrap_or_else(|| "未命名站点".to_string());
    let domain = pick_string(
        object,
        &["domain", "hostname", "host", "server", "origin", "upstream"],
    )
    .or_else(|| pick_first_array_string(object, &["server_names", "hosts"]))
    .unwrap_or_default();
    let status = pick_string(object, &["status", "state", "enabled", "mode"])
        .unwrap_or_else(|| "unknown".to_string());

    Some(SafeLineSiteSummary {
        id,
        name,
        domain,
        status,
        raw: value.clone(),
    })
}

fn parse_security_event_summary(value: &Value) -> Option<SafeLineSecurityEventSummary> {
    let object = value.as_object()?;
    let source_ip = pick_string(
        object,
        &["src_ip", "source_ip", "client_ip", "ip", "remote_addr"],
    )
    .unwrap_or_else(|| "0.0.0.0".to_string());
    let dest_ip = pick_string(object, &["dst_ip", "dest_ip", "server_ip"]).unwrap_or_default();
    let action = pick_string(object, &["action", "decision", "event_type", "type"])
        .unwrap_or_else(|| "alert".to_string());
    let attack_type = pick_string(object, &["attack_type", "rule_type", "category"]);
    let reason = pick_string(object, &["reason", "message", "description", "rule_name"])
        .or(attack_type.clone())
        .unwrap_or_else(|| "safeline_event".to_string());
    let uri = pick_string(object, &["uri", "path", "url", "request_uri"]);
    let http_method = pick_string(object, &["method", "http_method", "request_method"]);
    let http_version = pick_string(object, &["http_version", "version"]);
    let protocol =
        pick_string(object, &["protocol", "scheme"]).unwrap_or_else(|| "HTTP".to_string());
    let source_port = pick_i64(object, &["src_port", "source_port", "client_port"]).unwrap_or(0);
    let dest_port = pick_i64(object, &["dst_port", "dest_port", "server_port"]).unwrap_or(0);
    let created_at = pick_i64(
        object,
        &[
            "created_at",
            "timestamp",
            "time",
            "occurred_at",
            "attack_time",
        ],
    )
    .unwrap_or_else(unix_timestamp);
    let provider_site_id = pick_string(
        object,
        &["site_id", "siteId", "website_id", "websiteId", "uuid"],
    );
    let provider_site_name = pick_string(
        object,
        &[
            "site_name",
            "siteName",
            "site_title",
            "site_comment",
            "website",
            "domain_name",
            "host_name",
        ],
    );
    let provider_site_domain = pick_string(
        object,
        &[
            "domain",
            "host",
            "hostname",
            "server_name",
            "website_domain",
        ],
    )
    .or_else(|| pick_first_array_string(object, &["site_server_names", "server_names"]))
    .or_else(|| pick_string(object, &["website"]))
    .or_else(|| uri.as_ref().and_then(|value| extract_host_from_uri(value)));

    Some(SafeLineSecurityEventSummary {
        provider_site_id,
        provider_site_name,
        provider_site_domain,
        action,
        reason: attack_type
            .map(|kind| format!("safeline:{kind}:{reason}"))
            .unwrap_or_else(|| format!("safeline:{reason}")),
        source_ip,
        dest_ip,
        source_port,
        dest_port,
        protocol,
        http_method,
        uri,
        http_version,
        created_at: normalize_timestamp(created_at),
        raw: value.clone(),
    })
}

fn parse_blocked_ip_summaries(value: &Value) -> Vec<SafeLineBlockedIpSummary> {
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    let Some(ips) = pick_array_strings(object, &["ips"]) else {
        return parse_flat_blocked_ip_summary(value).into_iter().collect();
    };

    let reason = pick_string(object, &["reason", "message", "description"])
        .or_else(|| pick_string(object, &["reference", "comment"]))
        .unwrap_or_else(|| "safeline_blocked_ip".to_string());
    let blocked_at = pick_timestamp(
        object,
        &[
            "blocked_at",
            "updated_at",
            "created_at",
            "timestamp",
            "time",
        ],
    )
    .unwrap_or_else(unix_timestamp);
    let expires_at = pick_timestamp(
        object,
        &["expires_at", "expired_at", "expire_at", "ttl_until"],
    )
    .unwrap_or(blocked_at + 3600);
    let remote_id = pick_string(object, &["id", "uuid", "uid"]);

    ips.into_iter()
        .map(|ip| SafeLineBlockedIpSummary {
            remote_id: remote_id.clone(),
            ip,
            reason: format!("safeline:{reason}"),
            blocked_at,
            expires_at,
            raw: value.clone(),
        })
        .collect()
}

fn parse_flat_blocked_ip_summary(value: &Value) -> Option<SafeLineBlockedIpSummary> {
    let object = value.as_object()?;
    let ip = pick_string(object, &["ip", "ip_addr", "address"])?;
    let reason = pick_string(object, &["reason", "message", "description"])
        .or_else(|| pick_string(object, &["reference", "comment"]))
        .unwrap_or_else(|| "safeline_blocked_ip".to_string());
    let blocked_at = pick_timestamp(
        object,
        &[
            "blocked_at",
            "updated_at",
            "created_at",
            "timestamp",
            "time",
        ],
    )
    .unwrap_or_else(unix_timestamp);
    let expires_at = pick_timestamp(
        object,
        &["expires_at", "expired_at", "expire_at", "ttl_until"],
    )
    .unwrap_or(blocked_at + 3600);
    let remote_id = pick_string(object, &["id", "uuid", "uid"]);

    Some(SafeLineBlockedIpSummary {
        remote_id,
        ip,
        reason: format!("safeline:{reason}"),
        blocked_at,
        expires_at,
        raw: value.clone(),
    })
}

fn looks_like_blocked_ip_summary(value: &Value) -> bool {
    let Some(object) = value.as_object() else {
        return false;
    };

    object.contains_key("ips")
        || object.contains_key("ip")
        || object.contains_key("ip_addr")
        || object.contains_key("address")
}

fn pick_string(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };

        match value {
            Value::String(inner) if !inner.trim().is_empty() => {
                return Some(inner.trim().to_string());
            }
            Value::Number(number) => return Some(number.to_string()),
            Value::Bool(flag) => return Some(flag.to_string()),
            _ => {}
        }
    }

    None
}

fn pick_first_array_string(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
    pick_array_strings(object, keys)?.into_iter().next()
}

fn pick_array_strings(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<Vec<String>> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };

        if let Some(array) = value.as_array() {
            let mut values = Vec::new();
            for item in array {
                if let Some(inner) = item.as_str() {
                    let trimmed = inner.trim();
                    if !trimmed.is_empty() {
                        values.push(trimmed.to_string());
                    }
                }
            }
            if !values.is_empty() {
                return Some(values);
            }
        }
    }

    None
}

fn pick_i64(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<i64> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };

        match value {
            Value::Number(number) => return number.as_i64(),
            Value::String(inner) => {
                if let Ok(parsed) = inner.trim().parse::<i64>() {
                    return Some(parsed);
                }
            }
            _ => {}
        }
    }

    None
}

fn pick_timestamp(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<i64> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };

        match value {
            Value::Number(number) => {
                if let Some(parsed) = number.as_i64() {
                    return Some(normalize_timestamp(parsed));
                }
            }
            Value::String(inner) => {
                let trimmed = inner.trim();
                if trimmed.is_empty() {
                    continue;
                }
                if let Ok(parsed) = trimmed.parse::<i64>() {
                    return Some(normalize_timestamp(parsed));
                }
                if let Some(parsed) = parse_rfc3339_timestamp(trimmed) {
                    return Some(parsed);
                }
            }
            _ => {}
        }
    }

    None
}

fn normalize_timestamp(value: i64) -> i64 {
    if value > 10_000_000_000 {
        value / 1000
    } else {
        value
    }
}

fn parse_rfc3339_timestamp(value: &str) -> Option<i64> {
    let (date_part, rest) = value.split_once('T')?;
    let (year, month, day) = parse_date(date_part)?;
    let (time_part, offset_seconds) = parse_time_and_offset(rest)?;
    let (hour, minute, second) = parse_time(time_part)?;
    let days = days_from_civil(year, month, day);
    Some(days * 86_400 + hour as i64 * 3_600 + minute as i64 * 60 + second as i64 - offset_seconds)
}

fn parse_date(value: &str) -> Option<(i32, u32, u32)> {
    let mut parts = value.split('-');
    let year = parts.next()?.parse::<i32>().ok()?;
    let month = parts.next()?.parse::<u32>().ok()?;
    let day = parts.next()?.parse::<u32>().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    Some((year, month, day))
}

fn parse_time_and_offset(value: &str) -> Option<(&str, i64)> {
    if let Some(time_part) = value.strip_suffix('Z') {
        return Some((time_part, 0));
    }

    let tz_index = value
        .char_indices()
        .skip(8)
        .find_map(|(index, ch)| matches!(ch, '+' | '-').then_some(index))?;
    let (time_part, offset_part) = value.split_at(tz_index);
    let sign = if offset_part.starts_with('-') { -1 } else { 1 };
    let offset = &offset_part[1..];
    let (hours, minutes) = offset.split_once(':')?;
    let hours = hours.parse::<i64>().ok()?;
    let minutes = minutes.parse::<i64>().ok()?;
    Some((time_part, sign * (hours * 3_600 + minutes * 60)))
}

fn parse_time(value: &str) -> Option<(u32, u32, u32)> {
    let mut parts = value.split(':');
    let hour = parts.next()?.parse::<u32>().ok()?;
    let minute = parts.next()?.parse::<u32>().ok()?;
    let second_part = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let second = second_part
        .split_once('.')
        .map(|(whole, _)| whole)
        .unwrap_or(second_part)
        .parse::<u32>()
        .ok()?;
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    Some((hour, minute, second))
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = year - i32::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = month as i32;
    let day = day as i32;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    (era * 146_097 + day_of_era - 719_468) as i64
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn extract_host_from_uri(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        return reqwest::Url::parse(trimmed)
            .ok()
            .and_then(|url| url.host_str().map(|host| host.to_string()));
    }
    None
}

impl From<SafeLineSecurityEventSummary> for SecurityEventRecord {
    fn from(value: SafeLineSecurityEventSummary) -> Self {
        Self {
            layer: "safeline".to_string(),
            provider: Some("safeline".to_string()),
            provider_site_id: value.provider_site_id,
            provider_site_name: value.provider_site_name,
            provider_site_domain: value.provider_site_domain,
            action: value.action,
            reason: value.reason,
            source_ip: value.source_ip,
            dest_ip: value.dest_ip,
            source_port: value.source_port,
            dest_port: value.dest_port,
            protocol: value.protocol,
            http_method: value.http_method,
            uri: value.uri,
            http_version: value.http_version,
            created_at: value.created_at,
            handled: false,
            handled_at: None,
        }
    }
}

impl From<SafeLineBlockedIpSummary> for BlockedIpRecord {
    fn from(value: SafeLineBlockedIpSummary) -> Self {
        Self {
            provider: Some("safeline".to_string()),
            provider_remote_id: value.remote_id,
            ip: value.ip,
            reason: value.reason,
            blocked_at: value.blocked_at,
            expires_at: value.expires_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_sites_supports_nested_data_list() {
        let payload = json!({
            "data": {
                "list": [
                    {
                        "uuid": "site-1",
                        "name": "portal",
                        "domain": "portal.example.com",
                        "status": "running"
                    }
                ]
            }
        });

        let sites = extract_sites(&payload).unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].id, "site-1");
        assert_eq!(sites[0].name, "portal");
    }

    #[test]
    fn extract_sites_supports_top_level_array() {
        let payload = json!([
            {
                "id": 1,
                "site_name": "api",
                "host": "api.example.com",
                "enabled": true
            }
        ]);

        let sites = extract_sites(&payload).unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].id, "1");
        assert_eq!(sites[0].domain, "api.example.com");
        assert_eq!(sites[0].status, "true");
    }

    #[test]
    fn extract_sites_supports_open_site_payload() {
        let payload = json!({
            "total": 1,
            "data": [
                {
                    "id": 7,
                    "title": "portal",
                    "comment": "portal-comment",
                    "server_names": ["portal.example.com", "www.example.com"],
                    "mode": 0
                }
            ]
        });

        let sites = extract_sites(&payload).unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].id, "7");
        assert_eq!(sites[0].name, "portal");
        assert_eq!(sites[0].domain, "portal.example.com");
        assert_eq!(sites[0].status, "0");
    }

    #[test]
    fn extract_sites_supports_nested_data_data_payload() {
        let payload = json!({
            "data": {
                "data": [
                    {
                        "id": 13,
                        "title": "2tos",
                        "server_names": ["2tos.cn", "www.2tos.cn"],
                        "is_enabled": true
                    }
                ],
                "total": 1
            },
            "err": null,
            "msg": ""
        });

        let sites = extract_sites(&payload).unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].id, "13");
        assert_eq!(sites[0].name, "2tos");
        assert_eq!(sites[0].domain, "2tos.cn");
    }

    #[test]
    fn extract_security_events_supports_list_payload() {
        let payload = json!({
            "data": {
                "list": [
                    {
                        "src_ip": "203.0.113.10",
                        "dst_ip": "10.0.0.10",
                        "action": "block",
                        "attack_type": "sqli",
                        "uri": "/login",
                        "method": "POST",
                        "created_at": 1710000000
                    }
                ]
            }
        });

        let events = extract_security_events(&payload).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].action, "block");
        assert_eq!(events[0].source_ip, "203.0.113.10");
        assert_eq!(events[0].uri.as_deref(), Some("/login"));
    }

    #[test]
    fn extract_security_events_supports_open_records_payload() {
        let payload = json!({
            "total": 1,
            "data": [
                {
                    "event_id": "evt-1",
                    "src_ip": "2.2.2.2",
                    "website": "https://portal.example.com/login",
                    "reason": "sqli",
                    "attack_type": 4,
                    "timestamp": 1710000000,
                    "site_id": 99,
                    "site_title": "portal",
                    "site_server_names": ["portal.example.com"]
                }
            ]
        });

        let events = extract_security_events(&payload).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].provider_site_id.as_deref(), Some("99"));
        assert_eq!(events[0].provider_site_name.as_deref(), Some("portal"));
        assert_eq!(
            events[0].provider_site_domain.as_deref(),
            Some("portal.example.com")
        );
    }

    #[test]
    fn extract_blocked_ips_supports_open_ipgroup_nodes() {
        let payload = json!({
            "total": 1,
            "nodes": [
                {
                    "id": 12,
                    "reference": "manual",
                    "comment": "ops",
                    "ips": ["198.51.100.10"],
                    "updated_at": "1710000000",
                    "builtin": false
                }
            ]
        });

        let ips = extract_blocked_ips(&payload).unwrap();
        assert_eq!(ips.len(), 1);
        assert_eq!(ips[0].ip, "198.51.100.10");
        assert_eq!(ips[0].remote_id.as_deref(), Some("12"));
    }

    #[test]
    fn extract_blocked_ips_supports_nested_open_ipgroup_payload_with_multiple_ips() {
        let payload = json!({
            "data": {
                "nodes": [
                    {
                        "id": 7,
                        "comment": "manual",
                        "ips": ["198.51.100.10", "198.51.100.11"],
                        "updated_at": "2026-04-10T01:03:27.134874+08:00"
                    }
                ],
                "total": 1
            },
            "err": null,
            "msg": ""
        });

        let ips = extract_blocked_ips(&payload).unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].ip, "198.51.100.10");
        assert_eq!(ips[1].ip, "198.51.100.11");
        assert_eq!(ips[0].remote_id.as_deref(), Some("7"));
        assert_eq!(ips[0].reason, "safeline:manual");
        assert_eq!(ips[0].blocked_at, 1775754207);
    }

    #[test]
    fn extract_blocked_ips_supports_open_ipgroup_payload_with_empty_ips() {
        let payload = json!({
            "data": {
                "nodes": [
                    {
                        "id": 1,
                        "comment": "雷池社区恶意 IP 情报",
                        "ips": [],
                        "reference": "",
                        "builtin": true,
                        "updated_at": "2026-04-10T01:03:27.134874+08:00",
                        "total": 0
                    },
                    {
                        "id": 2,
                        "comment": "搜索引擎爬虫 IP",
                        "ips": [],
                        "reference": "",
                        "builtin": true,
                        "updated_at": "2026-04-10T02:07:31.105448+08:00",
                        "total": 0
                    }
                ],
                "total": 2
            },
            "err": null,
            "msg": ""
        });

        let ips = extract_blocked_ips(&payload).unwrap();
        assert!(ips.is_empty());
    }

    #[test]
    fn encrypt_password_matches_safeline_login_shape() {
        let encoded = encrypt_password("KvJFHAoYlLU9xI4j", "260b8bf4f0b6e877", "Qq203342").unwrap();
        let decoded = BASE64.decode(encoded).unwrap();
        assert!(decoded.starts_with(b"260b8bf4f0b6e877"));
        assert!(decoded.len() > 16);
    }

    #[test]
    fn has_any_auth_supports_username_password() {
        let config = SafeLineConfig {
            username: "wnluo".to_string(),
            password: "Qq203342".to_string(),
            ..SafeLineConfig::default()
        };
        assert!(has_any_auth(&config));
        assert!(has_username_password(&config));
    }

    #[test]
    fn open_ipgroup_action_paths_prefers_append_and_remove_suffixes() {
        assert_eq!(
            open_ipgroup_action_paths("/api/open/ipgroup", OPEN_BLOCKLIST_APPEND_SUFFIX),
            vec![
                "/api/open/ipgroup/append".to_string(),
                "/api/open/ipgroup".to_string(),
            ]
        );
        assert_eq!(
            open_ipgroup_action_paths("/api/open/ipgroup/remove", OPEN_BLOCKLIST_REMOVE_SUFFIX),
            vec![
                "/api/open/ipgroup/remove".to_string(),
                "/api/open/ipgroup".to_string(),
            ]
        );
    }

    #[test]
    fn configured_ip_group_ids_requires_non_empty_values() {
        let config = SafeLineConfig {
            blocklist_ip_group_ids: vec!["  ".to_string(), "12".to_string(), "12".to_string()],
            ..SafeLineConfig::default()
        };
        assert_eq!(
            configured_ip_group_ids(&config).unwrap(),
            vec!["12".to_string()]
        );

        let empty_config = SafeLineConfig::default();
        assert!(configured_ip_group_ids(&empty_config).is_err());
    }
}
