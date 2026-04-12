use super::payload::{
    extract_blocked_ips, extract_certificates, extract_security_events, extract_sites,
    parse_certificate_detail,
};
use super::sync_helpers::{
    body_or_status, build_site_upsert_payload, candidate_paths, configured_ip_group_ids,
    extract_write_response_id_from_body, format_failure, normalized_or_default,
    open_ipgroup_action_paths, DEFAULT_BLOCKLIST_PATH, OPEN_BLOCKLIST_APPEND_SUFFIX,
    OPEN_BLOCKLIST_REMOVE_SUFFIX,
};
use super::{
    SafeLineBlockedIpDeleteSummary, SafeLineBlockedIpSummary, SafeLineBlockedIpSyncSummary,
    SafeLineCertificateDetail, SafeLineCertificateSummary, SafeLineCertificateUpsert,
    SafeLineCertificateWriteSummary, SafeLineProbeResult, SafeLineSecurityEventSummary,
    SafeLineSiteSummary, SafeLineSiteUpsert, SafeLineSiteWriteSummary,
};
use crate::config::SafeLineConfig;
use crate::storage::BlockedIpEntry;
use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rand::{distributions::Alphanumeric, Rng};
use reqwest::{Client, RequestBuilder, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use std::process::{Command, Stdio};
use std::time::Duration;

const DEFAULT_OPENAPI_DOC_PATH: &str = "/openapi_doc/";
const DEFAULT_AUTH_PROBE_PATH: &str = "/api/open/system/key";
const LEGACY_AUTH_PROBE_PATH: &str = "/api/IPGroupAPI";
const DEFAULT_SITE_LIST_PATH: &str = "/api/open/site";
const LEGACY_SITE_LIST_PATH: &str = "/api/WebsiteAPI";
const DEFAULT_EVENT_LIST_PATH: &str = "/api/open/records";
const LEGACY_EVENT_LIST_PATH: &str = "/api/AttackLogAPI";
const LEGACY_BLOCKLIST_PATH: &str = "/api/IPGroupAPI";
const DEFAULT_CERT_PATH: &str = "/api/open/cert";
const LOGIN_AES_KEY_PATH: &str = "/api/open/system/key";
const LOGIN_CSRF_PATH: &str = "/api/open/auth/csrf";
const LOGIN_PATH: &str = "/api/open/auth/login";

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

enum SiteWriteAttempt {
    Post(String, Value),
    Put(String, Value),
}

impl SiteWriteAttempt {
    fn path(&self) -> &str {
        match self {
            Self::Post(path, _) | Self::Put(path, _) => path,
        }
    }
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

pub async fn list_certificates(config: &SafeLineConfig) -> Result<Vec<SafeLineCertificateSummary>> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法读取雷池证书列表"
        ));
    }

    let client = build_client(config)?;
    let payload = get_json_with_fallback(
        &client,
        &base_url,
        config,
        &candidate_paths(DEFAULT_CERT_PATH, &[DEFAULT_CERT_PATH]),
        "证书列表",
    )
    .await?;
    extract_certificates(&payload)
}

pub async fn load_certificate(
    config: &SafeLineConfig,
    certificate_id: &str,
) -> Result<SafeLineCertificateDetail> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法读取雷池证书详情"
        ));
    }

    let client = build_client(config)?;
    let url = format!(
        "{base_url}{}/{}",
        normalized_or_default(DEFAULT_CERT_PATH, DEFAULT_CERT_PATH),
        certificate_id.trim()
    );
    let (status, body) = send_with_auth(&client, &base_url, config, |auth| {
        with_auth_headers(client.get(&url), auth)
    })
    .await?;

    if !status.is_success() {
        return Err(anyhow!(
            "雷池证书详情接口返回 HTTP {}：{}",
            status,
            body.trim()
        ));
    }

    let payload = serde_json::from_str::<Value>(&body)
        .map_err(|err| anyhow!("雷池证书详情返回了不可解析的 JSON：{}", err))?;
    parse_certificate_detail(&payload).ok_or_else(|| {
        anyhow!(
            "已拿到雷池证书详情响应，但未能识别证书内容。请检查 /api/open/cert/{{id}} 的返回结构。"
        )
    })
}

pub async fn create_certificate(
    config: &SafeLineConfig,
    certificate: &SafeLineCertificateUpsert,
) -> Result<SafeLineCertificateWriteSummary> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法创建雷池证书"
        ));
    }

    let client = build_client(config)?;
    let path = normalized_or_default(DEFAULT_CERT_PATH, DEFAULT_CERT_PATH);
    let url = format!("{base_url}{path}");
    let payload = serde_json::json!({
        "type": 2,
        "domains": certificate.domains,
        "manual": {
            "crt": certificate.certificate_pem,
            "key": certificate.private_key_pem,
        }
    });

    let (status, body) = send_with_auth(&client, &base_url, config, |auth| {
        with_auth_headers(client.post(&url).json(&payload), auth)
    })
    .await?;

    if status.is_success() {
        let remote_id = extract_write_response_id_from_body(&body);
        return Ok(SafeLineCertificateWriteSummary {
            remote_id,
            accepted: true,
            status_code: status.as_u16(),
            message: body_or_status(status, &body),
        });
    }

    Ok(SafeLineCertificateWriteSummary {
        remote_id: None,
        accepted: false,
        status_code: status.as_u16(),
        message: body_or_status(status, &body),
    })
}

pub async fn update_certificate(
    config: &SafeLineConfig,
    remote_id: &str,
    certificate: &SafeLineCertificateUpsert,
) -> Result<SafeLineCertificateWriteSummary> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法更新雷池证书"
        ));
    }

    let remote_id = remote_id.trim();
    if remote_id.is_empty() {
        return Err(anyhow!("remote_id 不能为空"));
    }

    let client = build_client(config)?;
    let path = normalized_or_default(DEFAULT_CERT_PATH, DEFAULT_CERT_PATH);
    let url = format!("{base_url}{path}");
    let payload = serde_json::json!({
        "id": remote_id,
        "type": 2,
        "domains": certificate.domains,
        "manual": {
            "crt": certificate.certificate_pem,
            "key": certificate.private_key_pem,
        }
    });

    let attempts = [
        ("PUT", format!("{url}/{remote_id}"), payload.clone()),
        ("PUT", url.clone(), payload.clone()),
        ("POST", url, payload),
    ];

    let mut last_failure = SafeLineCertificateWriteSummary {
        remote_id: Some(remote_id.to_string()),
        accepted: false,
        status_code: StatusCode::BAD_GATEWAY.as_u16(),
        message: "未执行任何证书写入尝试".to_string(),
    };

    for (method, url, payload) in attempts {
        let (status, body) = send_with_auth(&client, &base_url, config, |auth| match method {
            "PUT" => with_auth_headers(client.put(&url).json(&payload), auth),
            _ => with_auth_headers(client.post(&url).json(&payload), auth),
        })
        .await?;

        if status.is_success() {
            return Ok(SafeLineCertificateWriteSummary {
                remote_id: extract_write_response_id_from_body(&body)
                    .or_else(|| Some(remote_id.to_string())),
                accepted: true,
                status_code: status.as_u16(),
                message: body_or_status(status, &body),
            });
        }

        last_failure = SafeLineCertificateWriteSummary {
            remote_id: Some(remote_id.to_string()),
            accepted: false,
            status_code: status.as_u16(),
            message: body_or_status(status, &body),
        };
    }

    Ok(last_failure)
}

pub async fn upsert_site(
    config: &SafeLineConfig,
    site: &SafeLineSiteUpsert,
) -> Result<SafeLineSiteWriteSummary> {
    let base_url = normalize_base_url(&config.base_url)?;
    if !has_any_auth(config) {
        return Err(anyhow!(
            "未填写 API Token，且未配置雷池账号密码，无法写入雷池站点"
        ));
    }

    let client = build_client(config)?;
    let path = normalized_or_default(&config.site_list_path, DEFAULT_SITE_LIST_PATH);
    let base_payload = build_site_upsert_payload(site);
    let mut attempts = Vec::new();

    if let Some(remote_id) = site.remote_id.as_deref() {
        let remote_id = remote_id.trim();
        if !remote_id.is_empty() {
            attempts.push(SiteWriteAttempt::Put(
                format!("{path}/{remote_id}"),
                base_payload.clone(),
            ));
            let mut payload_with_id = base_payload.clone();
            if let Some(object) = payload_with_id.as_object_mut() {
                object.insert("id".to_string(), Value::String(remote_id.to_string()));
            }
            attempts.push(SiteWriteAttempt::Put(path.clone(), payload_with_id.clone()));
            attempts.push(SiteWriteAttempt::Post(path.clone(), payload_with_id));
        }
    } else {
        attempts.push(SiteWriteAttempt::Post(path.clone(), base_payload.clone()));
    }

    if attempts.is_empty() {
        attempts.push(SiteWriteAttempt::Post(path.clone(), base_payload));
    }

    let mut last_failure = SafeLineSiteWriteSummary {
        remote_id: site.remote_id.clone(),
        accepted: false,
        status_code: StatusCode::BAD_GATEWAY.as_u16(),
        message: "未执行任何站点写入尝试".to_string(),
    };

    for attempt in attempts {
        let (status, body) = send_with_auth(&client, &base_url, config, |auth| {
            let url = format!("{base_url}{}", attempt.path());
            match &attempt {
                SiteWriteAttempt::Post(_, payload) => {
                    with_auth_headers(client.post(&url).json(payload), auth)
                }
                SiteWriteAttempt::Put(_, payload) => {
                    with_auth_headers(client.put(&url).json(payload), auth)
                }
            }
        })
        .await?;

        if status.is_success() {
            return Ok(SafeLineSiteWriteSummary {
                remote_id: extract_write_response_id_from_body(&body)
                    .or_else(|| site.remote_id.clone()),
                accepted: true,
                status_code: status.as_u16(),
                message: body_or_status(status, &body),
            });
        }

        last_failure = SafeLineSiteWriteSummary {
            remote_id: site.remote_id.clone(),
            accepted: false,
            status_code: status.as_u16(),
            message: format_failure(attempt.path(), status, &body),
        };
    }

    Ok(last_failure)
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

    let base_path = super::sync_helpers::open_ipgroup_base_path(path);
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
