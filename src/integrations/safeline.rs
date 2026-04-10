use crate::config::SafeLineConfig;
use crate::storage::SecurityEventRecord;
use anyhow::{anyhow, Result};
use reqwest::{Client, StatusCode};
use serde::Serialize;
use serde_json::Value;
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

pub async fn probe(config: &SafeLineConfig) -> Result<SafeLineProbeResult> {
    let base_url = normalize_base_url(&config.base_url)?;
    let openapi_doc_url = format!("{base_url}{}", config.openapi_doc_path);
    let auth_probe_url = format!("{base_url}{}", config.auth_probe_path);

    let client = build_client(config)?;

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

pub async fn list_sites(config: &SafeLineConfig) -> Result<Vec<SafeLineSiteSummary>> {
    let base_url = normalize_base_url(&config.base_url)?;
    if config.api_token.trim().is_empty() {
        return Err(anyhow!("未填写 API Token，无法读取雷池站点列表"));
    }

    let client = build_client(config)?;
    let site_list_url = format!("{base_url}{}", config.site_list_path);
    let response = client
        .get(&site_list_url)
        .header("API-TOKEN", config.api_token.trim())
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!(
            "雷池站点列表接口返回 HTTP {}，请检查 site_list_path 是否与目标实例版本匹配",
            status
        ));
    }

    let payload = response.json::<Value>().await?;
    extract_sites(&payload)
}

pub async fn list_security_events(
    config: &SafeLineConfig,
) -> Result<Vec<SafeLineSecurityEventSummary>> {
    let base_url = normalize_base_url(&config.base_url)?;
    if config.api_token.trim().is_empty() {
        return Err(anyhow!("未填写 API Token，无法读取雷池事件列表"));
    }

    let client = build_client(config)?;
    let event_list_url = format!("{base_url}{}", config.event_list_path);
    let response = client
        .get(&event_list_url)
        .header("API-TOKEN", config.api_token.trim())
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(anyhow!(
            "雷池事件接口返回 HTTP {}，请检查 event_list_path 是否与目标实例版本匹配",
            status
        ));
    }

    let payload = response.json::<Value>().await?;
    extract_security_events(&payload)
}

fn build_client(config: &SafeLineConfig) -> Result<Client> {
    Ok(Client::builder()
        .danger_accept_invalid_certs(!config.verify_tls)
        .timeout(Duration::from_secs(10))
        .build()?)
}

fn normalize_base_url(value: &str) -> Result<String> {
    let base_url = value.trim().trim_end_matches('/').to_string();
    if base_url.is_empty() {
        return Err(anyhow!("雷池地址不能为空"));
    }
    Ok(base_url)
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

fn find_array_candidates<'a>(value: &'a Value) -> Vec<&'a Vec<Value>> {
    let mut candidates = Vec::new();

    if let Some(array) = value.as_array() {
        candidates.push(array);
    }

    if let Some(object) = value.as_object() {
        for key in [
            "data",
            "list",
            "items",
            "results",
            "rows",
            "records",
            "objs",
            "objects",
        ] {
            if let Some(array) = object.get(key).and_then(Value::as_array) {
                candidates.push(array);
            }

            if let Some(array) = object
                .get(key)
                .and_then(Value::as_object)
                .and_then(|child| child.get("list"))
                .and_then(Value::as_array)
            {
                candidates.push(array);
            }
        }
    }

    candidates
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
    .unwrap_or_default();
    let status = pick_string(object, &["status", "state", "enabled"])
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
    let dest_ip =
        pick_string(object, &["dst_ip", "dest_ip", "server_ip"]).unwrap_or_default();
    let action = pick_string(object, &["action", "decision", "event_type", "type"])
        .unwrap_or_else(|| "alert".to_string());
    let attack_type = pick_string(object, &["attack_type", "rule_type", "category"]);
    let reason = pick_string(object, &["reason", "message", "description", "rule_name"])
        .or(attack_type.clone())
        .unwrap_or_else(|| "safeline_event".to_string());
    let uri = pick_string(object, &["uri", "path", "url", "request_uri"]);
    let http_method = pick_string(object, &["method", "http_method", "request_method"]);
    let http_version = pick_string(object, &["http_version", "version"]);
    let protocol = pick_string(object, &["protocol", "scheme"])
        .unwrap_or_else(|| "HTTP".to_string());
    let source_port = pick_i64(object, &["src_port", "source_port", "client_port"]).unwrap_or(0);
    let dest_port = pick_i64(object, &["dst_port", "dest_port", "server_port"]).unwrap_or(0);
    let created_at = pick_i64(
        object,
        &["created_at", "timestamp", "time", "occurred_at", "attack_time"],
    )
    .unwrap_or_else(unix_timestamp);

    Some(SafeLineSecurityEventSummary {
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

fn pick_string(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
) -> Option<String> {
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

fn normalize_timestamp(value: i64) -> i64 {
    if value > 10_000_000_000 {
        value / 1000
    } else {
        value
    }
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

impl From<SafeLineSecurityEventSummary> for SecurityEventRecord {
    fn from(value: SafeLineSecurityEventSummary) -> Self {
        Self {
            layer: "safeline".to_string(),
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
}
