use super::{
    SafeLineBlockedIpSummary, SafeLineCertificateDetail, SafeLineCertificateSummary,
    SafeLineSecurityEventSummary, SafeLineSiteSummary,
};
use crate::storage::{BlockedIpRecord, SecurityEventRecord};
use anyhow::{anyhow, Result};
use serde_json::Value;

pub(super) fn extract_sites(payload: &Value) -> Result<Vec<SafeLineSiteSummary>> {
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

pub(super) fn extract_security_events(
    payload: &Value,
) -> Result<Vec<SafeLineSecurityEventSummary>> {
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

pub(super) fn extract_blocked_ips(payload: &Value) -> Result<Vec<SafeLineBlockedIpSummary>> {
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

pub(super) fn extract_certificates(payload: &Value) -> Result<Vec<SafeLineCertificateSummary>> {
    let candidates = find_array_candidates(payload);
    for candidate in candidates {
        let certificates = candidate
            .iter()
            .filter_map(parse_certificate_summary)
            .collect::<Vec<_>>();
        if !certificates.is_empty() {
            return Ok(certificates);
        }
    }

    Err(anyhow!(
        "已拿到雷池响应，但未能从 JSON 中识别证书数组。请检查 /api/open/cert 的返回结构。"
    ))
}

pub(super) fn parse_certificate_detail(payload: &Value) -> Option<SafeLineCertificateDetail> {
    let object = find_object_candidates(payload)
        .into_iter()
        .find(|candidate| candidate.contains_key("manual") || candidate.contains_key("acme"))?;
    let id = pick_string(object, &["id", "cert_id", "uuid", "uid"])?;
    let manual = object.get("manual").and_then(Value::as_object);
    let acme = object.get("acme").and_then(Value::as_object);
    let domains = pick_array_strings(object, &["domains"])
        .or_else(|| acme.and_then(|item| pick_array_strings(item, &["domains"])))
        .unwrap_or_default();

    Some(SafeLineCertificateDetail {
        id,
        domains,
        cert_type: pick_i64(object, &["type", "cert_type"]),
        certificate_pem: manual.and_then(|item| pick_string(item, &["crt", "cert", "fullchain"])),
        private_key_pem: manual.and_then(|item| pick_string(item, &["key", "private_key"])),
        raw: payload.clone(),
    })
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

fn find_object_candidates<'a>(value: &'a Value) -> Vec<&'a serde_json::Map<String, Value>> {
    let mut candidates = Vec::new();
    collect_object_candidates(value, &mut candidates);
    candidates
}

fn collect_object_candidates<'a>(
    value: &'a Value,
    candidates: &mut Vec<&'a serde_json::Map<String, Value>>,
) {
    if let Some(object) = value.as_object() {
        candidates.push(object);
        for child in object.values() {
            collect_object_candidates(child, candidates);
        }
        return;
    }

    if let Some(array) = value.as_array() {
        for item in array {
            collect_object_candidates(item, candidates);
        }
    }
}

fn parse_site_summary(value: &Value) -> Option<SafeLineSiteSummary> {
    let object = value.as_object()?;
    let server_names = pick_array_strings(object, &["server_names", "hosts"]).unwrap_or_default();
    let ports = pick_array_strings(object, &["ports"]).unwrap_or_default();
    let ssl_ports = ports
        .iter()
        .filter(|port| port.to_ascii_lowercase().contains("ssl"))
        .cloned()
        .collect::<Vec<_>>();
    let upstreams = pick_array_strings(object, &["upstreams"]).unwrap_or_default();
    let enabled = pick_bool(object, &["is_enabled", "enabled"]);
    let cert_id = pick_i64(object, &["cert_id"]);
    let cert_type = pick_i64(object, &["cert_type"]);
    let cert_filename = pick_string(object, &["cert_filename"]);
    let key_filename = pick_string(object, &["key_filename"]);
    let health_check = pick_bool(object, &["health_check"]);
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
    .or_else(|| server_names.first().cloned())
    .unwrap_or_default();
    let status = enabled
        .map(|value| {
            if value {
                "enabled".to_string()
            } else {
                "disabled".to_string()
            }
        })
        .or_else(|| pick_string(object, &["status", "state", "mode"]))
        .unwrap_or_else(|| "unknown".to_string());
    let ssl_enabled = !ssl_ports.is_empty()
        || cert_id.unwrap_or_default() > 0
        || cert_filename
            .as_ref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);

    Some(SafeLineSiteSummary {
        id,
        name,
        domain,
        status,
        enabled,
        server_names,
        ports,
        ssl_ports,
        upstreams,
        ssl_enabled,
        cert_id,
        cert_type,
        cert_filename,
        key_filename,
        health_check,
        raw: value.clone(),
    })
}

fn parse_certificate_summary(value: &Value) -> Option<SafeLineCertificateSummary> {
    let object = value.as_object()?;
    let id = pick_string(object, &["id", "cert_id", "uuid", "uid"])?;
    let domains = pick_array_strings(object, &["domains"])
        .or_else(|| pick_array_strings(object, &["related_sites"]))
        .unwrap_or_default();

    Some(SafeLineCertificateSummary {
        id,
        domains,
        issuer: pick_string(object, &["issuer"]).unwrap_or_default(),
        trusted: pick_bool(object, &["trusted"]).unwrap_or(false),
        revoked: pick_bool(object, &["revoked"]).unwrap_or(false),
        expired: pick_bool(object, &["expired"]).unwrap_or(false),
        cert_type: pick_i64(object, &["type", "cert_type"]),
        valid_from: pick_timestamp(object, &["valid_after", "valid_from", "created_at"]),
        valid_to: pick_timestamp(object, &["valid_before", "valid_to", "expires_at"]),
        related_sites: pick_array_strings(object, &["related_sites"]).unwrap_or_default(),
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

fn pick_bool(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<bool> {
    for key in keys {
        let Some(value) = object.get(*key) else {
            continue;
        };

        match value {
            Value::Bool(flag) => return Some(*flag),
            Value::Number(number) => {
                if let Some(parsed) = number.as_i64() {
                    return Some(parsed != 0);
                }
            }
            Value::String(inner) => {
                let normalized = inner.trim().to_ascii_lowercase();
                match normalized.as_str() {
                    "true" | "1" | "yes" | "on" | "enabled" => return Some(true),
                    "false" | "0" | "no" | "off" | "disabled" => return Some(false),
                    _ => {}
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
                "enabled": true,
                "ports": ["80", "443_ssl"],
                "upstreams": ["http://127.0.0.1:8080"],
                "cert_id": 9
            }
        ]);

        let sites = extract_sites(&payload).unwrap();
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].id, "1");
        assert_eq!(sites[0].domain, "api.example.com");
        assert_eq!(sites[0].status, "enabled");
        assert_eq!(sites[0].ports, vec!["80", "443_ssl"]);
        assert_eq!(sites[0].ssl_ports, vec!["443_ssl"]);
        assert_eq!(sites[0].upstreams, vec!["http://127.0.0.1:8080"]);
        assert_eq!(sites[0].cert_id, Some(9));
        assert!(sites[0].ssl_enabled);
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
                    "ports": ["443_ssl"],
                    "upstreams": ["https://127.0.0.1:9443"],
                    "cert_type": 2,
                    "cert_filename": "portal.crt",
                    "key_filename": "portal.key",
                    "health_check": true,
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
        assert_eq!(
            sites[0].server_names,
            vec!["portal.example.com", "www.example.com"]
        );
        assert_eq!(sites[0].ssl_ports, vec!["443_ssl"]);
        assert_eq!(sites[0].upstreams, vec!["https://127.0.0.1:9443"]);
        assert_eq!(sites[0].cert_type, Some(2));
        assert_eq!(sites[0].cert_filename.as_deref(), Some("portal.crt"));
        assert_eq!(sites[0].key_filename.as_deref(), Some("portal.key"));
        assert_eq!(sites[0].health_check, Some(true));
        assert!(sites[0].ssl_enabled);
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
        assert_eq!(sites[0].enabled, Some(true));
        assert_eq!(sites[0].status, "enabled");
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
}
