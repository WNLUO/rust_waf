use super::SafeLineSiteUpsert;
use crate::config::SafeLineConfig;
use anyhow::{anyhow, Result};
use reqwest::StatusCode;
use serde_json::Value;
use std::collections::HashSet;

pub(super) const DEFAULT_BLOCKLIST_PATH: &str = "/api/open/ipgroup";
pub(super) const OPEN_BLOCKLIST_APPEND_SUFFIX: &str = "/append";
pub(super) const OPEN_BLOCKLIST_REMOVE_SUFFIX: &str = "/remove";

pub(super) fn normalized_or_default(value: &str, default: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

pub(super) fn candidate_paths(current: &str, fallbacks: &[&str]) -> Vec<String> {
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

pub(super) fn format_failure(path: &str, status: StatusCode, body: &str) -> String {
    if body.trim().is_empty() {
        format!("{path} -> HTTP {status}")
    } else {
        format!("{path} -> HTTP {status}: {}", body.trim())
    }
}

pub(super) fn body_or_status(status: StatusCode, body: &str) -> String {
    if body.trim().is_empty() {
        status.to_string()
    } else {
        body.trim().to_string()
    }
}

pub(super) fn configured_ip_group_ids(config: &SafeLineConfig) -> Result<Vec<String>> {
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

pub(super) fn open_ipgroup_base_path(path: &str) -> String {
    let normalized = normalized_or_default(path, DEFAULT_BLOCKLIST_PATH);
    if let Some(base) = normalized.strip_suffix(OPEN_BLOCKLIST_APPEND_SUFFIX) {
        return base.to_string();
    }
    if let Some(base) = normalized.strip_suffix(OPEN_BLOCKLIST_REMOVE_SUFFIX) {
        return base.to_string();
    }
    normalized
}

pub(super) fn open_ipgroup_action_paths(path: &str, suffix: &str) -> Vec<String> {
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

pub(super) fn extract_write_response_id_from_body(body: &str) -> Option<String> {
    let payload = serde_json::from_str::<Value>(body).ok()?;
    extract_write_response_id(&payload)
}

fn extract_write_response_id(payload: &Value) -> Option<String> {
    for candidate in find_object_candidates(payload) {
        if let Some(id) = pick_string(candidate, &["id", "site_id", "cert_id", "uuid", "uid"]) {
            return Some(id);
        }
    }
    None
}

pub(super) fn build_site_upsert_payload(site: &SafeLineSiteUpsert) -> Value {
    let primary_name = site
        .server_names
        .first()
        .cloned()
        .unwrap_or_else(|| site.name.clone());

    serde_json::json!({
        "comment": site.notes,
        "title": site.name,
        "server_names": site.server_names,
        "ports": site.ports,
        "upstreams": site.upstreams,
        "is_enabled": site.enabled,
        "health_check": site.health_check,
        "cert_id": site.cert_id.unwrap_or_default(),
        "cert_type": if site.cert_id.is_some() { 0 } else { -1 },
        "group_id": 0,
        "mode": 0,
        "static": false,
        "type": 0,
        "index": "index.html",
        "static_default": 1,
        "redirect_status_code": 301,
        "load_balance": { "balance_type": 1 },
        "acl_enabled": false,
        "portal": false,
        "portal_redirect": "",
        "position": 0,
        "cc_bot": false,
        "semantics": true,
        "name": primary_name,
    })
}

fn find_object_candidates(value: &Value) -> Vec<&serde_json::Map<String, Value>> {
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

#[cfg(test)]
mod tests {
    use super::*;

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
