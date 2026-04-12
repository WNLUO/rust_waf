use super::{Config, RuntimeProfile};
use std::env;
use std::net::SocketAddr;

pub(super) fn clamp_or_default(value: usize, default: usize) -> usize {
    if value == 0 {
        default
    } else {
        value
    }
}

pub(super) fn clamp_u64(value: u64, min: u64, max: u64, default: u64) -> u64 {
    let value = if value == 0 { default } else { value };
    value.clamp(min, max)
}

pub(super) fn clamp_scale(value: f64, default: f64, min: f64, max: f64) -> f64 {
    let initial = if value == 0.0 { default } else { value };
    initial.clamp(min, max)
}

pub(super) fn default_gateway_name() -> String {
    "玄枢防护网关".to_string()
}

pub(super) const fn default_auto_refresh_seconds() -> u32 {
    5
}

pub(super) const fn default_sqlite_enabled() -> bool {
    true
}

pub(super) const fn default_sqlite_rules_enabled() -> bool {
    true
}

pub(super) fn default_notification_level() -> String {
    "critical".to_string()
}

pub(super) const fn default_safeline_enabled() -> bool {
    true
}

pub(super) const fn default_retain_days() -> u32 {
    30
}

pub(super) const fn default_verify_tls() -> bool {
    false
}

pub(super) fn default_openapi_doc_path() -> String {
    "/openapi_doc/".to_string()
}

pub(super) fn default_auth_probe_path() -> String {
    "/api/open/system/key".to_string()
}

pub(super) fn default_site_list_path() -> String {
    "/api/open/site".to_string()
}

pub(super) fn default_event_list_path() -> String {
    "/api/open/records".to_string()
}

pub(super) fn default_blocklist_sync_path() -> String {
    "/api/open/ipgroup".to_string()
}

pub(super) fn default_blocklist_delete_path() -> String {
    "/api/open/ipgroup".to_string()
}

pub(super) const fn default_safeline_auto_sync_interval_secs() -> u64 {
    300
}

pub(super) const fn default_admin_api_audit_enabled() -> bool {
    true
}

pub(super) fn normalize_notification_level(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "all" => "all".to_string(),
        "blocked_only" => "blocked_only".to_string(),
        _ => "critical".to_string(),
    }
}

pub(super) fn normalize_base_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
}

pub(super) fn normalize_path(value: &str, default: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return default.to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

pub(super) fn normalize_string_list(values: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if normalized.iter().any(|item| item == trimmed) {
            continue;
        }
        normalized.push(trimmed.to_string());
    }
    normalized
}

pub fn resolve_sqlite_path() -> String {
    env::var("WAF_SQLITE_PATH").unwrap_or_else(|_| default_sqlite_path())
}

pub fn apply_env_overrides(mut config: Config) -> Config {
    if let Ok(value) = env::var("WAF_RUNTIME_PROFILE") {
        match value.trim().to_ascii_lowercase().as_str() {
            "minimal" => config.runtime_profile = RuntimeProfile::Minimal,
            "standard" => config.runtime_profile = RuntimeProfile::Standard,
            other => log::warn!(
                "Unsupported WAF_RUNTIME_PROFILE '{}', keeping SQLite value",
                other
            ),
        }
    }

    if let Ok(value) = env::var("WAF_API_ENABLED") {
        if let Some(parsed) = parse_bool_env(&value) {
            config.api_enabled = parsed;
        } else {
            log::warn!(
                "Unsupported WAF_API_ENABLED '{}', keeping SQLite value",
                value
            );
        }
    }

    if let Ok(value) = env::var("WAF_API_BIND") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            config.api_bind = trimmed.to_string();
        }
    }

    if let Ok(value) = env::var("WAF_LISTEN_ADDRS") {
        let addrs = value
            .split(',')
            .map(|addr| addr.trim().to_string())
            .filter(|addr| !addr.is_empty())
            .collect::<Vec<_>>();
        if !addrs.is_empty() {
            config.listen_addrs = addrs;
        }
    }

    if let Ok(value) = env::var("WAF_TCP_UPSTREAM_ADDR") {
        config.tcp_upstream_addr = non_empty_env(value);
    }

    if let Ok(value) = env::var("WAF_UDP_UPSTREAM_ADDR") {
        config.udp_upstream_addr = non_empty_env(value);
    }

    if let Ok(value) = env::var("WAF_SQLITE_RULES_ENABLED") {
        if let Some(parsed) = parse_bool_env(&value) {
            config.sqlite_rules_enabled = parsed;
        } else {
            log::warn!(
                "Unsupported WAF_SQLITE_RULES_ENABLED '{}', keeping SQLite value",
                value
            );
        }
    }

    if let Ok(value) = env::var("WAF_ADMIN_API_AUTH_ENABLED") {
        if let Some(parsed) = parse_bool_env(&value) {
            config.admin_api_auth.enabled = parsed;
        } else {
            log::warn!(
                "Unsupported WAF_ADMIN_API_AUTH_ENABLED '{}', keeping SQLite value",
                value
            );
        }
    }

    if let Ok(value) = env::var("WAF_ADMIN_API_TOKEN") {
        config.admin_api_auth.bearer_token = value.trim().to_string();
    }

    config
}

fn parse_bool_env(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn non_empty_env(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

pub(super) fn default_sqlite_path() -> String {
    "data/waf.db".to_string()
}

pub(super) fn normalize_https_listen_addr(value: &str) -> std::result::Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }

    if let Ok(port) = trimmed.parse::<u16>() {
        if port == 0 {
            return Err("HTTPS 入口端口不能为 0".to_string());
        }
        return Ok(format!("0.0.0.0:{port}"));
    }

    let addr = trimmed
        .parse::<SocketAddr>()
        .map_err(|err| format!("HTTPS 入口 '{}' 无效: {}", trimmed, err))?;
    if addr.port() == 0 {
        return Err("HTTPS 入口端口不能为 0".to_string());
    }

    Ok(format!("0.0.0.0:{}", addr.port()))
}

pub(super) const fn default_sqlite_auto_migrate() -> bool {
    true
}
