use crate::config::l7::CcDefenseConfig;
use crate::protocol::UnifiedHttpRequest;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

use super::types::*;

pub(super) fn challenge_action_name(mode: HtmlResponseMode) -> &'static str {
    match mode {
        HtmlResponseMode::HtmlChallenge => "challenge",
        HtmlResponseMode::TextOnly => "api_friction",
    }
}

pub(super) fn is_interactive_session(
    request: &UnifiedHttpRequest,
    host: &str,
    verified: bool,
) -> bool {
    let has_stable_identity = cookie_value(request, "rwaf_fp").is_some()
        || request
            .get_header("x-browser-fingerprint-id")
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
    if !has_stable_identity {
        return false;
    }

    let same_origin_referer = referer_host_path(request)
        .map(|(referer_host, _)| referer_host.eq_ignore_ascii_case(host))
        .unwrap_or(false);
    let same_origin_origin = request
        .get_header("origin")
        .and_then(|value| extract_host_from_origin(value))
        .map(|origin_host| origin_host.eq_ignore_ascii_case(host))
        .unwrap_or(false);
    let sec_fetch_site = request
        .get_header("sec-fetch-site")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let same_origin_fetch = matches!(sec_fetch_site.as_str(), "same-origin" | "same-site");
    let x_requested_with = request
        .get_header("x-requested-with")
        .map(|value| value.eq_ignore_ascii_case("XMLHttpRequest"))
        .unwrap_or(false);
    let sec_fetch_mode = request
        .get_header("sec-fetch-mode")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let interactive_fetch =
        x_requested_with || matches!(sec_fetch_mode.as_str(), "navigate" | "cors" | "same-origin");
    let behavior_score_low = request
        .get_metadata("l7.behavior.score")
        .and_then(|value| value.parse::<u32>().ok())
        .map(|score| score <= 10)
        .unwrap_or(false);
    let broad_navigation = request
        .get_metadata("l7.behavior.flags")
        .map(|value| {
            value
                .split(',')
                .any(|flag| flag.trim() == "broad_navigation_context")
        })
        .unwrap_or(false);

    interactive_fetch
        && (same_origin_fetch || same_origin_referer || same_origin_origin)
        && (verified || broad_navigation || behavior_score_low)
}

pub(super) fn is_survival_low_risk_identity_request(
    request: &UnifiedHttpRequest,
    route_path: &str,
) -> bool {
    let method = request.method.to_ascii_uppercase();
    if method != "GET" && method != "HEAD" {
        return false;
    }
    if route_path.starts_with("/api/") {
        return false;
    }

    let Some(identity) = stable_browser_identity(request) else {
        return false;
    };
    if identity.len() < 6 || identity.len() > 128 {
        return false;
    }

    let sec_fetch_site = request
        .get_header("sec-fetch-site")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    if !matches!(sec_fetch_site.as_str(), "same-origin" | "same-site") {
        return false;
    }

    if !is_low_risk_document_or_asset_request(request, route_path) {
        return false;
    }

    request
        .get_metadata("l7.behavior.score")
        .and_then(|value| value.parse::<u32>().ok())
        .map(|score| score <= 20)
        .unwrap_or(true)
}

pub(super) fn is_low_risk_document_or_asset_request(
    request: &UnifiedHttpRequest,
    route_path: &str,
) -> bool {
    if looks_like_static_asset(route_path) {
        return true;
    }
    if route_path == "/" || route_path.ends_with(".html") || route_path.ends_with(".htm") {
        return true;
    }
    if request
        .get_header("sec-fetch-dest")
        .map(|value| value.eq_ignore_ascii_case("document"))
        .unwrap_or(false)
    {
        return true;
    }
    request
        .get_header("accept")
        .map(|value| {
            let accept = value.to_ascii_lowercase();
            accept.contains("text/html") || accept.contains("application/xhtml+xml")
        })
        .unwrap_or(false)
}

fn stable_browser_identity(request: &UnifiedHttpRequest) -> Option<&str> {
    let cookie_fp = cookie_value(request, "rwaf_fp").filter(|value| !value.trim().is_empty());
    let header_fp = request
        .get_header("x-browser-fingerprint-id")
        .map(String::as_str)
        .filter(|value| !value.trim().is_empty());

    match (cookie_fp, header_fp) {
        (Some(cookie), Some(header)) if cookie == header => Some(cookie),
        (Some(cookie), None) => Some(cookie),
        (None, Some(header)) => Some(header),
        _ => None,
    }
}

pub(super) fn challenge_reason_verb(mode: HtmlResponseMode) -> &'static str {
    match mode {
        HtmlResponseMode::HtmlChallenge => "issued challenge",
        HtmlResponseMode::TextOnly => "applied api friction",
    }
}

pub(super) fn challenge_header_value(mode: HtmlResponseMode) -> &'static str {
    match mode {
        HtmlResponseMode::HtmlChallenge => "challenge",
        HtmlResponseMode::TextOnly => "api-friction",
    }
}

pub(super) fn request_client_ip(request: &UnifiedHttpRequest) -> Option<std::net::IpAddr> {
    request
        .client_ip
        .as_deref()
        .and_then(|value| value.parse::<std::net::IpAddr>().ok())
        .or_else(|| {
            request
                .get_metadata("network.client_ip")
                .and_then(|value| value.parse::<std::net::IpAddr>().ok())
        })
}

pub(super) fn classify_request(request: &UnifiedHttpRequest, route_path: &str) -> RequestKind {
    let method = request.method.to_ascii_uppercase();
    let accept = request
        .get_header("accept")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let content_type = request
        .get_header("content-type")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    if is_api_like_request(&method, route_path, &accept, &content_type) {
        return RequestKind::ApiLike;
    }
    if request
        .get_header("sec-fetch-dest")
        .map(|value| value.eq_ignore_ascii_case("document"))
        .unwrap_or(false)
        || ((method == "GET" || method == "HEAD")
            && (accept.contains("text/html")
                || accept.contains("application/xhtml+xml")
                || route_path == "/"
                || route_path.ends_with(".html")
                || route_path.ends_with(".htm")))
    {
        return RequestKind::Document;
    }

    if is_static_asset_request(request, route_path, &method, &accept) {
        return RequestKind::StaticAsset;
    }

    RequestKind::Other
}

pub(super) fn has_static_fetch_dest(request: &UnifiedHttpRequest) -> bool {
    request
        .get_header("sec-fetch-dest")
        .map(|value| {
            matches!(
                value.to_ascii_lowercase().as_str(),
                "image" | "style" | "script" | "font" | "video" | "audio" | "manifest"
            )
        })
        .unwrap_or(false)
}

pub(super) fn is_api_like_request(
    method: &str,
    route_path: &str,
    accept: &str,
    content_type: &str,
) -> bool {
    ((method != "GET") && (method != "HEAD"))
        || method == "OPTIONS"
        || route_path.starts_with("/api/")
        || accept.contains("application/json")
        || content_type.contains("application/json")
}

pub(super) fn is_static_asset_request(
    request: &UnifiedHttpRequest,
    route_path: &str,
    method: &str,
    accept: &str,
) -> bool {
    if method != "GET" && method != "HEAD" {
        return false;
    }

    if looks_like_static_asset(route_path) {
        return true;
    }

    if !has_static_fetch_dest(request) {
        return false;
    }

    // Treat Sec-Fetch-Dest as a hint only; require a compatible Accept to reduce spoofing.
    accept.is_empty()
        || accept == "*/*"
        || accept.contains("image/")
        || accept.contains("text/css")
        || accept.contains("javascript")
        || accept.contains("font/")
        || accept.contains("application/font")
}

pub(super) fn referer_host_path(request: &UnifiedHttpRequest) -> Option<(String, String)> {
    let referer = request.get_header("referer")?.trim();
    if referer.is_empty() {
        return None;
    }
    let uri: http::Uri = referer.parse().ok()?;
    let host = uri.host()?.to_ascii_lowercase();
    let path = uri
        .path_and_query()
        .map(|value| value.path())
        .unwrap_or("/");
    Some((host, normalized_route_path(path)))
}

pub(super) fn extract_host_from_origin(origin: &str) -> Option<String> {
    let trimmed = origin.trim();
    if trimmed.is_empty() {
        return None;
    }
    let uri: http::Uri = trimmed.parse().ok()?;
    Some(uri.host()?.to_ascii_lowercase())
}

pub(super) fn page_window_key(
    client_ip: std::net::IpAddr,
    host: &str,
    document_path: &str,
) -> String {
    format!("{client_ip}|{host}|{document_path}")
}

pub(super) fn page_host_window_key(client_ip: std::net::IpAddr, host: &str) -> String {
    format!("{client_ip}|{host}")
}

pub(super) fn challenge_mode(request: &UnifiedHttpRequest, route_path: &str) -> HtmlResponseMode {
    if !request.method.eq_ignore_ascii_case("GET") && !request.method.eq_ignore_ascii_case("HEAD") {
        return HtmlResponseMode::TextOnly;
    }

    if looks_like_static_asset(route_path) {
        return HtmlResponseMode::TextOnly;
    }

    let accept = request
        .get_header("accept")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    if accept.contains("text/html") || accept.contains("application/xhtml+xml") {
        HtmlResponseMode::HtmlChallenge
    } else {
        HtmlResponseMode::TextOnly
    }
}

pub(super) fn global_hot_path_client_challenge_threshold(config: &CcDefenseConfig) -> u32 {
    config.route_challenge_threshold.saturating_div(2).max(4)
}

pub(super) fn global_hot_path_client_block_threshold(config: &CcDefenseConfig) -> u32 {
    config
        .route_block_threshold
        .saturating_div(2)
        .max(global_hot_path_client_challenge_threshold(config).saturating_mul(2))
        .max(8)
}

pub(super) fn global_hot_path_effective_challenge_threshold(config: &CcDefenseConfig) -> u32 {
    config.route_challenge_threshold.saturating_div(2).max(4)
}

pub(super) fn global_hot_path_effective_block_threshold(config: &CcDefenseConfig) -> u32 {
    config
        .route_block_threshold
        .saturating_div(2)
        .max(global_hot_path_effective_challenge_threshold(config).saturating_mul(2))
        .max(8)
}

pub(super) fn request_path(uri: &str) -> &str {
    uri.split('?').next().unwrap_or(uri)
}

pub(super) fn normalized_route_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }
    if trimmed == "/" {
        return "/".to_string();
    }
    compact_component("route", trimmed.trim_end_matches('/'), MAX_ROUTE_PATH_LEN)
}

pub(super) fn normalized_host(request: &UnifiedHttpRequest) -> String {
    let raw = request
        .get_header("host")
        .or_else(|| request.get_metadata("authority"))
        .map(String::as_str)
        .unwrap_or("*")
        .trim();
    if raw.is_empty() {
        return "*".to_string();
    }
    if let Ok(uri) = format!("http://{raw}").parse::<http::Uri>() {
        if let Some(authority) = uri.authority() {
            return compact_component("host", &authority.host().to_ascii_lowercase(), MAX_HOST_LEN);
        }
    }
    let normalized = raw
        .trim_start_matches('[')
        .split(']')
        .next()
        .unwrap_or(raw)
        .split(':')
        .next()
        .unwrap_or(raw)
        .to_ascii_lowercase();
    compact_component("host", &normalized, MAX_HOST_LEN)
}

pub(super) fn looks_like_static_asset(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2",
        ".ttf", ".map",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

pub(super) fn cookie_value<'a>(request: &'a UnifiedHttpRequest, name: &str) -> Option<&'a str> {
    request.get_header("cookie").and_then(|value| {
        value.split(';').find_map(|item| {
            let (key, value) = item.trim().split_once('=')?;
            (key.trim() == name).then_some(value.trim())
        })
    })
}

pub(super) fn sign_challenge(
    secret: &str,
    client_ip: std::net::IpAddr,
    host: &str,
    expires_at: i64,
    nonce: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher.update(b"|");
    hasher.update(client_ip.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(host.as_bytes());
    hasher.update(b"|");
    hasher.update(expires_at.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(nonce.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    digest.chars().take(32).collect()
}

pub(super) fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

pub(super) fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub(super) fn bounded_dashmap_key<T>(
    map: &DashMap<String, T>,
    key: String,
    limit: usize,
    namespace: &str,
    overflow_shards: u64,
) -> String {
    let compacted = compact_component(namespace, &key, MAX_BUCKET_KEY_LEN);
    if map.contains_key(&compacted) || map.len() < limit {
        compacted
    } else {
        overflow_bucket_key(namespace, &compacted, overflow_shards)
    }
}

pub(super) fn compact_component(label: &str, value: &str, max_len: usize) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= max_len {
        return trimmed.to_string();
    }
    format!("{label}:{:016x}", stable_hash(trimmed))
}

pub(super) fn overflow_bucket_key(namespace: &str, value: &str, overflow_shards: u64) -> String {
    let shard = stable_hash(value) % overflow_shards.max(1);
    format!("__overflow__:{namespace}:{shard:02x}")
}

pub(super) fn stable_hash(value: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

pub(super) fn should_drop_delay_under_pressure(request: &UnifiedHttpRequest) -> bool {
    request
        .get_metadata("runtime.pressure.drop_delay")
        .map(|value| value == "true")
        .unwrap_or(false)
}

pub(super) fn effective_page_load_grace_secs(config: &CcDefenseConfig) -> u64 {
    config.page_load_grace_secs.max(8)
}
