use super::*;
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::hash::{Hash, Hasher};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) const BEHAVIOR_CLEARANCE_COOKIE_NAME: &str = "rwaf_behavior";

pub(super) fn request_identity(request: &UnifiedHttpRequest) -> Option<String> {
    let identity_state = request
        .get_metadata("network.identity_state")
        .map(String::as_str)
        .unwrap_or("unknown");

    if let Some(value) = cookie_value(request, "rwaf_fp") {
        return Some(compact_component(
            "identity",
            &format!("fp:{value}"),
            MAX_BEHAVIOR_KEY_LEN,
        ));
    }
    if let Some(value) = request.get_header("x-browser-fingerprint-id") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(compact_component(
                "identity",
                &format!("fp:{trimmed}"),
                MAX_BEHAVIOR_KEY_LEN,
            ));
        }
    }
    if let Some(value) = passive_fingerprint_id(request) {
        return Some(compact_component(
            "identity",
            &format!("pfp:{value}"),
            MAX_BEHAVIOR_KEY_LEN,
        ));
    }
    if let Some(value) = cookie_value(request, "rwaf_cc") {
        return Some(compact_component(
            "identity",
            &format!("cookie:{value}"),
            MAX_BEHAVIOR_KEY_LEN,
        ));
    }
    if let Some(value) = cookie_value(request, BEHAVIOR_CLEARANCE_COOKIE_NAME) {
        return Some(compact_component(
            "identity",
            &format!("behavior:{value}"),
            MAX_BEHAVIOR_KEY_LEN,
        ));
    }
    if identity_state == "trusted_cdn_unresolved" {
        return None;
    }
    let ip = request.client_ip.as_deref()?.trim();
    if ip.is_empty() {
        return None;
    }
    let ua = request
        .get_header("user-agent")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("-");
    Some(compact_component(
        "identity",
        &format!("ipua:{ip}|{ua}"),
        MAX_BEHAVIOR_KEY_LEN,
    ))
}

pub(super) fn has_valid_behavior_clearance(request: &UnifiedHttpRequest) -> bool {
    let Some(value) = cookie_value(request, BEHAVIOR_CLEARANCE_COOKIE_NAME) else {
        return false;
    };
    let Some((expires_at, _nonce)) = value.split_once(':') else {
        return false;
    };
    expires_at
        .parse::<i64>()
        .map(|expires_at| expires_at > unix_timestamp())
        .unwrap_or(false)
}

pub(super) fn passive_fingerprint_id(request: &UnifiedHttpRequest) -> Option<String> {
    let fields = [
        request
            .get_header("user-agent")
            .map(String::as_str)
            .unwrap_or(""),
        request
            .get_header("sec-ch-ua")
            .map(String::as_str)
            .unwrap_or(""),
        request
            .get_header("sec-ch-ua-mobile")
            .map(String::as_str)
            .unwrap_or(""),
        request
            .get_header("sec-ch-ua-platform")
            .map(String::as_str)
            .unwrap_or(""),
        request
            .get_header("accept-language")
            .map(String::as_str)
            .unwrap_or(""),
        request
            .get_header("accept-encoding")
            .map(String::as_str)
            .unwrap_or(""),
        request
            .get_header("tls-hash")
            .map(String::as_str)
            .unwrap_or(""),
    ];
    if fields.iter().all(|value| value.trim().is_empty()) {
        return None;
    }
    let seed = fields.join("|");
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    Some(
        format!("{:x}", hasher.finalize())
            .chars()
            .take(24)
            .collect(),
    )
}

pub(super) fn is_high_value_route(route: &str) -> bool {
    let route = route.to_ascii_lowercase();
    [
        "/login",
        "/signin",
        "/signup",
        "/register",
        "/auth",
        "/search",
        "/query",
        "/captcha",
        "/verify",
        "/otp",
        "/checkout",
        "/order",
        "/pay",
        "/submit",
        "/detail",
        "/product",
        "/item",
        "/cart",
        "/user",
        "/account",
    ]
    .iter()
    .any(|segment| route.contains(segment))
}

pub(super) fn is_browser_document_navigation(request: &UnifiedHttpRequest) -> bool {
    if !request.method.eq_ignore_ascii_case("GET") && !request.method.eq_ignore_ascii_case("HEAD") {
        return false;
    }
    let fetch_mode = request
        .get_header("sec-fetch-mode")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let fetch_dest = request
        .get_header("sec-fetch-dest")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    matches!(fetch_mode.as_str(), "navigate") && matches!(fetch_dest.as_str(), "document")
}

pub(super) fn is_browser_same_origin_async_request(request: &UnifiedHttpRequest) -> bool {
    if request.method.eq_ignore_ascii_case("GET")
        && request
            .get_header("accept")
            .is_some_and(|value| value.to_ascii_lowercase().contains("text/html"))
    {
        return false;
    }

    let fetch_site = request
        .get_header("sec-fetch-site")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let fetch_mode = request
        .get_header("sec-fetch-mode")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let accept = request
        .get_header("accept")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let content_type = request
        .get_header("content-type")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let x_requested_with = request
        .get_header("x-requested-with")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    let explicit_async = x_requested_with == "xmlhttprequest"
        || matches!(fetch_mode.as_str(), "cors" | "same-origin")
        || accept.contains("application/json")
        || accept.contains("text/javascript")
        || content_type.contains("application/json")
        || content_type.contains("application/x-www-form-urlencoded");
    if !explicit_async {
        return false;
    }

    let same_origin_fetch = matches!(fetch_site.as_str(), "same-origin" | "same-site");
    let same_origin_headers = request_has_same_origin_context(request);
    let browser_ua = request
        .get_header("user-agent")
        .is_some_and(|value| looks_like_browser_user_agent(value));

    browser_ua && (same_origin_fetch || same_origin_headers)
}

fn request_has_same_origin_context(request: &UnifiedHttpRequest) -> bool {
    let Some(host) = request
        .get_header("host")
        .map(|value| normalized_host(value))
        .filter(|value| !value.is_empty())
    else {
        return false;
    };
    request
        .get_header("origin")
        .or_else(|| request.get_header("referer"))
        .map(|value| normalized_origin_host(value) == host)
        .unwrap_or(false)
}

fn normalized_origin_host(value: &str) -> String {
    let trimmed = value.trim();
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    normalized_host(without_scheme.split('/').next().unwrap_or(without_scheme))
}

fn normalized_host(value: &str) -> String {
    value
        .trim()
        .trim_matches('[')
        .split(']')
        .next()
        .unwrap_or(value)
        .split(':')
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase()
}

pub(super) fn looks_like_browser_user_agent(value: &str) -> bool {
    let ua = value.to_ascii_lowercase();
    if [
        "curl",
        "wget",
        "python",
        "benchmark",
        "wrk",
        "ab/",
        "go-http-client",
        "okhttp",
    ]
    .iter()
    .any(|needle| ua.contains(needle))
    {
        return false;
    }
    [
        "mozilla/", "chrome/", "safari/", "firefox/", "edg/", "mobile/",
    ]
    .iter()
    .any(|needle| ua.contains(needle))
}

pub(super) fn route_family(uri: &str, route: &str) -> Option<&'static str> {
    let route = route.to_ascii_lowercase();
    let uri = uri.to_ascii_lowercase();
    if route == "/robots.txt"
        || route == "/sitemap.xml"
        || route.starts_with("/sitemap")
        || route == "/favicon.ico"
        || route.starts_with("/.well-known/")
    {
        return None;
    }
    if route == "/" && (uri.contains("?p=") || uri.contains("&p=")) {
        return Some("wp_post_query");
    }
    if route == "/" {
        return Some("root");
    }
    if route == "/wp-login.php" {
        return Some("wp_login");
    }
    if route.starts_with("/wp-admin") {
        return Some("wp_admin");
    }
    if route == "/wp-cron.php" || route == "/xmlrpc.php" {
        return Some("wp_system_probe");
    }
    if route.starts_with("/wp-content/plugins/") {
        return Some("wp_plugin_probe");
    }
    if route.starts_with("/wp-content/themes/") {
        return Some("wp_theme_probe");
    }
    if route.starts_with("/tag/") || route.starts_with("/category/") {
        return Some("taxonomy_page");
    }
    if route.starts_with("/search") || uri.contains("?s=") || uri.contains("&s=") {
        return Some("search_page");
    }
    if looks_like_article_path(&route) {
        return Some("article_page");
    }
    if route.starts_with("/api/") {
        return Some("api_endpoint");
    }
    None
}

fn looks_like_article_path(route: &str) -> bool {
    let without_suffix = route
        .strip_suffix(".html")
        .or_else(|| route.strip_suffix(".htm"))
        .unwrap_or(route);
    let tail = without_suffix.rsplit('/').next().unwrap_or(without_suffix);
    let digit_count = tail.chars().filter(|ch| ch.is_ascii_digit()).count();
    digit_count >= 4 && digit_count.saturating_mul(2) >= tail.chars().count().max(1)
}

pub(super) fn request_kind(request: &UnifiedHttpRequest) -> RequestKind {
    let path = request_path(&request.uri).to_ascii_lowercase();
    if let Some(kind) = request
        .get_metadata("l7.cc.request_kind")
        .map(String::as_str)
    {
        return match kind {
            "document" => RequestKind::Document,
            "static" => RequestKind::Static,
            "api" => RequestKind::Api,
            "other" if path == "/" || path.ends_with(".html") || path.ends_with(".htm") => {
                RequestKind::Document
            }
            _ => RequestKind::Other,
        };
    }

    let accept = request
        .get_header("accept")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let sec_fetch_dest = request
        .get_header("sec-fetch-dest")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let content_type = request
        .get_header("content-type")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let x_requested_with = request
        .get_header("x-requested-with")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();

    if sec_fetch_dest == "document"
        || accept.contains("text/html")
        || path == "/"
        || path.ends_with(".html")
        || path.ends_with(".htm")
    {
        return RequestKind::Document;
    }

    if sec_fetch_dest == "script"
        || sec_fetch_dest == "style"
        || sec_fetch_dest == "image"
        || sec_fetch_dest == "font"
        || path.ends_with(".js")
        || path.ends_with(".css")
        || path.ends_with(".png")
        || path.ends_with(".jpg")
        || path.ends_with(".jpeg")
        || path.ends_with(".gif")
        || path.ends_with(".svg")
        || path.ends_with(".ico")
        || path.ends_with(".webp")
        || path.ends_with(".woff")
        || path.ends_with(".woff2")
    {
        return RequestKind::Static;
    }

    if path.starts_with("/api/")
        || accept.contains("application/json")
        || content_type.contains("application/json")
        || x_requested_with == "xmlhttprequest"
    {
        return RequestKind::Api;
    }

    RequestKind::Other
}

pub(super) fn request_path(uri: &str) -> &str {
    uri.split('?').next().unwrap_or(uri)
}

pub(super) fn normalized_route_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        "/".to_string()
    } else {
        compact_component(
            "route",
            trimmed.trim_end_matches('/'),
            MAX_BEHAVIOR_ROUTE_LEN,
        )
    }
}

fn cookie_value<'a>(request: &'a UnifiedHttpRequest, name: &str) -> Option<&'a str> {
    request.get_header("cookie").and_then(|value| {
        value.split(';').find_map(|item| {
            let (key, value) = item.trim().split_once('=')?;
            (key.trim() == name).then_some(value.trim())
        })
    })
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
    if map.contains_key(&key) || map.len() < limit {
        key
    } else {
        overflow_bucket_key(namespace, &key, overflow_shards)
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
    if request
        .get_metadata("runtime.defense.stage")
        .is_some_and(|value| matches!(value.as_str(), "challenge" | "drop"))
    {
        return true;
    }
    request
        .get_metadata("runtime.pressure.drop_delay")
        .map(|value| value == "true")
        .unwrap_or(false)
}
