use super::types::VisitorIntelligenceBucket;
use super::utils::compact_text;
use crate::protocol::UnifiedHttpRequest;

pub(super) fn update_bucket_flags(
    bucket: &mut VisitorIntelligenceBucket,
    request: &UnifiedHttpRequest,
    route: &str,
    kind: &str,
) {
    if kind == "document" && !has_same_site_referer(request) {
        bucket.flags.insert("document_without_referer".to_string());
    }
    if kind == "document" && bucket.static_count == 0 && bucket.document_count >= 4 {
        bucket.flags.insert("document_without_assets".to_string());
    }
    if is_admin_route(route) {
        bucket.flags.insert("admin_route".to_string());
    }
    if route.contains("xmlrpc.php") || route.contains("wp-login.php") {
        bucket.flags.insert("sensitive_wordpress_route".to_string());
    }
    if request
        .get_metadata("l7.cc.challenge_verified")
        .is_some_and(|value| value == "true")
    {
        bucket.flags.insert("challenge_verified".to_string());
    }
    if request.get_metadata("ai.policy.matched_ids").is_some() {
        bucket.flags.insert("ai_policy_matched".to_string());
    }
}

pub(super) fn storage_route_profile_matches(
    profile: &crate::storage::AiRouteProfileEntry,
    route: &str,
) -> bool {
    match profile.match_mode.as_str() {
        "exact" => route == profile.route_pattern,
        "prefix" => route.starts_with(&profile.route_pattern),
        "wildcard" => wildcard_route_matches(&profile.route_pattern, route),
        _ => false,
    }
}

pub(super) fn wildcard_route_matches(pattern: &str, route: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return route == pattern;
    };
    route.starts_with(prefix) && route.ends_with(suffix)
}

pub(super) fn classify_request_kind(request: &UnifiedHttpRequest, route: &str) -> &'static str {
    let method = request.method.to_ascii_uppercase();
    if method != "GET" && method != "HEAD" {
        return "api";
    }
    let lower = route.to_ascii_lowercase();
    if lower.contains("/wp-admin/admin-ajax.php")
        || lower.starts_with("/api/")
        || lower.contains("ajax")
    {
        return "api";
    }
    if lower.ends_with(".css")
        || lower.ends_with(".js")
        || lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".webp")
        || lower.ends_with(".gif")
        || lower.ends_with(".svg")
        || lower.ends_with(".woff")
        || lower.ends_with(".woff2")
        || lower.ends_with(".ttf")
    {
        return "static";
    }
    "document"
}

pub(super) fn normalized_route(uri: &str) -> String {
    let path = uri.split('?').next().unwrap_or(uri).trim();
    if path.is_empty() {
        "/".to_string()
    } else {
        compact_text(path.trim_end_matches('/'), 180)
    }
}

pub(super) fn is_admin_route(route: &str) -> bool {
    let lower = route.to_ascii_lowercase();
    lower.contains("/wp-admin") || lower.contains("/wp-login") || lower.contains("xmlrpc.php")
}

pub(super) fn has_same_site_referer(request: &UnifiedHttpRequest) -> bool {
    let Some(referer) = request.get_header("referer") else {
        return false;
    };
    let Some(host) = request.get_header("host") else {
        return false;
    };
    let host = host.split(':').next().unwrap_or(host).trim();
    !host.is_empty() && referer.contains(host)
}
