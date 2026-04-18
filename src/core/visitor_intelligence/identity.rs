use super::utils::compact_text;
use crate::protocol::UnifiedHttpRequest;

pub(super) fn visitor_identity(request: &UnifiedHttpRequest) -> Option<(String, String)> {
    if let Some(value) = cookie_value(request, "rwaf_fp") {
        return Some((
            format!("fp:{}", compact_text(&value, 96)),
            "fingerprint".to_string(),
        ));
    }
    if let Some(value) = request.get_header("x-browser-fingerprint-id") {
        let value = value.trim();
        if !value.is_empty() {
            return Some((
                format!("fp:{}", compact_text(value, 96)),
                "fingerprint".to_string(),
            ));
        }
    }
    if let Some(value) = cookie_value(request, "rwaf_cc") {
        return Some((
            format!("cc:{}", compact_text(&value, 96)),
            "challenge_cookie".to_string(),
        ));
    }
    if let Some(value) = cookie_value(request, "rwaf_behavior") {
        return Some((
            format!("behavior:{}", compact_text(&value, 96)),
            "behavior_cookie".to_string(),
        ));
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
    Some((
        format!("ipua:{}|{}", ip, compact_text(ua, 96)),
        "ip_user_agent".to_string(),
    ))
}

pub(super) fn cookie_value(request: &UnifiedHttpRequest, name: &str) -> Option<String> {
    request.get_header("cookie").and_then(|value| {
        value.split(';').find_map(|item| {
            let (key, value) = item.trim().split_once('=')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    })
}
