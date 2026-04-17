use super::*;
use crate::core::CustomHttpResponse;

use super::request_utils::escape_html;

pub(super) fn build_behavior_response(
    request: &UnifiedHttpRequest,
    status_code: u16,
    title: &str,
    reason: &str,
) -> CustomHttpResponse {
    let accept = request
        .get_header("accept")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let html = accept.contains("text/html") || accept.contains("application/xhtml+xml");
    if html {
        CustomHttpResponse {
            status_code,
            headers: vec![
                ("content-type".to_string(), "text/html; charset=utf-8".to_string()),
                ("cache-control".to_string(), "no-store".to_string()),
                ("retry-after".to_string(), "15".to_string()),
                ("x-rust-waf-behavior".to_string(), "active".to_string()),
            ],
            body: format!(
                "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title></head><body><h1>{}</h1><p>检测到访问行为异常，请稍后再试。</p><p><code>{}</code></p></body></html>",
                escape_html(title),
                escape_html(title),
                escape_html(reason),
            )
            .into_bytes(),
            tarpit: None,
            random_status: None,
        }
    } else {
        CustomHttpResponse {
            status_code,
            headers: vec![
                (
                    "content-type".to_string(),
                    "text/plain; charset=utf-8".to_string(),
                ),
                ("cache-control".to_string(), "no-store".to_string()),
                ("retry-after".to_string(), "15".to_string()),
                ("x-rust-waf-behavior".to_string(), "active".to_string()),
            ],
            body: format!("{title}: {reason}").into_bytes(),
            tarpit: None,
            random_status: None,
        }
    }
}
