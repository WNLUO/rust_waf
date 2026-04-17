use super::*;
use crate::core::CustomHttpResponse;
use rand::Rng;

use super::request_utils::escape_html;

const BEHAVIOR_CLEARANCE_TTL_SECS: i64 = 15 * 60;

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
        let expires_at = super::request_utils::unix_timestamp() + BEHAVIOR_CLEARANCE_TTL_SECS;
        let nonce = format!("{:016x}", rand::thread_rng().gen::<u64>());
        let cookie = format!(
            "{}={expires_at}:{nonce}; Max-Age={}; Path=/; SameSite=Lax",
            super::request_utils::BEHAVIOR_CLEARANCE_COOKIE_NAME,
            BEHAVIOR_CLEARANCE_TTL_SECS
        );
        let target = serde_json::to_string(&request.uri).unwrap_or_else(|_| "\"/\"".to_string());
        let cookie_js = serde_json::to_string(&cookie).unwrap_or_else(|_| "\"\"".to_string());
        CustomHttpResponse {
            status_code,
            headers: vec![
                ("content-type".to_string(), "text/html; charset=utf-8".to_string()),
                ("cache-control".to_string(), "no-store".to_string()),
                ("retry-after".to_string(), "15".to_string()),
                ("set-cookie".to_string(), cookie),
                ("x-rust-waf-behavior".to_string(), "active".to_string()),
            ],
            body: format!(
                "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>{}</title><style>body{{font-family:ui-sans-serif,system-ui,sans-serif;margin:0;min-height:100vh;display:grid;place-items:center;background:#f6f7f8;color:#111827}}main{{max-width:540px;padding:32px 28px}}p{{line-height:1.6;color:#4b5563}}code{{background:#f3f4f6;padding:2px 6px;border-radius:6px}}</style></head><body><main><h1>{}</h1><p>检测到访问节奏异常，正在验证浏览器环境。</p><p id=\"rwaf-status\">请保持此页面打开，验证完成后会自动返回。</p><p><code>{}</code></p></main><script>document.cookie={};setTimeout(function(){{var s=document.getElementById('rwaf-status');if(s)s.textContent='验证完成，正在返回原页面。';window.location.replace({});}},2800);</script></body></html>",
                escape_html(title),
                escape_html(title),
                escape_html(reason),
                cookie_js,
                target,
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
