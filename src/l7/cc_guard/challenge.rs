use super::helpers::*;
use super::types::*;
use super::L7CcGuard;
use crate::config::l7::CcDefenseConfig;
use crate::core::CustomHttpResponse;
use crate::protocol::UnifiedHttpRequest;
use rand::Rng;

impl L7CcGuard {
    pub(super) fn build_challenge_response(
        &self,
        request: &UnifiedHttpRequest,
        client_ip: std::net::IpAddr,
        host: &str,
        reason: &str,
        mode: HtmlResponseMode,
        config: &CcDefenseConfig,
    ) -> CustomHttpResponse {
        if mode == HtmlResponseMode::TextOnly {
            return CustomHttpResponse {
                status_code: 429,
                headers: vec![
                    (
                        "content-type".to_string(),
                        "application/json; charset=utf-8".to_string(),
                    ),
                    ("cache-control".to_string(), "no-store".to_string()),
                    ("retry-after".to_string(), "10".to_string()),
                    (
                        "x-rust-waf-cc-action".to_string(),
                        challenge_header_value(mode).to_string(),
                    ),
                ],
                body: serde_json::json!({
                    "success": false,
                    "action": challenge_header_value(mode),
                    "message": "接口请求频率偏高，已施加访问摩擦，请稍后重试。",
                    "reason": reason,
                })
                .to_string()
                .into_bytes(),
                tarpit: None,
                random_status: None,
            };
        }

        let expires_at = unix_timestamp() + config.challenge_ttl_secs as i64;
        let nonce = format!("{:016x}", rand::thread_rng().gen::<u64>());
        let signature = sign_challenge(&self.secret, client_ip, host, expires_at, &nonce);
        let cookie_value = format!("{expires_at}:{nonce}:{signature}");
        let cookie_assignment = format!(
            "{}={}; Max-Age={}; Path=/; SameSite=Lax",
            config.challenge_cookie_name,
            cookie_value,
            config.challenge_ttl_secs.max(30)
        );
        let reload_target =
            serde_json::to_string(&request.uri).unwrap_or_else(|_| "\"/\"".to_string());
        let reason_html = if config.challenge_page.show_reason {
            format!("<p><code>{}</code></p>", escape_html(reason))
        } else {
            String::new()
        };
        let title = escape_html(&config.challenge_page.title);
        let heading = escape_html(&config.challenge_page.heading);
        let description = escape_html(&config.challenge_page.description);
        let completion_message = escape_html(&config.challenge_page.completion_message);
        let wait_ms = 2800_u64;
        let html = format!(
            concat!(
                "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">",
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
                "<title>{title}</title>",
                "<style>body{{font-family:ui-sans-serif,system-ui,sans-serif;margin:0;",
                "min-height:100vh;display:grid;place-items:center;background:#f6f7f8;color:#111827;}}",
                ".card{{max-width:540px;padding:32px 28px;border-radius:20px;background:#fff;",
                "box-shadow:0 16px 60px rgba(15,23,42,.08);}}",
                "h1{{margin:0 0 12px;font-size:28px;}}p{{margin:0 0 10px;line-height:1.6;color:#4b5563;}}",
                "code{{font-family:ui-monospace,SFMono-Regular,monospace;background:#f3f4f6;padding:2px 6px;border-radius:8px;}}</style>",
                "</head><body><main class=\"card\"><h1>{heading}</h1>",
                "<p>{description}</p>",
                "<p>{completion_message}</p>",
                "<p id=\"rwaf-status\">正在验证浏览器环境，请保持此页面打开。</p>",
                "{reason_html}",
                "</main><script>",
                "document.cookie = {cookie};",
                "var __rwafTarget = {target};",
                "var __rwafReport = '/.well-known/waf/browser-fingerprint-report';",
                "var __rwafSeed = JSON.stringify({{",
                "ua:navigator.userAgent||'',",
                "lang:navigator.language||'',",
                "langs:(navigator.languages||[]).join(','),",
                "platform:navigator.platform||'',",
                "mobile:(navigator.userAgentData&&navigator.userAgentData.mobile)||false,",
                "memory:(typeof navigator.deviceMemory==='number'?navigator.deviceMemory:null),",
                "cores:(navigator.hardwareConcurrency||null),",
                "screen:(window.screen?window.screen.width+'x'+window.screen.height:''),",
                "viewport:(window.innerWidth||0)+'x'+(window.innerHeight||0),",
                "timezone:(Intl.DateTimeFormat().resolvedOptions().timeZone||''),",
                "touch:(navigator.maxTouchPoints||0)",
                "}});",
                "var __rwafHash=function(v){{var h=2166136261;for(var i=0;i<v.length;i++){{h^=v.charCodeAt(i);h=Math.imul(h,16777619);}}return ('00000000'+(h>>>0).toString(16)).slice(-8);}};",
                "var __rwafPayload={{fingerprintId:__rwafHash(__rwafSeed)+__rwafHash(__rwafSeed.split('').reverse().join('')),...JSON.parse(__rwafSeed),challenge:{{rendered:true,js:true,action:'challenge',target:__rwafTarget,waitMs:{wait_ms},issuedAt:Date.now()}}}};",
                "var __rwafStatus=document.getElementById('rwaf-status');",
                "var __rwafDone=function(){{if(__rwafStatus)__rwafStatus.textContent='验证完成，正在返回原页面。';window.location.replace(__rwafTarget);}};",
                "var __rwafWait=function(){{setTimeout(__rwafDone,{wait_ms});}};",
                "try{{fetch(__rwafReport,{{method:'POST',headers:{{'content-type':'application/json'}},credentials:'same-origin',body:JSON.stringify(__rwafPayload),keepalive:true}}).finally(__rwafWait);}}catch(_e){{__rwafWait();}}",
                "</script></body></html>"
            ),
            title = title,
            heading = heading,
            description = description,
            completion_message = completion_message,
            reason_html = reason_html,
            cookie = serde_json::to_string(&cookie_assignment)
                .unwrap_or_else(|_| "\"\"".to_string()),
            target = reload_target,
            wait_ms = wait_ms,
        );

        CustomHttpResponse {
            status_code: 403,
            headers: vec![
                (
                    "content-type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                ),
                ("cache-control".to_string(), "no-store".to_string()),
                ("set-cookie".to_string(), cookie_assignment),
                (
                    "x-rust-waf-cc-action".to_string(),
                    challenge_header_value(mode).to_string(),
                ),
            ],
            body: html.into_bytes(),
            tarpit: None,
            random_status: None,
        }
    }

    pub(super) fn has_valid_challenge_cookie(
        &self,
        request: &UnifiedHttpRequest,
        client_ip: std::net::IpAddr,
        host: &str,
        config: &CcDefenseConfig,
    ) -> bool {
        let Some(cookie_value) = cookie_value(request, &config.challenge_cookie_name) else {
            return false;
        };
        let mut parts = cookie_value.splitn(3, ':');
        let Some(expires_at) = parts.next().and_then(|value| value.parse::<i64>().ok()) else {
            return false;
        };
        let Some(nonce) = parts.next() else {
            return false;
        };
        let Some(signature) = parts.next() else {
            return false;
        };
        if expires_at < unix_timestamp() {
            return false;
        }
        sign_challenge(&self.secret, client_ip, host, expires_at, nonce) == signature
    }
}
