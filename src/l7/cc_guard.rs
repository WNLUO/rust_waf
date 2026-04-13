use crate::config::l7::CcDefenseConfig;
use crate::core::{CustomHttpResponse, InspectionLayer, InspectionResult};
use crate::protocol::UnifiedHttpRequest;
use dashmap::DashMap;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BYPASS_PATHS: &[&str] = &["/.well-known/waf/browser-fingerprint-report"];

#[derive(Debug)]
pub struct L7CcGuard {
    config: CcDefenseConfig,
    secret: String,
    ip_buckets: DashMap<String, SlidingWindowCounter>,
    host_buckets: DashMap<String, SlidingWindowCounter>,
    route_buckets: DashMap<String, SlidingWindowCounter>,
    hot_path_buckets: DashMap<String, SlidingWindowCounter>,
    request_sequence: AtomicU64,
}

#[derive(Debug)]
struct SlidingWindowCounter {
    events: Mutex<VecDeque<Instant>>,
    last_seen_unix: AtomicI64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HtmlResponseMode {
    HtmlChallenge,
    TextOnly,
}

impl L7CcGuard {
    pub fn new(config: &CcDefenseConfig) -> Self {
        let secret = format!("{:032x}", rand::thread_rng().gen::<u128>());
        Self {
            config: config.clone(),
            secret,
            ip_buckets: DashMap::new(),
            host_buckets: DashMap::new(),
            route_buckets: DashMap::new(),
            hot_path_buckets: DashMap::new(),
            request_sequence: AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> &CcDefenseConfig {
        &self.config
    }

    pub async fn inspect_request(
        &self,
        request: &mut UnifiedHttpRequest,
    ) -> Option<InspectionResult> {
        if !self.config.enabled {
            return None;
        }

        let client_ip = request_client_ip(request)?;
        let path = request_path(&request.uri);
        if BYPASS_PATHS.contains(&path) {
            return None;
        }

        let host = normalized_host(request);
        let route_path = normalized_route_path(path);
        let method = request.method.to_ascii_uppercase();
        let html_mode = challenge_mode(request, &route_path);
        let verified = self.has_valid_challenge_cookie(request, client_ip, &host);

        let now = Instant::now();
        let unix_now = unix_timestamp();
        let window = Duration::from_secs(self.config.request_window_secs.max(1));

        let ip_count = self.observe(
            &self.ip_buckets,
            client_ip.to_string(),
            now,
            unix_now,
            window,
        );
        let host_count = self.observe(
            &self.host_buckets,
            format!("{client_ip}|{host}"),
            now,
            unix_now,
            window,
        );
        let route_count = self.observe(
            &self.route_buckets,
            format!("{client_ip}|{host}|{method}|{route_path}"),
            now,
            unix_now,
            window,
        );
        let hot_path_count = self.observe(
            &self.hot_path_buckets,
            format!("{host}|{route_path}"),
            now,
            unix_now,
            window,
        );

        request.add_metadata("l7.cc.client_ip".to_string(), client_ip.to_string());
        request.add_metadata("l7.cc.host".to_string(), host.clone());
        request.add_metadata("l7.cc.route".to_string(), route_path.clone());
        request.add_metadata("l7.cc.ip_count".to_string(), ip_count.to_string());
        request.add_metadata("l7.cc.host_count".to_string(), host_count.to_string());
        request.add_metadata("l7.cc.route_count".to_string(), route_count.to_string());
        request.add_metadata(
            "l7.cc.hot_path_count".to_string(),
            hot_path_count.to_string(),
        );
        request.add_metadata("l7.cc.challenge_verified".to_string(), verified.to_string());

        self.maybe_cleanup(unix_now);

        let challenge_multiplier = if verified { 3 } else { 1 };
        let block_multiplier = if verified { 2 } else { 1 };

        let route_block_threshold = self
            .config
            .route_block_threshold
            .saturating_mul(block_multiplier);
        let host_block_threshold = self
            .config
            .host_block_threshold
            .saturating_mul(block_multiplier);
        let ip_block_threshold = self
            .config
            .ip_block_threshold
            .saturating_mul(block_multiplier);
        let hot_path_block_threshold = self
            .config
            .hot_path_block_threshold
            .saturating_mul(block_multiplier);

        if route_count >= route_block_threshold
            || host_count >= host_block_threshold
            || ip_count >= ip_block_threshold
            || (hot_path_count >= hot_path_block_threshold
                && route_count >= self.config.route_challenge_threshold.max(3))
        {
            let reason = format!(
                "l7 cc guard throttled request: ip_count={} host_count={} route_count={} hot_path_count={} verified={}",
                ip_count, host_count, route_count, hot_path_count, verified
            );
            request.add_metadata("l7.cc.action".to_string(), "block".to_string());
            return Some(InspectionResult::respond(
                InspectionLayer::L7,
                reason.clone(),
                build_block_response(request, &reason),
            ));
        }

        let route_challenge_threshold = self
            .config
            .route_challenge_threshold
            .saturating_mul(challenge_multiplier);
        let host_challenge_threshold = self
            .config
            .host_challenge_threshold
            .saturating_mul(challenge_multiplier);
        let ip_challenge_threshold = self
            .config
            .ip_challenge_threshold
            .saturating_mul(challenge_multiplier);
        let hot_path_challenge_threshold = self
            .config
            .hot_path_challenge_threshold
            .saturating_mul(challenge_multiplier);

        if !verified
            && (route_count >= route_challenge_threshold
                || host_count >= host_challenge_threshold
                || ip_count >= ip_challenge_threshold
                || (hot_path_count >= hot_path_challenge_threshold
                    && route_count >= route_challenge_threshold.saturating_sub(4).max(1)))
        {
            let reason = format!(
                "l7 cc guard issued challenge: ip_count={} host_count={} route_count={} hot_path_count={}",
                ip_count, host_count, route_count, hot_path_count
            );
            request.add_metadata("l7.cc.action".to_string(), "challenge".to_string());
            return Some(InspectionResult::respond(
                InspectionLayer::L7,
                reason.clone(),
                self.build_challenge_response(request, client_ip, &host, &reason, html_mode),
            ));
        }

        let delay_threshold = u32::from(self.config.delay_threshold_percent)
            .saturating_mul(self.config.route_challenge_threshold.max(1))
            / 100;
        if self.config.delay_ms > 0
            && (route_count >= delay_threshold.max(1)
                || host_count
                    >= u32::from(self.config.delay_threshold_percent)
                        .saturating_mul(self.config.host_challenge_threshold.max(1))
                        / 100
                || ip_count
                    >= u32::from(self.config.delay_threshold_percent)
                        .saturating_mul(self.config.ip_challenge_threshold.max(1))
                        / 100)
        {
            request.add_metadata(
                "l7.cc.action".to_string(),
                format!("delay:{}ms", self.config.delay_ms),
            );
            tokio::time::sleep(Duration::from_millis(self.config.delay_ms)).await;
        }

        None
    }

    fn build_challenge_response(
        &self,
        request: &UnifiedHttpRequest,
        client_ip: std::net::IpAddr,
        host: &str,
        reason: &str,
        mode: HtmlResponseMode,
    ) -> CustomHttpResponse {
        if mode == HtmlResponseMode::TextOnly {
            return CustomHttpResponse {
                status_code: 429,
                headers: vec![
                    (
                        "content-type".to_string(),
                        "text/plain; charset=utf-8".to_string(),
                    ),
                    ("cache-control".to_string(), "no-store".to_string()),
                    ("retry-after".to_string(), "10".to_string()),
                ],
                body: format!("challenge required: {reason}").into_bytes(),
                tarpit: None,
                random_status: None,
            };
        }

        let expires_at = unix_timestamp() + self.config.challenge_ttl_secs as i64;
        let nonce = format!("{:016x}", rand::thread_rng().gen::<u64>());
        let signature = sign_challenge(&self.secret, client_ip, host, expires_at, &nonce);
        let cookie_value = format!("{expires_at}:{nonce}:{signature}");
        let cookie_assignment = format!(
            "{}={}; Max-Age={}; Path=/; SameSite=Lax",
            self.config.challenge_cookie_name,
            cookie_value,
            self.config.challenge_ttl_secs.max(30)
        );
        let reload_target =
            serde_json::to_string(&request.uri).unwrap_or_else(|_| "\"/\"".to_string());
        let html = format!(
            concat!(
                "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">",
                "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
                "<title>请求校验中</title>",
                "<style>body{{font-family:ui-sans-serif,system-ui,sans-serif;margin:0;",
                "min-height:100vh;display:grid;place-items:center;background:#f6f7f8;color:#111827;}}",
                ".card{{max-width:540px;padding:32px 28px;border-radius:20px;background:#fff;",
                "box-shadow:0 16px 60px rgba(15,23,42,.08);}}",
                "h1{{margin:0 0 12px;font-size:28px;}}p{{margin:0 0 10px;line-height:1.6;color:#4b5563;}}",
                "code{{font-family:ui-monospace,SFMono-Regular,monospace;background:#f3f4f6;padding:2px 6px;border-radius:8px;}}</style>",
                "</head><body><main class=\"card\"><h1>正在校验请求</h1>",
                "<p>检测到当前请求速率偏高，正在确认这是一个真实浏览器会话。</p>",
                "<p>校验完成后会自动返回当前页面。</p>",
                "<p><code>{reason}</code></p>",
                "</main><script>",
                "document.cookie = {cookie};",
                "setTimeout(function(){{ window.location.replace({target}); }}, 30);",
                "</script></body></html>"
            ),
            reason = escape_html(reason),
            cookie = serde_json::to_string(&cookie_assignment)
                .unwrap_or_else(|_| "\"\"".to_string()),
            target = reload_target,
        );

        CustomHttpResponse {
            status_code: 403,
            headers: vec![
                (
                    "content-type".to_string(),
                    "text/html; charset=utf-8".to_string(),
                ),
                ("cache-control".to_string(), "no-store".to_string()),
                ("x-rust-waf-cc-action".to_string(), "challenge".to_string()),
            ],
            body: html.into_bytes(),
            tarpit: None,
            random_status: None,
        }
    }

    fn has_valid_challenge_cookie(
        &self,
        request: &UnifiedHttpRequest,
        client_ip: std::net::IpAddr,
        host: &str,
    ) -> bool {
        let Some(cookie_value) = cookie_value(request, &self.config.challenge_cookie_name) else {
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

    fn observe(
        &self,
        map: &DashMap<String, SlidingWindowCounter>,
        key: String,
        now: Instant,
        unix_now: i64,
        window: Duration,
    ) -> u32 {
        let mut entry = map.entry(key).or_insert_with(SlidingWindowCounter::new);
        entry.observe(now, unix_now, window)
    }

    fn maybe_cleanup(&self, unix_now: i64) {
        let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        if !sequence.is_multiple_of(1024) {
            return;
        }

        let stale_before = unix_now - (self.config.request_window_secs as i64 * 6).max(30);
        cleanup_map(&self.ip_buckets, stale_before);
        cleanup_map(&self.host_buckets, stale_before);
        cleanup_map(&self.route_buckets, stale_before);
        cleanup_map(&self.hot_path_buckets, stale_before);
    }
}

impl SlidingWindowCounter {
    fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    fn observe(&mut self, now: Instant, unix_now: i64, window: Duration) -> u32 {
        let mut events = self.events.lock().expect("cc bucket lock poisoned");
        while let Some(front) = events.front() {
            if now.duration_since(*front) > window {
                events.pop_front();
            } else {
                break;
            }
        }
        events.push_back(now);
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        events.len() as u32
    }
}

fn cleanup_map(map: &DashMap<String, SlidingWindowCounter>, stale_before: i64) {
    let keys = map
        .iter()
        .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
        .take(128)
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();

    for key in keys {
        map.remove(&key);
    }
}

fn build_block_response(request: &UnifiedHttpRequest, reason: &str) -> CustomHttpResponse {
    let content_type =
        if challenge_mode(request, &normalized_route_path(request_path(&request.uri)))
            == HtmlResponseMode::HtmlChallenge
        {
            "text/html; charset=utf-8"
        } else {
            "text/plain; charset=utf-8"
        };
    let body = if content_type.starts_with("text/html") {
        format!(
            "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>请求过于频繁</title></head><body><h1>请求过于频繁</h1><p>当前请求已被限流，请稍后重试。</p><p><code>{}</code></p></body></html>",
            escape_html(reason)
        )
        .into_bytes()
    } else {
        format!("too many requests: {reason}").into_bytes()
    };

    CustomHttpResponse {
        status_code: 429,
        headers: vec![
            ("content-type".to_string(), content_type.to_string()),
            ("cache-control".to_string(), "no-store".to_string()),
            ("retry-after".to_string(), "10".to_string()),
            ("x-rust-waf-cc-action".to_string(), "block".to_string()),
        ],
        body,
        tarpit: None,
        random_status: None,
    }
}

fn request_client_ip(request: &UnifiedHttpRequest) -> Option<std::net::IpAddr> {
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

fn challenge_mode(request: &UnifiedHttpRequest, route_path: &str) -> HtmlResponseMode {
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

fn request_path(uri: &str) -> &str {
    uri.split('?').next().unwrap_or(uri)
}

fn normalized_route_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return "/".to_string();
    }
    if trimmed == "/" {
        return "/".to_string();
    }
    trimmed.trim_end_matches('/').to_string()
}

fn normalized_host(request: &UnifiedHttpRequest) -> String {
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
            return authority.host().to_ascii_lowercase();
        }
    }
    raw.trim_start_matches('[')
        .split(']')
        .next()
        .unwrap_or(raw)
        .split(':')
        .next()
        .unwrap_or(raw)
        .to_ascii_lowercase()
}

fn looks_like_static_asset(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2",
        ".ttf", ".map", ".json", ".txt", ".xml",
    ]
    .iter()
    .any(|suffix| lower.ends_with(suffix))
}

fn cookie_value<'a>(request: &'a UnifiedHttpRequest, name: &str) -> Option<&'a str> {
    request.get_header("cookie").and_then(|value| {
        value.split(';').find_map(|item| {
            let (key, value) = item.trim().split_once('=')?;
            (key.trim() == name).then_some(value.trim())
        })
    })
}

fn sign_challenge(
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

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::HttpVersion;

    fn request(uri: &str) -> UnifiedHttpRequest {
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), uri.to_string());
        request.set_client_ip("203.0.113.10".to_string());
        request.add_header("host".to_string(), "example.com".to_string());
        request.add_header("accept".to_string(), "text/html".to_string());
        request
    }

    #[tokio::test]
    async fn issues_challenge_when_route_rate_crosses_threshold() {
        let config = CcDefenseConfig {
            route_challenge_threshold: 2,
            route_block_threshold: 20,
            host_challenge_threshold: 20,
            host_block_threshold: 40,
            ip_challenge_threshold: 20,
            ip_block_threshold: 40,
            ..CcDefenseConfig::default()
        };
        let guard = L7CcGuard::new(&config);

        let mut first = request("/search?q=1");
        assert!(guard.inspect_request(&mut first).await.is_none());

        let mut second = request("/search?q=2");
        let result = guard.inspect_request(&mut second).await;
        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.layer, InspectionLayer::L7);
        assert_eq!(result.action, crate::core::InspectionAction::Respond);
        assert_eq!(
            result
                .custom_response
                .as_ref()
                .expect("challenge response")
                .status_code,
            403
        );
    }

    #[test]
    fn validates_signed_challenge_cookie() {
        let config = CcDefenseConfig::default();
        let guard = L7CcGuard::new(&config);
        let mut request = request("/");
        let expires_at = unix_timestamp() + 60;
        let nonce = "abc123";
        let signature = sign_challenge(
            &guard.secret,
            "203.0.113.10".parse().unwrap(),
            "example.com",
            expires_at,
            nonce,
        );
        request.add_header(
            "cookie".to_string(),
            format!(
                "{}={expires_at}:{nonce}:{signature}",
                guard.config.challenge_cookie_name
            ),
        );

        assert!(guard.has_valid_challenge_cookie(
            &request,
            "203.0.113.10".parse().unwrap(),
            "example.com"
        ));
    }
}
