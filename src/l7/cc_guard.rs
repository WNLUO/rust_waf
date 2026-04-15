use crate::config::l7::CcDefenseConfig;
use crate::core::{CustomHttpResponse, InspectionLayer, InspectionResult};
use crate::protocol::UnifiedHttpRequest;
use dashmap::DashMap;
use log::debug;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const BYPASS_PATHS: &[&str] = &["/.well-known/waf/browser-fingerprint-report"];
const API_REQUEST_WEIGHT_PERCENT: u8 = 140;
const MAX_COUNTER_BUCKETS: usize = 65_536;
const MAX_PAGE_WINDOW_BUCKETS: usize = 32_768;
const MAX_BUCKET_KEY_LEN: usize = 192;
const MAX_ROUTE_PATH_LEN: usize = 160;
const MAX_HOST_LEN: usize = 96;
const OVERFLOW_SHARDS: u64 = 64;

#[derive(Debug)]
pub struct L7CcGuard {
    config: RwLock<CcDefenseConfig>,
    secret: String,
    ip_buckets: DashMap<String, SlidingWindowCounter>,
    host_buckets: DashMap<String, SlidingWindowCounter>,
    route_buckets: DashMap<String, SlidingWindowCounter>,
    hot_path_buckets: DashMap<String, SlidingWindowCounter>,
    hot_path_client_buckets: DashMap<String, DistinctSlidingWindowCounter>,
    ip_weighted_buckets: DashMap<String, WeightedSlidingWindowCounter>,
    host_weighted_buckets: DashMap<String, WeightedSlidingWindowCounter>,
    route_weighted_buckets: DashMap<String, WeightedSlidingWindowCounter>,
    hot_path_weighted_buckets: DashMap<String, WeightedSlidingWindowCounter>,
    page_load_windows: DashMap<String, PageLoadWindowState>,
    page_load_host_windows: DashMap<String, PageLoadWindowState>,
    request_sequence: AtomicU64,
}

#[derive(Debug)]
struct SlidingWindowCounter {
    events: Mutex<VecDeque<Instant>>,
    last_seen_unix: AtomicI64,
}

#[derive(Debug)]
struct WeightedSlidingWindowCounter {
    events: Mutex<VecDeque<(Instant, u16)>>,
    total_weight: AtomicU64,
    last_seen_unix: AtomicI64,
}

#[derive(Debug)]
struct PageLoadWindowState {
    expires_at_unix: AtomicI64,
    last_seen_unix: AtomicI64,
}

#[derive(Debug)]
struct DistinctSlidingWindowCounter {
    events: Mutex<VecDeque<(Instant, String)>>,
    counts: Mutex<HashMap<String, u32>>,
    last_seen_unix: AtomicI64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HtmlResponseMode {
    HtmlChallenge,
    TextOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestKind {
    Document,
    StaticAsset,
    ApiLike,
    Other,
}

impl RequestKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::StaticAsset => "static",
            Self::ApiLike => "api",
            Self::Other => "other",
        }
    }
}

impl L7CcGuard {
    pub fn new(config: &CcDefenseConfig) -> Self {
        let secret = format!("{:032x}", rand::thread_rng().gen::<u128>());
        Self {
            config: RwLock::new(config.clone()),
            secret,
            ip_buckets: DashMap::new(),
            host_buckets: DashMap::new(),
            route_buckets: DashMap::new(),
            hot_path_buckets: DashMap::new(),
            hot_path_client_buckets: DashMap::new(),
            ip_weighted_buckets: DashMap::new(),
            host_weighted_buckets: DashMap::new(),
            route_weighted_buckets: DashMap::new(),
            hot_path_weighted_buckets: DashMap::new(),
            page_load_windows: DashMap::new(),
            page_load_host_windows: DashMap::new(),
            request_sequence: AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> CcDefenseConfig {
        self.config
            .read()
            .expect("l7 cc config lock poisoned")
            .clone()
    }

    pub fn update_config(&self, config: &CcDefenseConfig) {
        let mut guard = self.config.write().expect("l7 cc config lock poisoned");
        *guard = config.clone();
    }

    pub fn allows_browser_fingerprint_report(
        &self,
        request: &UnifiedHttpRequest,
        fallback_client_ip: std::net::IpAddr,
    ) -> bool {
        let config = self.config();
        let client_ip = request_client_ip(request).unwrap_or(fallback_client_ip);
        let host = normalized_host(request);
        self.has_valid_challenge_cookie(request, client_ip, &host, &config)
    }

    pub async fn inspect_request(
        &self,
        request: &mut UnifiedHttpRequest,
    ) -> Option<InspectionResult> {
        let config = self.config();
        if !config.enabled {
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
        let request_kind = classify_request(request, &route_path);
        let html_mode = challenge_mode(request, &route_path);
        let identity_state = request
            .get_metadata("network.identity_state")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let client_identity_unresolved = request
            .get_metadata("network.client_ip_unresolved")
            .map(|value| value == "true")
            .unwrap_or(false);
        let spoofed_forward_header = identity_state == "spoofed_forward_header";
        let verified = self.has_valid_challenge_cookie(request, client_ip, &host, &config);
        let interactive_session = is_interactive_session(request, &host, verified);
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let window = Duration::from_secs(config.request_window_secs.max(1));

        request.add_metadata("l7.cc.identity_state".to_string(), identity_state.clone());

        if spoofed_forward_header {
            let reason = format!(
                "l7 cc guard blocked spoofed forwarded header request: host={} route={} peer_ip={} header_present=true",
                host, route_path, client_ip
            );
            request.add_metadata("l7.cc.action".to_string(), "block".to_string());
            return Some(InspectionResult::respond(
                InspectionLayer::L7,
                reason.clone(),
                build_block_response(request, &reason),
            ));
        }

        if request_kind == RequestKind::Document {
            self.record_page_load_window(client_ip, &host, &route_path, unix_now, &config);
        }
        let is_page_subresource = request_kind == RequestKind::StaticAsset
            && self.matches_page_load_window(request, client_ip, &host, &route_path, unix_now);
        let weight_percent = self.request_weight_percent(
            request_kind,
            is_page_subresource,
            interactive_session,
            &config,
        );

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
        let hot_path_client_count = self.observe_distinct(
            &self.hot_path_client_buckets,
            format!("{host}|{route_path}"),
            client_ip.to_string(),
            now,
            unix_now,
            window,
        );

        let ip_weighted_points = self.observe_weighted(
            &self.ip_weighted_buckets,
            client_ip.to_string(),
            now,
            unix_now,
            window,
            weight_percent,
        );
        let host_weighted_points = self.observe_weighted(
            &self.host_weighted_buckets,
            format!("{client_ip}|{host}"),
            now,
            unix_now,
            window,
            weight_percent,
        );
        let route_weighted_points = self.observe_weighted(
            &self.route_weighted_buckets,
            format!("{client_ip}|{host}|{method}|{route_path}"),
            now,
            unix_now,
            window,
            weight_percent,
        );
        let hot_path_weighted_points = self.observe_weighted(
            &self.hot_path_weighted_buckets,
            format!("{host}|{route_path}"),
            now,
            unix_now,
            window,
            weight_percent,
        );

        let ip_effective = weighted_points_to_requests(ip_weighted_points);
        let host_effective = weighted_points_to_requests(host_weighted_points);
        let route_effective = weighted_points_to_requests(route_weighted_points);
        let hot_path_effective = weighted_points_to_requests(hot_path_weighted_points);

        request.add_metadata("l7.cc.client_ip".to_string(), client_ip.to_string());
        request.add_metadata("l7.cc.host".to_string(), host.clone());
        request.add_metadata("l7.cc.route".to_string(), route_path.clone());
        request.add_metadata(
            "l7.cc.request_kind".to_string(),
            request_kind.as_str().to_string(),
        );
        request.add_metadata(
            "l7.cc.page_subresource".to_string(),
            is_page_subresource.to_string(),
        );
        request.add_metadata(
            "l7.cc.weight_percent".to_string(),
            weight_percent.to_string(),
        );
        request.add_metadata("l7.cc.ip_count".to_string(), ip_count.to_string());
        request.add_metadata("l7.cc.host_count".to_string(), host_count.to_string());
        request.add_metadata("l7.cc.route_count".to_string(), route_count.to_string());
        request.add_metadata(
            "l7.cc.hot_path_count".to_string(),
            hot_path_count.to_string(),
        );
        request.add_metadata(
            "l7.cc.hot_path_clients".to_string(),
            hot_path_client_count.to_string(),
        );
        request.add_metadata("l7.cc.ip_weighted".to_string(), ip_effective.to_string());
        request.add_metadata(
            "l7.cc.host_weighted".to_string(),
            host_effective.to_string(),
        );
        request.add_metadata(
            "l7.cc.route_weighted".to_string(),
            route_effective.to_string(),
        );
        request.add_metadata(
            "l7.cc.hot_path_weighted".to_string(),
            hot_path_effective.to_string(),
        );
        request.add_metadata("l7.cc.challenge_verified".to_string(), verified.to_string());
        request.add_metadata(
            "l7.cc.interactive_session".to_string(),
            interactive_session.to_string(),
        );
        request.add_metadata(
            "l7.cc.client_identity_unresolved".to_string(),
            client_identity_unresolved.to_string(),
        );

        self.maybe_cleanup(unix_now, &config);

        // A verified browser should avoid immediate re-challenge loops,
        // but it should not get a materially higher block threshold.
        let challenge_multiplier = if verified { 3 } else { 1 };
        let block_multiplier = 1;
        let interactive_host_ip_multiplier = if interactive_session { 4 } else { 1 };
        let interactive_host_ip_block_multiplier = if interactive_session { 3 } else { 1 };
        let low_risk_subresource = request_kind == RequestKind::StaticAsset
            && (is_page_subresource || interactive_session);
        let route_scale_percent = request
            .get_metadata("ai.cc.route_threshold_scale_percent")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(100)
            .clamp(10, 100);
        let host_scale_percent = request
            .get_metadata("ai.cc.host_threshold_scale_percent")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(100)
            .clamp(10, 100);
        let force_challenge = request
            .get_metadata("ai.cc.force_challenge")
            .map(|value| value == "true")
            .unwrap_or(false);
        let extra_delay_ms = request
            .get_metadata("ai.cc.extra_delay_ms")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);

        let route_block_threshold = config
            .route_block_threshold
            .saturating_mul(block_multiplier)
            .saturating_mul(route_scale_percent)
            / 100;
        let host_block_threshold = config
            .host_block_threshold
            .saturating_mul(block_multiplier)
            .saturating_mul(interactive_host_ip_block_multiplier);
        let host_block_threshold = host_block_threshold.saturating_mul(host_scale_percent) / 100;
        let ip_block_threshold = config
            .ip_block_threshold
            .saturating_mul(block_multiplier)
            .saturating_mul(interactive_host_ip_block_multiplier);
        let hot_path_block_threshold = config
            .hot_path_block_threshold
            .saturating_mul(block_multiplier);

        let hard_route_block_threshold =
            route_block_threshold.saturating_mul(u32::from(config.hard_route_block_multiplier));
        let hard_host_block_threshold =
            host_block_threshold.saturating_mul(u32::from(config.hard_host_block_multiplier));
        let hard_ip_block_threshold =
            ip_block_threshold.saturating_mul(u32::from(config.hard_ip_block_multiplier));
        let hard_hot_path_block_threshold = hot_path_block_threshold
            .saturating_mul(u32::from(config.hard_hot_path_block_multiplier));
        let global_hot_path_client_block_threshold =
            global_hot_path_client_block_threshold(&config);
        let global_hot_path_effective_block_threshold =
            global_hot_path_effective_block_threshold(&config);
        let hard_block = route_count >= hard_route_block_threshold
            || host_count >= hard_host_block_threshold
            || ip_count >= hard_ip_block_threshold
            || hot_path_count >= hard_hot_path_block_threshold;
        let global_hot_path_pressure_block =
            matches!(request_kind, RequestKind::ApiLike | RequestKind::Other)
                && hot_path_client_count >= global_hot_path_client_block_threshold
                && hot_path_effective >= global_hot_path_effective_block_threshold;

        if !client_identity_unresolved
            && (hard_block
                || global_hot_path_pressure_block
                || (!low_risk_subresource
                    && (route_effective >= route_block_threshold
                        || host_effective >= host_block_threshold
                        || ip_effective >= ip_block_threshold
                        || (hot_path_effective >= hot_path_block_threshold
                            && route_effective >= config.route_challenge_threshold.max(3)))))
        {
            let reason = format!(
                "l7 cc guard throttled request: kind={} page_subresource={} ip={} host={} route={} hot_path={} raw_ip={} raw_host={} raw_route={} raw_hot_path={} verified={} identity_unresolved={}",
                request_kind.as_str(),
                is_page_subresource,
                ip_effective,
                host_effective,
                route_effective,
                hot_path_effective,
                ip_count,
                host_count,
                route_count,
                hot_path_count,
                verified,
                client_identity_unresolved,
            );
            request.add_metadata("l7.cc.action".to_string(), "block".to_string());
            return Some(InspectionResult::respond(
                InspectionLayer::L7,
                reason.clone(),
                build_block_response(request, &reason),
            ));
        }

        let route_challenge_threshold = config
            .route_challenge_threshold
            .saturating_mul(challenge_multiplier)
            .saturating_mul(route_scale_percent)
            / 100;
        let host_challenge_threshold = config
            .host_challenge_threshold
            .saturating_mul(challenge_multiplier)
            .saturating_mul(interactive_host_ip_multiplier)
            .saturating_mul(host_scale_percent)
            / 100;
        let ip_challenge_threshold = config
            .ip_challenge_threshold
            .saturating_mul(challenge_multiplier)
            .saturating_mul(interactive_host_ip_multiplier);
        let hot_path_challenge_threshold = config
            .hot_path_challenge_threshold
            .saturating_mul(challenge_multiplier);
        let global_hot_path_client_challenge_threshold =
            global_hot_path_client_challenge_threshold(&config);
        let global_hot_path_effective_challenge_threshold =
            global_hot_path_effective_challenge_threshold(&config);
        let global_hot_path_pressure_challenge =
            matches!(request_kind, RequestKind::ApiLike | RequestKind::Other)
                && hot_path_client_count >= global_hot_path_client_challenge_threshold
                && hot_path_effective >= global_hot_path_effective_challenge_threshold;

        if !verified
            && !low_risk_subresource
            && (force_challenge
                || global_hot_path_pressure_challenge
                || route_effective >= route_challenge_threshold
                || host_effective >= host_challenge_threshold
                || ip_effective >= ip_challenge_threshold
                || (hot_path_effective >= hot_path_challenge_threshold
                    && route_effective >= route_challenge_threshold.saturating_sub(4).max(1)))
        {
            let action = challenge_action_name(html_mode);
            let reason = format!(
                "l7 cc guard {}: kind={} page_subresource={} ip={} host={} route={} hot_path={}",
                challenge_reason_verb(html_mode),
                request_kind.as_str(),
                is_page_subresource,
                ip_effective,
                host_effective,
                route_effective,
                hot_path_effective,
            );
            request.add_metadata("l7.cc.action".to_string(), action.to_string());
            return Some(InspectionResult::respond(
                InspectionLayer::L7,
                reason.clone(),
                self.build_challenge_response(
                    request, client_ip, &host, &reason, html_mode, &config,
                ),
            ));
        }

        let delay_threshold_percent = if client_identity_unresolved {
            config.delay_threshold_percent.saturating_sub(20).max(10)
        } else {
            config.delay_threshold_percent
        };
        let delay_threshold = u32::from(delay_threshold_percent)
            .saturating_mul(config.route_challenge_threshold.max(1))
            / 100;
        if config.delay_ms > 0
            && (route_effective >= delay_threshold.max(1)
                || host_effective
                    >= u32::from(delay_threshold_percent)
                        .saturating_mul(config.host_challenge_threshold.max(1))
                        / 100
                || ip_effective
                    >= u32::from(delay_threshold_percent)
                        .saturating_mul(config.ip_challenge_threshold.max(1))
                        / 100)
        {
            if should_drop_delay_under_pressure(request) {
                if !verified && !low_risk_subresource && !client_identity_unresolved {
                    let action = challenge_action_name(html_mode);
                    let reason = format!(
                        "l7 cc guard upgraded delay to {} under runtime pressure: kind={} ip={} host={} route={} hot_path={}",
                        challenge_reason_verb(html_mode),
                        request_kind.as_str(),
                        ip_effective,
                        host_effective,
                        route_effective,
                        hot_path_effective,
                    );
                    request.add_metadata("l7.cc.action".to_string(), action.to_string());
                    return Some(InspectionResult::respond(
                        InspectionLayer::L7,
                        reason.clone(),
                        self.build_challenge_response(
                            request, client_ip, &host, &reason, html_mode, &config,
                        ),
                    ));
                }
                request.add_metadata(
                    "l7.cc.action".to_string(),
                    "skip_delay:runtime_pressure".to_string(),
                );
                return None;
            }
            if client_identity_unresolved {
                debug!(
                    "L7 CC downgraded unresolved trusted-proxy request to delay-only: client_ip={} host={} route={} delay_ms={} route_effective={} host_effective={} ip_effective={}",
                    client_ip,
                    host,
                    route_path,
                    config.delay_ms,
                    route_effective,
                    host_effective,
                    ip_effective
                );
            }
            request.add_metadata(
                "l7.cc.action".to_string(),
                format!("delay:{}ms", config.delay_ms),
            );
            tokio::time::sleep(Duration::from_millis(config.delay_ms)).await;
        }
        if extra_delay_ms > 0 {
            if should_drop_delay_under_pressure(request) {
                request.add_metadata(
                    "l7.cc.action".to_string(),
                    "skip_delay:runtime_pressure".to_string(),
                );
                return None;
            }
            request.add_metadata(
                "l7.cc.action".to_string(),
                format!("delay:{}ms", extra_delay_ms),
            );
            tokio::time::sleep(Duration::from_millis(extra_delay_ms)).await;
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
                "var __rwafPayload={{fingerprintId:__rwafHash(__rwafSeed)+__rwafHash(__rwafSeed.split('').reverse().join('')),...JSON.parse(__rwafSeed)}};",
                "var __rwafDone=function(){{window.location.replace(__rwafTarget);}};",
                "try{{fetch(__rwafReport,{{method:'POST',headers:{{'content-type':'application/json'}},credentials:'same-origin',body:JSON.stringify(__rwafPayload),keepalive:true}}).finally(function(){{setTimeout(__rwafDone,60);}});}}catch(_e){{setTimeout(__rwafDone,60);}}",
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

    fn has_valid_challenge_cookie(
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

    fn observe(
        &self,
        map: &DashMap<String, SlidingWindowCounter>,
        key: String,
        now: Instant,
        unix_now: i64,
        window: Duration,
    ) -> u32 {
        let key = bounded_dashmap_key(map, key, MAX_COUNTER_BUCKETS, "cc", OVERFLOW_SHARDS);
        let mut entry = map.entry(key).or_insert_with(SlidingWindowCounter::new);
        entry.observe(now, unix_now, window)
    }

    fn observe_weighted(
        &self,
        map: &DashMap<String, WeightedSlidingWindowCounter>,
        key: String,
        now: Instant,
        unix_now: i64,
        window: Duration,
        weight_percent: u8,
    ) -> u32 {
        let key = bounded_dashmap_key(
            map,
            key,
            MAX_COUNTER_BUCKETS,
            "cc_weighted",
            OVERFLOW_SHARDS,
        );
        let mut entry = map
            .entry(key)
            .or_insert_with(WeightedSlidingWindowCounter::new);
        entry.observe(now, unix_now, window, weight_percent)
    }

    fn observe_distinct(
        &self,
        map: &DashMap<String, DistinctSlidingWindowCounter>,
        key: String,
        value: String,
        now: Instant,
        unix_now: i64,
        window: Duration,
    ) -> u32 {
        let key = bounded_dashmap_key(
            map,
            key,
            MAX_COUNTER_BUCKETS,
            "cc_distinct",
            OVERFLOW_SHARDS,
        );
        let mut entry = map
            .entry(key)
            .or_insert_with(DistinctSlidingWindowCounter::new);
        entry.observe(value, now, unix_now, window)
    }

    fn request_weight_percent(
        &self,
        kind: RequestKind,
        is_page_subresource: bool,
        interactive_session: bool,
        config: &CcDefenseConfig,
    ) -> u8 {
        if is_page_subresource {
            return config.page_subresource_weight_percent;
        }
        if interactive_session {
            return match kind {
                RequestKind::StaticAsset => config.static_request_weight_percent.min(30),
                RequestKind::ApiLike => API_REQUEST_WEIGHT_PERCENT.min(90),
                RequestKind::Document => 80,
                RequestKind::Other => 70,
            };
        }
        match kind {
            RequestKind::ApiLike => API_REQUEST_WEIGHT_PERCENT,
            RequestKind::StaticAsset => config.static_request_weight_percent,
            _ => 100,
        }
    }

    fn record_page_load_window(
        &self,
        client_ip: std::net::IpAddr,
        host: &str,
        document_path: &str,
        unix_now: i64,
        config: &CcDefenseConfig,
    ) {
        let key = bounded_dashmap_key(
            &self.page_load_windows,
            page_window_key(client_ip, host, document_path),
            MAX_PAGE_WINDOW_BUCKETS,
            "cc_page_window",
            OVERFLOW_SHARDS,
        );
        let host_key = bounded_dashmap_key(
            &self.page_load_host_windows,
            page_host_window_key(client_ip, host),
            MAX_PAGE_WINDOW_BUCKETS,
            "cc_page_host_window",
            OVERFLOW_SHARDS,
        );
        let expires_at = unix_now + config.page_load_grace_secs as i64;
        let mut entry = self
            .page_load_windows
            .entry(key)
            .or_insert_with(|| PageLoadWindowState::new(expires_at, unix_now));
        entry.refresh(expires_at, unix_now);
        let mut host_entry = self
            .page_load_host_windows
            .entry(host_key)
            .or_insert_with(|| PageLoadWindowState::new(expires_at, unix_now));
        host_entry.refresh(expires_at, unix_now);
    }

    fn matches_page_load_window(
        &self,
        request: &UnifiedHttpRequest,
        client_ip: std::net::IpAddr,
        host: &str,
        route_path: &str,
        unix_now: i64,
    ) -> bool {
        if !request.method.eq_ignore_ascii_case("GET")
            && !request.method.eq_ignore_ascii_case("HEAD")
        {
            return false;
        }

        if let Some((referer_host, referer_path)) = referer_host_path(request) {
            if referer_host.eq_ignore_ascii_case(host) {
                let key = bounded_dashmap_key(
                    &self.page_load_windows,
                    page_window_key(client_ip, host, &normalized_route_path(&referer_path)),
                    MAX_PAGE_WINDOW_BUCKETS,
                    "cc_page_window",
                    OVERFLOW_SHARDS,
                );
                if self
                    .page_load_windows
                    .get(&key)
                    .map(|entry| entry.is_active(unix_now))
                    .unwrap_or(false)
                {
                    return true;
                }
            }
        }

        // Weak match path: when Referer/Sec-Fetch metadata is missing but path strongly
        // looks like a static asset, still trust a short host-level page-load window.
        if !looks_like_static_asset(route_path) {
            return false;
        }
        let host_key = bounded_dashmap_key(
            &self.page_load_host_windows,
            page_host_window_key(client_ip, host),
            MAX_PAGE_WINDOW_BUCKETS,
            "cc_page_host_window",
            OVERFLOW_SHARDS,
        );
        self.page_load_host_windows
            .get(&host_key)
            .map(|entry| entry.is_active(unix_now))
            .unwrap_or(false)
    }

    fn maybe_cleanup(&self, unix_now: i64, config: &CcDefenseConfig) {
        let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let largest_map_len = [
            self.ip_buckets.len(),
            self.host_buckets.len(),
            self.route_buckets.len(),
            self.hot_path_buckets.len(),
            self.hot_path_client_buckets.len(),
            self.ip_weighted_buckets.len(),
            self.host_weighted_buckets.len(),
            self.route_weighted_buckets.len(),
            self.hot_path_weighted_buckets.len(),
            self.page_load_windows.len(),
            self.page_load_host_windows.len(),
        ]
        .into_iter()
        .max()
        .unwrap_or(0);
        let cleanup_interval = cleanup_interval_for_size(largest_map_len);
        if !sequence.is_multiple_of(cleanup_interval) {
            return;
        }

        let stale_before = unix_now - (config.request_window_secs as i64 * 6).max(30);
        let cleanup_batch = cleanup_batch_for_size(largest_map_len);
        cleanup_map(&self.ip_buckets, stale_before, cleanup_batch);
        cleanup_map(&self.host_buckets, stale_before, cleanup_batch);
        cleanup_map(&self.route_buckets, stale_before, cleanup_batch);
        cleanup_map(&self.hot_path_buckets, stale_before, cleanup_batch);
        cleanup_distinct_map(&self.hot_path_client_buckets, stale_before, cleanup_batch);
        cleanup_weighted_map(&self.ip_weighted_buckets, stale_before, cleanup_batch);
        cleanup_weighted_map(&self.host_weighted_buckets, stale_before, cleanup_batch);
        cleanup_weighted_map(&self.route_weighted_buckets, stale_before, cleanup_batch);
        cleanup_weighted_map(&self.hot_path_weighted_buckets, stale_before, cleanup_batch);
        cleanup_page_window_map(
            &self.page_load_windows,
            unix_now,
            stale_before,
            cleanup_batch,
        );
        cleanup_page_window_map(
            &self.page_load_host_windows,
            unix_now,
            stale_before,
            cleanup_batch,
        );
    }
}

fn challenge_action_name(mode: HtmlResponseMode) -> &'static str {
    match mode {
        HtmlResponseMode::HtmlChallenge => "challenge",
        HtmlResponseMode::TextOnly => "api_friction",
    }
}

fn is_interactive_session(request: &UnifiedHttpRequest, host: &str, verified: bool) -> bool {
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

fn challenge_reason_verb(mode: HtmlResponseMode) -> &'static str {
    match mode {
        HtmlResponseMode::HtmlChallenge => "issued challenge",
        HtmlResponseMode::TextOnly => "applied api friction",
    }
}

fn challenge_header_value(mode: HtmlResponseMode) -> &'static str {
    match mode {
        HtmlResponseMode::HtmlChallenge => "challenge",
        HtmlResponseMode::TextOnly => "api-friction",
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

impl WeightedSlidingWindowCounter {
    fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::new()),
            total_weight: AtomicU64::new(0),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    fn observe(
        &mut self,
        now: Instant,
        unix_now: i64,
        window: Duration,
        weight_percent: u8,
    ) -> u32 {
        let mut events = self
            .events
            .lock()
            .expect("cc weighted bucket lock poisoned");
        let mut total_weight = self.total_weight.load(Ordering::Relaxed) as u32;
        while let Some((front, _)) = events.front() {
            if now.duration_since(*front) > window {
                if let Some((_, expired_weight)) = events.pop_front() {
                    total_weight = total_weight.saturating_sub(u32::from(expired_weight));
                }
            } else {
                break;
            }
        }
        let weight = u16::from(weight_percent.max(1));
        events.push_back((now, weight));
        total_weight = total_weight.saturating_add(u32::from(weight));
        self.total_weight
            .store(u64::from(total_weight), Ordering::Relaxed);
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        total_weight
    }
}

impl PageLoadWindowState {
    fn new(expires_at_unix: i64, unix_now: i64) -> Self {
        Self {
            expires_at_unix: AtomicI64::new(expires_at_unix),
            last_seen_unix: AtomicI64::new(unix_now),
        }
    }

    fn refresh(&mut self, expires_at_unix: i64, unix_now: i64) {
        self.expires_at_unix
            .store(expires_at_unix, Ordering::Relaxed);
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
    }

    fn is_active(&self, unix_now: i64) -> bool {
        self.expires_at_unix.load(Ordering::Relaxed) >= unix_now
    }
}

impl DistinctSlidingWindowCounter {
    fn new() -> Self {
        Self {
            events: Mutex::new(VecDeque::new()),
            counts: Mutex::new(HashMap::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    fn observe(&mut self, value: String, now: Instant, unix_now: i64, window: Duration) -> u32 {
        let mut events = self
            .events
            .lock()
            .expect("cc distinct bucket lock poisoned");
        let mut counts = self
            .counts
            .lock()
            .expect("cc distinct counts lock poisoned");
        while let Some((front, _)) = events.front() {
            if now.duration_since(*front) > window {
                if let Some((_, expired)) = events.pop_front() {
                    if let Some(count) = counts.get_mut(&expired) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            counts.remove(&expired);
                        }
                    }
                }
            } else {
                break;
            }
        }
        events.push_back((now, value.clone()));
        *counts.entry(value).or_insert(0) += 1;
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        counts.len().min(u32::MAX as usize) as u32
    }
}

fn weighted_points_to_requests(points: u32) -> u32 {
    if points == 0 {
        return 0;
    }
    points.div_ceil(100)
}

fn cleanup_interval_for_size(size: usize) -> u64 {
    match size {
        0..=2_047 => 1_024,
        2_048..=8_191 => 256,
        _ => 64,
    }
}

fn cleanup_batch_for_size(size: usize) -> usize {
    match size {
        0..=2_047 => 128,
        2_048..=8_191 => 512,
        _ => 2_048,
    }
}

fn cleanup_map(map: &DashMap<String, SlidingWindowCounter>, stale_before: i64, limit: usize) {
    let keys = map
        .iter()
        .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
        .take(limit)
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();

    for key in keys {
        map.remove(&key);
    }
}

fn cleanup_weighted_map(
    map: &DashMap<String, WeightedSlidingWindowCounter>,
    stale_before: i64,
    limit: usize,
) {
    let keys = map
        .iter()
        .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
        .take(limit)
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();

    for key in keys {
        map.remove(&key);
    }
}

fn cleanup_distinct_map(
    map: &DashMap<String, DistinctSlidingWindowCounter>,
    stale_before: i64,
    limit: usize,
) {
    let keys = map
        .iter()
        .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
        .take(limit)
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();

    for key in keys {
        map.remove(&key);
    }
}

fn cleanup_page_window_map(
    map: &DashMap<String, PageLoadWindowState>,
    unix_now: i64,
    stale_before: i64,
    limit: usize,
) {
    let keys = map
        .iter()
        .filter(|entry| {
            let value = entry.value();
            value.expires_at_unix.load(Ordering::Relaxed) < unix_now
                && value.last_seen_unix.load(Ordering::Relaxed) < stale_before
        })
        .take(limit)
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

fn classify_request(request: &UnifiedHttpRequest, route_path: &str) -> RequestKind {
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
            && (accept.contains("text/html") || accept.contains("application/xhtml+xml")))
    {
        return RequestKind::Document;
    }

    if is_static_asset_request(request, route_path, &method, &accept) {
        return RequestKind::StaticAsset;
    }

    RequestKind::Other
}

fn has_static_fetch_dest(request: &UnifiedHttpRequest) -> bool {
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

fn is_api_like_request(method: &str, route_path: &str, accept: &str, content_type: &str) -> bool {
    ((method != "GET") && (method != "HEAD"))
        || method == "OPTIONS"
        || route_path.starts_with("/api/")
        || accept.contains("application/json")
        || content_type.contains("application/json")
}

fn is_static_asset_request(
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

fn referer_host_path(request: &UnifiedHttpRequest) -> Option<(String, String)> {
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

fn extract_host_from_origin(origin: &str) -> Option<String> {
    let trimmed = origin.trim();
    if trimmed.is_empty() {
        return None;
    }
    let uri: http::Uri = trimmed.parse().ok()?;
    Some(uri.host()?.to_ascii_lowercase())
}

fn page_window_key(client_ip: std::net::IpAddr, host: &str, document_path: &str) -> String {
    format!("{client_ip}|{host}|{document_path}")
}

fn page_host_window_key(client_ip: std::net::IpAddr, host: &str) -> String {
    format!("{client_ip}|{host}")
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

fn global_hot_path_client_challenge_threshold(config: &CcDefenseConfig) -> u32 {
    config.route_challenge_threshold.saturating_div(2).max(4)
}

fn global_hot_path_client_block_threshold(config: &CcDefenseConfig) -> u32 {
    config
        .route_block_threshold
        .saturating_div(2)
        .max(global_hot_path_client_challenge_threshold(config).saturating_mul(2))
        .max(8)
}

fn global_hot_path_effective_challenge_threshold(config: &CcDefenseConfig) -> u32 {
    config.route_challenge_threshold.saturating_div(2).max(4)
}

fn global_hot_path_effective_block_threshold(config: &CcDefenseConfig) -> u32 {
    config
        .route_block_threshold
        .saturating_div(2)
        .max(global_hot_path_effective_challenge_threshold(config).saturating_mul(2))
        .max(8)
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
    compact_component("route", trimmed.trim_end_matches('/'), MAX_ROUTE_PATH_LEN)
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

fn looks_like_static_asset(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    [
        ".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2",
        ".ttf", ".map",
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

fn bounded_dashmap_key<T>(
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

fn compact_component(label: &str, value: &str, max_len: usize) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= max_len {
        return trimmed.to_string();
    }
    format!("{label}:{:016x}", stable_hash(trimmed))
}

fn overflow_bucket_key(namespace: &str, value: &str, overflow_shards: u64) -> String {
    let shard = stable_hash(value) % overflow_shards.max(1);
    format!("__overflow__:{namespace}:{shard:02x}")
}

fn stable_hash(value: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn should_drop_delay_under_pressure(request: &UnifiedHttpRequest) -> bool {
    request
        .get_metadata("runtime.pressure.drop_delay")
        .map(|value| value == "true")
        .unwrap_or(false)
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

    fn unresolved_proxy_request(uri: &str) -> UnifiedHttpRequest {
        let mut request = request(uri);
        request.add_metadata("network.trusted_proxy_peer".to_string(), "true".to_string());
        request.add_metadata(
            "network.client_ip_unresolved".to_string(),
            "true".to_string(),
        );
        request.add_metadata(
            "network.identity_state".to_string(),
            "trusted_cdn_unresolved".to_string(),
        );
        request
    }

    fn spoofed_forward_header_request(uri: &str) -> UnifiedHttpRequest {
        let mut request = request(uri);
        request.add_metadata(
            "network.identity_state".to_string(),
            "spoofed_forward_header".to_string(),
        );
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

    #[tokio::test]
    async fn page_subresources_are_not_challenged_aggressively() {
        let config = CcDefenseConfig {
            route_challenge_threshold: 2,
            route_block_threshold: 3,
            page_load_grace_secs: 5,
            ..CcDefenseConfig::default()
        };
        let guard = L7CcGuard::new(&config);

        let mut doc = request("/index.html");
        doc.add_header("sec-fetch-dest".to_string(), "document".to_string());
        assert!(guard.inspect_request(&mut doc).await.is_none());

        let mut img = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/assets/a.png".to_string(),
        );
        img.set_client_ip("203.0.113.10".to_string());
        img.add_header("host".to_string(), "example.com".to_string());
        img.add_header("sec-fetch-dest".to_string(), "image".to_string());
        img.add_header(
            "referer".to_string(),
            "https://example.com/index.html".to_string(),
        );

        assert!(guard.inspect_request(&mut img).await.is_none());
    }

    #[tokio::test]
    async fn api_requests_accumulate_weight_faster_than_documents() {
        let config = CcDefenseConfig {
            route_challenge_threshold: 3,
            route_block_threshold: 20,
            host_challenge_threshold: 20,
            host_block_threshold: 40,
            ip_challenge_threshold: 20,
            ip_block_threshold: 40,
            ..CcDefenseConfig::default()
        };
        let guard = L7CcGuard::new(&config);

        let mut first = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "POST".to_string(),
            "/api/search".to_string(),
        );
        first.set_client_ip("203.0.113.10".to_string());
        first.add_header("host".to_string(), "example.com".to_string());
        first.add_header("accept".to_string(), "application/json".to_string());
        assert!(guard.inspect_request(&mut first).await.is_none());
        assert_eq!(
            first
                .get_metadata("l7.cc.weight_percent")
                .map(String::as_str),
            Some("140")
        );

        let mut second = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "POST".to_string(),
            "/api/search".to_string(),
        );
        second.set_client_ip("203.0.113.10".to_string());
        second.add_header("host".to_string(), "example.com".to_string());
        second.add_header("accept".to_string(), "application/json".to_string());
        let result = guard.inspect_request(&mut second).await;
        assert!(result.is_some(), "api-like traffic should challenge sooner");
        assert_eq!(
            second
                .get_metadata("l7.cc.request_kind")
                .map(String::as_str),
            Some("api")
        );
        assert_eq!(
            second.get_metadata("l7.cc.action").map(String::as_str),
            Some("api_friction")
        );
        let response = result
            .and_then(|item| item.custom_response)
            .expect("api friction response");
        assert_eq!(response.status_code, 429);
        assert!(response
            .headers
            .iter()
            .any(|(key, value)| { key == "x-rust-waf-cc-action" && value == "api-friction" }));
    }

    #[tokio::test]
    async fn distributed_api_requests_trigger_global_hot_path_pressure() {
        let config = CcDefenseConfig {
            route_challenge_threshold: 8,
            route_block_threshold: 16,
            host_challenge_threshold: 100,
            host_block_threshold: 200,
            ip_challenge_threshold: 100,
            ip_block_threshold: 200,
            hot_path_challenge_threshold: 500,
            hot_path_block_threshold: 1_000,
            ..CcDefenseConfig::default()
        };
        let guard = L7CcGuard::new(&config);

        for idx in 0..3 {
            let mut request = UnifiedHttpRequest::new(
                HttpVersion::Http1_1,
                "POST".to_string(),
                "/api/checkout".to_string(),
            );
            request.set_client_ip(format!("203.0.113.{}", idx + 10));
            request.add_header("host".to_string(), "example.com".to_string());
            request.add_header("accept".to_string(), "application/json".to_string());
            assert!(guard.inspect_request(&mut request).await.is_none());
            assert_eq!(
                request
                    .get_metadata("l7.cc.hot_path_clients")
                    .map(String::as_str),
                Some(match idx {
                    0 => "1",
                    1 => "2",
                    _ => "3",
                })
            );
        }

        let mut fourth = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "POST".to_string(),
            "/api/checkout".to_string(),
        );
        fourth.set_client_ip("203.0.113.20".to_string());
        fourth.add_header("host".to_string(), "example.com".to_string());
        fourth.add_header("accept".to_string(), "application/json".to_string());
        let result = guard.inspect_request(&mut fourth).await;
        assert!(
            result.is_some(),
            "distributed pressure should trigger challenge"
        );
        assert_eq!(
            fourth
                .get_metadata("l7.cc.hot_path_clients")
                .map(String::as_str),
            Some("4")
        );
    }

    #[tokio::test]
    async fn hard_multiplier_configuration_can_force_block_for_subresources() {
        let config = CcDefenseConfig {
            route_challenge_threshold: 100,
            route_block_threshold: 2,
            hard_route_block_multiplier: 1,
            page_load_grace_secs: 5,
            ..CcDefenseConfig::default()
        };
        let guard = L7CcGuard::new(&config);

        let mut doc = request("/index.html");
        doc.add_header("sec-fetch-dest".to_string(), "document".to_string());
        assert!(guard.inspect_request(&mut doc).await.is_none());

        let mut first_img = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/assets/a.png".to_string(),
        );
        first_img.set_client_ip("203.0.113.10".to_string());
        first_img.add_header("host".to_string(), "example.com".to_string());
        first_img.add_header(
            "referer".to_string(),
            "https://example.com/index.html".to_string(),
        );
        assert!(guard.inspect_request(&mut first_img).await.is_none());

        let mut second_img = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/assets/a.png".to_string(),
        );
        second_img.set_client_ip("203.0.113.10".to_string());
        second_img.add_header("host".to_string(), "example.com".to_string());
        second_img.add_header(
            "referer".to_string(),
            "https://example.com/index.html".to_string(),
        );
        let result = guard.inspect_request(&mut second_img).await;
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().action,
            crate::core::InspectionAction::Respond
        );
    }

    #[tokio::test]
    async fn unresolved_proxy_identity_can_be_challenged_without_direct_block() {
        let config = CcDefenseConfig {
            route_challenge_threshold: 2,
            route_block_threshold: 2,
            host_challenge_threshold: 2,
            host_block_threshold: 2,
            ip_challenge_threshold: 2,
            ip_block_threshold: 2,
            delay_threshold_percent: 100,
            delay_ms: 1,
            ..CcDefenseConfig::default()
        };
        let guard = L7CcGuard::new(&config);

        let mut first = unresolved_proxy_request("/search?q=1");
        let first_result = guard.inspect_request(&mut first).await;
        assert!(first_result.is_none());

        let mut second = unresolved_proxy_request("/search?q=2");
        let second_result = guard.inspect_request(&mut second).await;
        assert!(second_result.is_some());
        let second_result = second_result.unwrap();
        assert_eq!(
            second.get_metadata("l7.cc.action").map(String::as_str),
            Some("challenge")
        );
        assert_eq!(second_result.action, crate::core::InspectionAction::Respond);
        assert_eq!(
            second
                .get_metadata("l7.cc.client_identity_unresolved")
                .map(String::as_str),
            Some("true")
        );
    }

    #[tokio::test]
    async fn spoofed_forward_header_requests_are_blocked_immediately() {
        let guard = L7CcGuard::new(&CcDefenseConfig::default());
        let mut request = spoofed_forward_header_request("/search?q=1");

        let result = guard.inspect_request(&mut request).await;

        assert!(result.is_some());
        let result = result.unwrap();
        assert_eq!(result.action, crate::core::InspectionAction::Respond);
        assert_eq!(
            request.get_metadata("l7.cc.action").map(String::as_str),
            Some("block")
        );
        assert!(result.reason.contains("spoofed forwarded header"));
    }

    #[tokio::test]
    async fn updating_config_preserves_existing_request_history() {
        let mut config = CcDefenseConfig {
            route_challenge_threshold: 3,
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
        assert!(guard.inspect_request(&mut second).await.is_none());

        config.route_challenge_threshold = 2;
        guard.update_config(&config);

        let mut third = request("/search?q=3");
        let result = guard.inspect_request(&mut third).await;
        assert!(
            result.is_some(),
            "existing counters should survive config updates"
        );
        assert_eq!(
            result.unwrap().action,
            crate::core::InspectionAction::Respond
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
                guard.config().challenge_cookie_name
            ),
        );

        let config = guard.config();
        assert!(guard.has_valid_challenge_cookie(
            &request,
            "203.0.113.10".parse().unwrap(),
            "example.com",
            &config,
        ));
    }

    #[test]
    fn browser_fingerprint_report_requires_valid_challenge_cookie() {
        let config = CcDefenseConfig::default();
        let guard = L7CcGuard::new(&config);
        let client_ip = "203.0.113.10".parse().unwrap();
        let mut request = request("/");
        let expires_at = unix_timestamp() + 60;
        let nonce = "fpcheck";
        let signature = sign_challenge(&guard.secret, client_ip, "example.com", expires_at, nonce);
        request.add_header(
            "cookie".to_string(),
            format!(
                "{}={expires_at}:{nonce}:{signature}",
                guard.config().challenge_cookie_name
            ),
        );

        assert!(guard.allows_browser_fingerprint_report(&request, client_ip));
        request.headers.remove("cookie");
        assert!(!guard.allows_browser_fingerprint_report(&request, client_ip));
    }

    #[test]
    fn cleanup_strategy_scales_with_map_size() {
        assert_eq!(cleanup_interval_for_size(128), 1_024);
        assert_eq!(cleanup_batch_for_size(128), 128);
        assert_eq!(cleanup_interval_for_size(4_096), 256);
        assert_eq!(cleanup_batch_for_size(4_096), 512);
        assert_eq!(cleanup_interval_for_size(16_384), 64);
        assert_eq!(cleanup_batch_for_size(16_384), 2_048);
    }

    #[test]
    fn long_route_and_host_are_compacted() {
        let mut request = request("/");
        request.add_header("host".to_string(), "a".repeat(MAX_HOST_LEN + 48));
        let host = normalized_host(&request);
        assert!(host.len() <= MAX_HOST_LEN);
        assert!(host.starts_with("host:"));

        let route = normalized_route_path(&format!("/{}", "x".repeat(MAX_ROUTE_PATH_LEN + 48)));
        assert!(route.len() <= MAX_ROUTE_PATH_LEN);
        assert!(route.starts_with("route:"));
    }

    #[test]
    fn bounded_dashmap_key_overflows_when_limit_is_hit() {
        let map = DashMap::new();
        map.insert("first".to_string(), SlidingWindowCounter::new());
        map.insert("second".to_string(), SlidingWindowCounter::new());

        let key = bounded_dashmap_key(&map, "third".to_string(), 2, "cc-test", 4);

        assert!(key.starts_with("__overflow__:cc-test:"));
    }

    #[tokio::test]
    async fn interactive_same_origin_sessions_relax_host_and_ip_pressure() {
        let config = CcDefenseConfig {
            route_challenge_threshold: 8,
            route_block_threshold: 16,
            host_challenge_threshold: 6,
            host_block_threshold: 10,
            ip_challenge_threshold: 6,
            ip_block_threshold: 10,
            ..CcDefenseConfig::default()
        };
        let guard = L7CcGuard::new(&config);

        for index in 0..7 {
            let mut request = UnifiedHttpRequest::new(
                HttpVersion::Http1_1,
                if index % 2 == 0 { "GET" } else { "POST" }.to_string(),
                format!("/console/route-{index}"),
            );
            request.set_client_ip("203.0.113.10".to_string());
            request.add_header("host".to_string(), "example.com".to_string());
            request.add_header("cookie".to_string(), "rwaf_fp=stablefp".to_string());
            request.add_header("sec-fetch-site".to_string(), "same-origin".to_string());
            request.add_header(
                "sec-fetch-mode".to_string(),
                if index % 2 == 0 { "navigate" } else { "cors" }.to_string(),
            );
            request.add_header(
                "referer".to_string(),
                "https://example.com/console/home".to_string(),
            );
            if index % 2 == 0 {
                request.add_header("accept".to_string(), "text/html".to_string());
                request.add_metadata(
                    "l7.behavior.flags".to_string(),
                    "broad_navigation_context".to_string(),
                );
                request.add_metadata("l7.behavior.score".to_string(), "0".to_string());
            } else {
                request.add_header("accept".to_string(), "application/json".to_string());
                request.add_header("x-requested-with".to_string(), "XMLHttpRequest".to_string());
                request.add_metadata(
                    "l7.behavior.flags".to_string(),
                    "broad_navigation_context".to_string(),
                );
                request.add_metadata("l7.behavior.score".to_string(), "0".to_string());
            }
            let result = guard.inspect_request(&mut request).await;
            assert!(
                result.is_none(),
                "interactive same-origin traffic should not trip host/ip pressure on iteration {index}"
            );
            assert_eq!(
                request
                    .get_metadata("l7.cc.interactive_session")
                    .map(String::as_str),
                Some("true")
            );
        }
    }

    #[tokio::test]
    async fn delay_is_upgraded_to_challenge_under_runtime_pressure() {
        let config = CcDefenseConfig {
            route_challenge_threshold: 100,
            route_block_threshold: 200,
            host_challenge_threshold: 100,
            host_block_threshold: 200,
            ip_challenge_threshold: 100,
            ip_block_threshold: 200,
            delay_threshold_percent: 1,
            delay_ms: 150,
            ..CcDefenseConfig::default()
        };
        let guard = L7CcGuard::new(&config);
        let mut request = request("/hot");
        request.add_metadata(
            "runtime.pressure.drop_delay".to_string(),
            "true".to_string(),
        );

        let result = guard.inspect_request(&mut request).await;

        assert!(result.is_some());
        assert_eq!(
            request.get_metadata("l7.cc.action").map(String::as_str),
            Some("challenge")
        );
    }
}
