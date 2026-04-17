use super::counters::{
    cleanup_batch_for_size, cleanup_distinct_map, cleanup_interval_for_size, cleanup_map,
    cleanup_page_window_map, cleanup_weighted_map, weighted_points_to_requests,
};
use super::helpers::*;
use super::types::*;
use super::L7CcGuard;
use crate::config::l7::CcDefenseConfig;
use crate::core::{CustomHttpResponse, InspectionLayer, InspectionResult};
use crate::protocol::UnifiedHttpRequest;
use dashmap::DashMap;
use log::debug;
use rand::Rng;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

impl L7CcGuard {
    pub async fn inspect_request(
        &self,
        request: &mut UnifiedHttpRequest,
    ) -> Option<InspectionResult> {
        let config = self.config();
        if !config.enabled {
            return None;
        }
        let defense_depth = runtime_defense_depth(request);
        let rich_tracking = matches!(
            defense_depth,
            crate::core::DefenseDepth::Full | crate::core::DefenseDepth::Balanced
        );
        let bucket_limit = runtime_usize_metadata(
            request,
            "runtime.budget.l7_bucket_limit",
            MAX_COUNTER_BUCKETS,
        )
        .clamp(512, MAX_COUNTER_BUCKETS);
        let page_window_limit = runtime_usize_metadata(
            request,
            "runtime.budget.l7_page_window_limit",
            MAX_PAGE_WINDOW_BUCKETS,
        )
        .clamp(128, MAX_PAGE_WINDOW_BUCKETS);

        let client_ip = request_client_ip(request)?;
        let raw_path = request_path(&request.uri).to_string();
        if BYPASS_PATHS.contains(&raw_path.as_str()) {
            return None;
        }

        let host = normalized_host(request);
        let route_path = normalized_route_path(&raw_path);
        let method = request.method.to_ascii_uppercase();
        let request_kind = classify_request(request, &raw_path);
        let html_mode = challenge_mode(request, &raw_path);
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
            request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
            request.add_metadata(
                "l7.drop_reason".to_string(),
                "spoofed_forward_header".to_string(),
            );
            request.add_metadata("l4.force_close".to_string(), "true".to_string());
            return Some(InspectionResult::drop(InspectionLayer::L7, reason));
        }

        if rich_tracking && request_kind == RequestKind::Document {
            self.record_page_load_window(
                client_ip,
                &host,
                &route_path,
                unix_now,
                &config,
                page_window_limit,
            );
        }
        let is_page_subresource = rich_tracking
            && request_kind == RequestKind::StaticAsset
            && self.matches_page_load_window(
                request,
                client_ip,
                &host,
                &raw_path,
                unix_now,
                page_window_limit,
            );
        let verified_static_asset = verified && request_kind == RequestKind::StaticAsset;
        let effective_page_subresource = is_page_subresource || verified_static_asset;
        let weight_percent = self.request_weight_percent(
            request_kind,
            effective_page_subresource,
            interactive_session,
            &config,
        );

        let ip_count = self.observe(
            &self.ip_buckets,
            client_ip.to_string(),
            now,
            unix_now,
            window,
            bucket_limit,
        );
        let host_count = self.observe(
            &self.host_buckets,
            format!("{client_ip}|{host}"),
            now,
            unix_now,
            window,
            bucket_limit,
        );
        let route_count = self.observe(
            &self.route_buckets,
            format!("{client_ip}|{host}|{method}|{route_path}"),
            now,
            unix_now,
            window,
            bucket_limit,
        );
        let hot_path_count = self.observe(
            &self.hot_path_buckets,
            format!("{host}|{route_path}"),
            now,
            unix_now,
            window,
            bucket_limit,
        );
        let hot_path_client_count = if rich_tracking {
            self.observe_distinct(
                &self.hot_path_client_buckets,
                format!("{host}|{route_path}"),
                client_ip.to_string(),
                now,
                unix_now,
                window,
                bucket_limit,
            )
        } else {
            0
        };

        let (
            ip_weighted_points,
            host_weighted_points,
            route_weighted_points,
            hot_path_weighted_points,
        ) = if rich_tracking {
            (
                self.observe_weighted(
                    &self.ip_weighted_buckets,
                    client_ip.to_string(),
                    now,
                    unix_now,
                    window,
                    weight_percent,
                    bucket_limit,
                ),
                self.observe_weighted(
                    &self.host_weighted_buckets,
                    format!("{client_ip}|{host}"),
                    now,
                    unix_now,
                    window,
                    weight_percent,
                    bucket_limit,
                ),
                self.observe_weighted(
                    &self.route_weighted_buckets,
                    format!("{client_ip}|{host}|{method}|{route_path}"),
                    now,
                    unix_now,
                    window,
                    weight_percent,
                    bucket_limit,
                ),
                self.observe_weighted(
                    &self.hot_path_weighted_buckets,
                    format!("{host}|{route_path}"),
                    now,
                    unix_now,
                    window,
                    weight_percent,
                    bucket_limit,
                ),
            )
        } else {
            (
                ip_count.saturating_mul(100),
                host_count.saturating_mul(100),
                route_count.saturating_mul(100),
                hot_path_count.saturating_mul(100),
            )
        };

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
            "l7.cc.verified_static_asset".to_string(),
            verified_static_asset.to_string(),
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
        request.add_metadata("l7.cc.rich_tracking".to_string(), rich_tracking.to_string());

        self.maybe_cleanup(unix_now, &config);

        // A verified browser should avoid immediate re-challenge loops,
        // but it should not get a materially higher block threshold.
        let challenge_multiplier = if verified { 3 } else { 1 };
        let block_multiplier = 1;
        let interactive_host_ip_multiplier = if interactive_session { 4 } else { 1 };
        let interactive_host_ip_block_multiplier = if interactive_session { 3 } else { 1 };
        let low_risk_subresource = request_kind == RequestKind::StaticAsset
            && (effective_page_subresource || interactive_session);
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
            request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
            request.add_metadata("l7.drop_reason".to_string(), "cc_hard_block".to_string());
            request.add_metadata("l4.force_close".to_string(), "true".to_string());
            return Some(InspectionResult::drop_and_persist_ip(
                InspectionLayer::L7,
                reason,
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

        let challenge_needed = force_challenge
            || global_hot_path_pressure_challenge
            || route_effective >= route_challenge_threshold
            || host_effective >= host_challenge_threshold
            || ip_effective >= ip_challenge_threshold
            || (hot_path_effective >= hot_path_challenge_threshold
                && route_effective >= route_challenge_threshold.saturating_sub(4).max(1));

        if !verified && !low_risk_subresource && challenge_needed {
            if request_kind == RequestKind::StaticAsset {
                request.add_metadata(
                    "l7.cc.action".to_string(),
                    "skip_challenge:static_asset".to_string(),
                );
            } else {
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
                if !verified
                    && !low_risk_subresource
                    && !client_identity_unresolved
                    && request_kind != RequestKind::StaticAsset
                {
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
        let reason_html = if config.challenge_page.show_reason {
            format!("<p><code>{}</code></p>", escape_html(reason))
        } else {
            String::new()
        };
        let title = escape_html(&config.challenge_page.title);
        let heading = escape_html(&config.challenge_page.heading);
        let description = escape_html(&config.challenge_page.description);
        let completion_message = escape_html(&config.challenge_page.completion_message);
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
                "var __rwafPayload={{fingerprintId:__rwafHash(__rwafSeed)+__rwafHash(__rwafSeed.split('').reverse().join('')),...JSON.parse(__rwafSeed)}};",
                "var __rwafDone=function(){{window.location.replace(__rwafTarget);}};",
                "try{{fetch(__rwafReport,{{method:'POST',headers:{{'content-type':'application/json'}},credentials:'same-origin',body:JSON.stringify(__rwafPayload),keepalive:true}}).finally(function(){{setTimeout(__rwafDone,60);}});}}catch(_e){{setTimeout(__rwafDone,60);}}",
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

    fn observe(
        &self,
        map: &DashMap<String, SlidingWindowCounter>,
        key: String,
        now: Instant,
        unix_now: i64,
        window: Duration,
        limit: usize,
    ) -> u32 {
        let key = bounded_dashmap_key(map, key, limit, "cc", OVERFLOW_SHARDS);
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
        limit: usize,
    ) -> u32 {
        let key = bounded_dashmap_key(map, key, limit, "cc_weighted", OVERFLOW_SHARDS);
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
        limit: usize,
    ) -> u32 {
        let key = bounded_dashmap_key(map, key, limit, "cc_distinct", OVERFLOW_SHARDS);
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
        limit: usize,
    ) {
        let key = bounded_dashmap_key(
            &self.page_load_windows,
            page_window_key(client_ip, host, document_path),
            limit,
            "cc_page_window",
            OVERFLOW_SHARDS,
        );
        let host_key = bounded_dashmap_key(
            &self.page_load_host_windows,
            page_host_window_key(client_ip, host),
            limit,
            "cc_page_host_window",
            OVERFLOW_SHARDS,
        );
        let expires_at = unix_now + effective_page_load_grace_secs(config) as i64;
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
        raw_path: &str,
        unix_now: i64,
        limit: usize,
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
                    limit,
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
        if !looks_like_static_asset(raw_path) {
            return false;
        }
        let host_key = bounded_dashmap_key(
            &self.page_load_host_windows,
            page_host_window_key(client_ip, host),
            limit,
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

fn runtime_defense_depth(request: &UnifiedHttpRequest) -> crate::core::DefenseDepth {
    request
        .get_metadata("runtime.defense.depth")
        .map(|value| crate::core::DefenseDepth::from_str(value))
        .unwrap_or(crate::core::DefenseDepth::Balanced)
}

fn runtime_usize_metadata(request: &UnifiedHttpRequest, key: &str, default: usize) -> usize {
    request
        .get_metadata(key)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}
