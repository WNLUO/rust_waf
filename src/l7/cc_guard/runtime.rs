use super::counters::weighted_points_to_requests;
use super::helpers::*;
use super::types::*;
use super::L7CcGuard;
use crate::core::{InspectionLayer, InspectionResult};
use crate::protocol::UnifiedHttpRequest;
use log::debug;
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
        if request
            .get_metadata("network.server_public_ip_exempt")
            .map(|value| value == "true")
            .unwrap_or(false)
        {
            request.add_metadata("l7.cc.skipped".to_string(), "server_public_ip".to_string());
            return None;
        }
        if matches!(
            request
                .get_metadata("client.trust_class")
                .map(String::as_str),
            Some("internal" | "verified_good_bot")
        ) {
            request.add_metadata(
                "l7.cc.skipped".to_string(),
                request
                    .get_metadata("client.trust_class")
                    .map(|value| format!("client_trust:{value}"))
                    .unwrap_or_else(|| "client_trust".to_string()),
            );
            return None;
        }
        let bot_reduce_friction =
            request.get_metadata("bot.policy").map(String::as_str) == Some("reduce_friction");
        let known_bot_threshold_multiplier = if request
            .get_metadata("client.trust_class")
            .map(String::as_str)
            == Some("claimed_good_bot")
        {
            if bot_reduce_friction {
                3
            } else {
                2
            }
        } else {
            1
        };
        let bot_threshold_scale_percent = if request
            .get_metadata("client.trust_class")
            .map(String::as_str)
            == Some("suspect_bot")
        {
            60
        } else {
            100
        };
        let reduce_friction = bot_reduce_friction
            || request
                .get_metadata("ai.visitor.reduce_friction")
                .is_some_and(|value| value == "true");
        let defense_depth = runtime_defense_depth(request);
        if defense_depth == crate::core::DefenseDepth::Survival {
            return match self.inspect_survival_fast(request, &config).await {
                SurvivalFastPathResult::Block(result)
                | SurvivalFastPathResult::Challenge(result) => Some(result),
                SurvivalFastPathResult::NoDecision => None,
            };
        }
        let tracking_mode = runtime_tracking_mode(request, defense_depth);
        let rich_tracking = tracking_mode == CcTrackingMode::Rich;
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

        if is_survival_low_risk_identity_request(request, &route_path) {
            let verified_normal_kind = if looks_like_static_asset(&route_path) {
                RequestKind::StaticAsset
            } else {
                RequestKind::Document
            };
            request.add_metadata(
                "l7.cc.survival_verified_normal".to_string(),
                "true".to_string(),
            );
            if interactive_session {
                request.add_metadata("l7.cc.interactive_session".to_string(), "true".to_string());
            }
            request.add_metadata("l7.cc.client_ip".to_string(), client_ip.to_string());
            request.add_metadata("l7.cc.host".to_string(), host);
            request.add_metadata("l7.cc.route".to_string(), route_path);
            request.add_metadata(
                "l7.cc.request_kind".to_string(),
                verified_normal_kind.as_str().to_string(),
            );
            request.add_metadata(
                "l7.cc.action".to_string(),
                "verified_normal_pass".to_string(),
            );
            return None;
        }

        if tracking_mode.uses_page_windows() && request_kind == RequestKind::Document {
            self.record_page_load_window(
                client_ip,
                &host,
                &route_path,
                unix_now,
                &config,
                page_window_limit,
            );
        }
        let is_page_subresource = tracking_mode.uses_page_windows()
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
        let hot_path_client_count = if tracking_mode.uses_distinct_hot_path_clients(request_kind) {
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
        ) = if tracking_mode.uses_weighted_buckets() {
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
        request.add_metadata(
            "l7.cc.tracking_mode".to_string(),
            tracking_mode.as_str().to_string(),
        );
        request.add_metadata(
            "l7.cc.known_bot_threshold_multiplier".to_string(),
            known_bot_threshold_multiplier.to_string(),
        );
        request.add_metadata(
            "l7.cc.bot_threshold_scale_percent".to_string(),
            bot_threshold_scale_percent.to_string(),
        );

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
        let bot_scaled = |value: u32| value.saturating_mul(bot_threshold_scale_percent) / 100;

        let route_block_threshold = bot_scaled(
            config
                .route_block_threshold
                .saturating_mul(block_multiplier)
                .saturating_mul(known_bot_threshold_multiplier)
                .saturating_mul(route_scale_percent)
                / 100,
        );
        let host_block_threshold = bot_scaled(
            config
                .host_block_threshold
                .saturating_mul(block_multiplier)
                .saturating_mul(known_bot_threshold_multiplier)
                .saturating_mul(interactive_host_ip_block_multiplier),
        );
        let host_block_threshold = host_block_threshold.saturating_mul(host_scale_percent) / 100;
        let ip_block_threshold = bot_scaled(
            config
                .ip_block_threshold
                .saturating_mul(block_multiplier)
                .saturating_mul(known_bot_threshold_multiplier)
                .saturating_mul(interactive_host_ip_block_multiplier),
        );
        let hot_path_block_threshold = bot_scaled(
            config
                .hot_path_block_threshold
                .saturating_mul(block_multiplier)
                .saturating_mul(known_bot_threshold_multiplier),
        );

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
        let route_specific_static_hard_block =
            request_kind == RequestKind::StaticAsset && route_count >= hard_route_block_threshold;
        let static_asset_persist_block =
            request_kind == RequestKind::StaticAsset && route_specific_static_hard_block;

        if !client_identity_unresolved
            && ((hard_block
                && (request_kind != RequestKind::StaticAsset || static_asset_persist_block))
                || global_hot_path_pressure_block
                || (!low_risk_subresource
                    && (request_kind != RequestKind::StaticAsset || static_asset_persist_block)
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

        let route_challenge_threshold = bot_scaled(
            config
                .route_challenge_threshold
                .saturating_mul(challenge_multiplier)
                .saturating_mul(known_bot_threshold_multiplier)
                .saturating_mul(route_scale_percent)
                / 100,
        );
        let host_challenge_threshold = bot_scaled(
            config
                .host_challenge_threshold
                .saturating_mul(challenge_multiplier)
                .saturating_mul(known_bot_threshold_multiplier)
                .saturating_mul(interactive_host_ip_multiplier)
                .saturating_mul(host_scale_percent)
                / 100,
        );
        let ip_challenge_threshold = bot_scaled(
            config
                .ip_challenge_threshold
                .saturating_mul(challenge_multiplier)
                .saturating_mul(known_bot_threshold_multiplier)
                .saturating_mul(interactive_host_ip_multiplier),
        );
        let hot_path_challenge_threshold = bot_scaled(
            config
                .hot_path_challenge_threshold
                .saturating_mul(challenge_multiplier)
                .saturating_mul(known_bot_threshold_multiplier),
        );
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

        if !reduce_friction && !verified && !low_risk_subresource && challenge_needed {
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
        if !reduce_friction
            && config.delay_ms > 0
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
}

fn runtime_defense_depth(request: &UnifiedHttpRequest) -> crate::core::DefenseDepth {
    request
        .get_metadata("runtime.defense.depth")
        .map(|value| crate::core::DefenseDepth::from_str(value))
        .unwrap_or(crate::core::DefenseDepth::Balanced)
}

impl L7CcGuard {
    async fn inspect_survival_fast(
        &self,
        request: &mut UnifiedHttpRequest,
        config: &crate::config::l7::CcDefenseConfig,
    ) -> SurvivalFastPathResult {
        let Some(client_ip) = request_client_ip(request) else {
            request.add_metadata(
                "l7.cc.fast_path_no_decision".to_string(),
                "identity".to_string(),
            );
            return SurvivalFastPathResult::NoDecision;
        };
        let raw_path = request_path(&request.uri).to_string();
        if BYPASS_PATHS.contains(&raw_path.as_str()) {
            request.add_metadata(
                "l7.cc.fast_path_no_decision".to_string(),
                "bypass_path".to_string(),
            );
            return SurvivalFastPathResult::NoDecision;
        }

        let unix_now = unix_timestamp();
        let host = normalized_host(request);
        let route_path = normalized_route_path(&raw_path);
        let client_ip_key = client_ip.to_string();
        let ip_route_hot_key = format!("iproute:{}|{}|{}", client_ip_key, host, route_path);
        let hot_cache_base_ttl = survival_hot_cache_base_ttl(config);
        let survival_low_risk_identity =
            is_survival_low_risk_identity_request(request, &route_path);

        request.add_metadata("l7.cc.fast_path".to_string(), "true".to_string());
        request.add_metadata(
            "l7.cc.tracking_mode".to_string(),
            "survival_fast".to_string(),
        );

        let mut hot_cache_expired = false;
        if let Some(active) =
            self.hot_block_cache_hit_and_extend(&ip_route_hot_key, unix_now, hot_cache_base_ttl)
        {
            if active {
                request.add_metadata("l7.cc.hot_cache_hit".to_string(), "true".to_string());
                request.add_metadata("l7.cc.action".to_string(), "block".to_string());
                request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
                request.add_metadata("l7.drop_reason".to_string(), "cc_hot_block".to_string());
                request.add_metadata("l4.force_close".to_string(), "true".to_string());
                return SurvivalFastPathResult::Block(InspectionResult::drop(
                    InspectionLayer::L7,
                    "l7 cc fast path hot block".to_string(),
                ));
            }
            hot_cache_expired = true;
        }
        let ip_hot_key = format!("ip:{}", client_ip_key);
        if let Some(active) =
            self.hot_block_cache_hit_and_extend(&ip_hot_key, unix_now, hot_cache_base_ttl)
        {
            if active {
                request.add_metadata("l7.cc.hot_cache_hit".to_string(), "true".to_string());
                request.add_metadata("l7.cc.action".to_string(), "block".to_string());
                request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
                request.add_metadata("l7.drop_reason".to_string(), "cc_hot_block".to_string());
                request.add_metadata("l4.force_close".to_string(), "true".to_string());
                return SurvivalFastPathResult::Block(InspectionResult::drop(
                    InspectionLayer::L7,
                    "l7 cc fast path hot block".to_string(),
                ));
            }
            hot_cache_expired = true;
        }
        let route_hot_key = format!("route:{}|{}", host, route_path);
        let site_hot_key = format!("site:{}", host);
        if survival_low_risk_identity {
            request.add_metadata(
                "l7.cc.survival_bypass".to_string(),
                "low_risk_identity".to_string(),
            );
            request.add_metadata(
                "l7.cc.survival_verified_normal".to_string(),
                "true".to_string(),
            );
        } else {
            if let Some(active) =
                self.hot_block_cache_hit_and_extend(&route_hot_key, unix_now, hot_cache_base_ttl)
            {
                if active {
                    request.add_metadata("l7.cc.hot_cache_hit".to_string(), "true".to_string());
                    request.add_metadata("l7.cc.action".to_string(), "block".to_string());
                    request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
                    request.add_metadata("l7.drop_reason".to_string(), "cc_hot_block".to_string());
                    request.add_metadata("l4.force_close".to_string(), "true".to_string());
                    return SurvivalFastPathResult::Block(InspectionResult::drop(
                        InspectionLayer::L7,
                        "l7 cc fast path hot block".to_string(),
                    ));
                }
                hot_cache_expired = true;
            }
            if let Some(active) =
                self.hot_block_cache_hit_and_extend(&site_hot_key, unix_now, hot_cache_base_ttl)
            {
                if active {
                    request.add_metadata("l7.cc.hot_cache_hit".to_string(), "true".to_string());
                    request.add_metadata("l7.cc.action".to_string(), "block".to_string());
                    request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
                    request.add_metadata("l7.drop_reason".to_string(), "cc_hot_block".to_string());
                    request.add_metadata("l4.force_close".to_string(), "true".to_string());
                    return SurvivalFastPathResult::Block(InspectionResult::drop(
                        InspectionLayer::L7,
                        "l7 cc fast path hot block".to_string(),
                    ));
                }
                hot_cache_expired = true;
            }
        }
        if hot_cache_expired {
            request.add_metadata("l7.cc.hot_cache_expired".to_string(), "true".to_string());
        } else {
            request.add_metadata("l7.cc.hot_cache_miss".to_string(), "true".to_string());
        }

        request.add_metadata("l7.cc.client_ip".to_string(), client_ip_key.clone());
        request.add_metadata("l7.cc.host".to_string(), host.clone());
        request.add_metadata("l7.cc.route".to_string(), route_path.clone());
        request.add_metadata(
            "l7.cc.request_kind".to_string(),
            fast_request_kind(request, &route_path).as_str().to_string(),
        );

        let bucket_limit = runtime_usize_metadata(
            request,
            "runtime.budget.l7_bucket_limit",
            MAX_COUNTER_BUCKETS,
        )
        .clamp(512, MAX_COUNTER_BUCKETS);
        let window_secs = config.request_window_secs.max(1);
        let route_key = format!("{}|{}|{}", client_ip_key, host, route_path);
        let hot_path_key = format!("{}|{}", host, route_path);
        let ip_count = self
            .observe_fast(
                &self.fast_ip_buckets,
                client_ip_key.clone(),
                unix_now,
                window_secs,
                bucket_limit,
            )
            .count;
        let route_count = self
            .observe_fast(
                &self.fast_route_buckets,
                route_key,
                unix_now,
                window_secs,
                bucket_limit,
            )
            .count;
        let hot_path_count = self
            .observe_fast(
                &self.fast_hot_path_buckets,
                hot_path_key,
                unix_now,
                window_secs,
                bucket_limit,
            )
            .count;

        request.add_metadata("l7.cc.ip_count".to_string(), ip_count.to_string());
        request.add_metadata("l7.cc.route_count".to_string(), route_count.to_string());
        request.add_metadata(
            "l7.cc.hot_path_count".to_string(),
            hot_path_count.to_string(),
        );

        if survival_low_risk_identity {
            request.add_metadata(
                "l7.cc.fast_path_no_decision".to_string(),
                "low_risk_identity".to_string(),
            );
            return SurvivalFastPathResult::NoDecision;
        }

        self.maybe_cleanup(unix_now, config);

        let route_scale_percent = request
            .get_metadata("ai.cc.route_threshold_scale_percent")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(100)
            .clamp(10, 100);
        let ip_block_threshold = config.ip_block_threshold.max(1);
        let route_block_threshold = config
            .route_block_threshold
            .saturating_mul(route_scale_percent)
            .saturating_div(100)
            .max(1);
        let route_challenge_threshold = config
            .route_challenge_threshold
            .saturating_mul(route_scale_percent)
            .saturating_div(100)
            .max(1);
        let hard_ip_threshold =
            ip_block_threshold.saturating_mul(u32::from(config.hard_ip_block_multiplier));
        let hard_route_threshold =
            route_block_threshold.saturating_mul(u32::from(config.hard_route_block_multiplier));
        let prefer_drop = request
            .get_metadata("runtime.prefer_drop")
            .map(|value| value == "true")
            .unwrap_or(false);
        let hot_path_challenge_threshold = config
            .hot_path_challenge_threshold
            .max(route_challenge_threshold);
        let survival_hot_path_threshold = hot_path_challenge_threshold
            .min(route_challenge_threshold.saturating_mul(2).max(24))
            .max(1);
        let hot_path_block_threshold = if prefer_drop {
            survival_hot_path_threshold
        } else {
            config.hot_path_block_threshold.max(route_block_threshold)
        };
        let hard_hot_path_threshold = hot_path_block_threshold
            .saturating_mul(u32::from(config.hard_hot_path_block_multiplier));

        if ip_count >= hard_ip_threshold
            || route_count >= hard_route_threshold
            || hot_path_count >= hard_hot_path_threshold
            || ip_count >= ip_block_threshold
            || route_count >= route_block_threshold
            || hot_path_count >= hot_path_block_threshold
        {
            let ttl = hot_cache_base_ttl;
            self.insert_hot_block_cache(ip_route_hot_key, unix_now, ttl);
            self.insert_hot_block_cache(ip_hot_key, unix_now, ttl.min(180));
            if hot_path_count >= hot_path_block_threshold {
                self.insert_hot_block_cache(route_hot_key, unix_now, ttl.min(90));
            }
            if hot_path_count >= hard_hot_path_threshold {
                self.insert_hot_block_cache(site_hot_key, unix_now, ttl.min(30));
            }
            request.add_metadata("l7.cc.action".to_string(), "block".to_string());
            request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
            request.add_metadata("l7.drop_reason".to_string(), "cc_fast_block".to_string());
            request.add_metadata("l4.force_close".to_string(), "true".to_string());
            return SurvivalFastPathResult::Block(InspectionResult::drop_and_persist_ip(
                InspectionLayer::L7,
                format!(
                    "l7 cc fast path blocked request: ip={} route={} ip_count={} route_count={} hot_path_count={}",
                    client_ip, route_path, ip_count, route_count, hot_path_count
                ),
            ));
        }

        let hot_path_challenge_threshold =
            hot_path_challenge_threshold.min(survival_hot_path_threshold);
        let challenge_needed = route_count >= route_challenge_threshold
            || hot_path_count >= hot_path_challenge_threshold
            || ip_count >= config.ip_challenge_threshold;
        if challenge_needed {
            let verified = self.has_valid_challenge_cookie(request, client_ip, &host, config);
            request.add_metadata("l7.cc.challenge_verified".to_string(), verified.to_string());
            if !verified {
                let html_mode = challenge_mode(request, &route_path);
                let action = challenge_action_name(html_mode);
                let reason = format!(
                    "l7 cc fast path {}: ip={} route={} ip_count={} route_count={} hot_path_count={}",
                    challenge_reason_verb(html_mode),
                    client_ip,
                    route_path,
                    ip_count,
                    route_count,
                    hot_path_count
                );
                request.add_metadata("l7.cc.action".to_string(), action.to_string());
                return SurvivalFastPathResult::Challenge(InspectionResult::respond(
                    InspectionLayer::L7,
                    reason.clone(),
                    self.build_challenge_response(
                        request, client_ip, &host, &reason, html_mode, config,
                    ),
                ));
            }
        }

        request.add_metadata(
            "l7.cc.fast_path_no_decision".to_string(),
            "below_threshold".to_string(),
        );
        SurvivalFastPathResult::NoDecision
    }
}

fn survival_hot_cache_base_ttl(config: &crate::config::l7::CcDefenseConfig) -> u64 {
    config
        .challenge_ttl_secs
        .max(config.request_window_secs.saturating_mul(4))
        .clamp(3, 900)
}

fn fast_request_kind(request: &UnifiedHttpRequest, route_path: &str) -> RequestKind {
    let method = request.method.as_str();
    if !method.eq_ignore_ascii_case("GET") && !method.eq_ignore_ascii_case("HEAD") {
        return RequestKind::ApiLike;
    }
    if route_path.starts_with("/api/") {
        return RequestKind::ApiLike;
    }
    if looks_like_static_asset(route_path) {
        return RequestKind::StaticAsset;
    }
    if route_path == "/" || route_path.ends_with(".html") || route_path.ends_with(".htm") {
        return RequestKind::Document;
    }
    RequestKind::Other
}

fn runtime_tracking_mode(
    request: &UnifiedHttpRequest,
    defense_depth: crate::core::DefenseDepth,
) -> CcTrackingMode {
    if request
        .get_metadata("early_defense.action")
        .map(String::as_str)
        == Some("lightweight_l7")
    {
        return CcTrackingMode::Core;
    }

    let cpu_score = request
        .get_metadata("runtime.pressure.cpu_score")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0);

    match defense_depth {
        crate::core::DefenseDepth::Full | crate::core::DefenseDepth::Balanced => {
            if cpu_score >= 3 {
                CcTrackingMode::Core
            } else {
                CcTrackingMode::Rich
            }
        }
        crate::core::DefenseDepth::Lean => CcTrackingMode::Core,
        crate::core::DefenseDepth::Survival => CcTrackingMode::Minimal,
    }
}

fn runtime_usize_metadata(request: &UnifiedHttpRequest, key: &str, default: usize) -> usize {
    request
        .get_metadata(key)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}
