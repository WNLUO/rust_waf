use crate::core::{InspectionLayer, InspectionResult};
use crate::protocol::UnifiedHttpRequest;
use dashmap::DashMap;
use std::collections::{HashSet, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

mod assessment;
mod request_utils;
mod response;
mod types;

use assessment::assess_samples;
use request_utils::{
    bounded_dashmap_key, compact_component, normalized_route_path, request_identity, request_kind,
    request_path, route_family, should_drop_delay_under_pressure, unix_timestamp,
};
use response::build_behavior_response;
use types::{BehaviorAssessment, BehaviorWindow, RequestKind, RequestSample};

pub use types::BehaviorProfileSnapshot;

const BEHAVIOR_WINDOW_SECS: u64 = 300;
const ACTIVE_PROFILE_IDLE_SECS: i64 = 60;
const MAX_SAMPLES_PER_IDENTITY: usize = 96;
const CLEANUP_EVERY_REQUESTS: u64 = 512;
const CHALLENGE_SCORE: u32 = 60;
const BLOCK_SCORE: u32 = 90;
const DELAY_SCORE: u32 = 35;
const DELAY_MS: u64 = 250;
pub const AUTO_BLOCK_DURATION_SECS: u64 = 15 * 60;
const CHALLENGES_BEFORE_AUTO_BLOCK: usize = 2;
const MAX_BEHAVIOR_BUCKETS: usize = 32_768;
const MAX_BEHAVIOR_KEY_LEN: usize = 160;
const MAX_BEHAVIOR_ROUTE_LEN: usize = 160;
const OVERFLOW_SHARDS: u64 = 64;
const AGGREGATE_CHALLENGE_ENFORCEMENT_SECS: u64 = 30;
const AGGREGATE_BLOCK_ENFORCEMENT_SECS: u64 = 90;
const ROUTE_BURST_WINDOW_SECS: u64 = 3;
const ROUTE_BURST_CHALLENGE_TOTAL: usize = 6;
const ROUTE_BURST_CHALLENGE_DISTINCT_IPS: usize = 4;
const ROUTE_BURST_BLOCK_TOTAL: usize = 10;
const ROUTE_BURST_BLOCK_DISTINCT_IPS: usize = 8;
const MAX_BURST_SAMPLES_PER_ROUTE: usize = 64;

#[derive(Debug)]
pub struct L7BehaviorGuard {
    buckets: DashMap<String, BehaviorWindow>,
    aggregate_buckets: DashMap<String, BehaviorWindow>,
    aggregate_enforcements: DashMap<String, AggregateEnforcement>,
    route_burst_buckets: DashMap<String, RouteBurstWindow>,
    request_sequence: AtomicU64,
}

impl L7BehaviorGuard {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
            aggregate_buckets: DashMap::new(),
            aggregate_enforcements: DashMap::new(),
            route_burst_buckets: DashMap::new(),
            request_sequence: AtomicU64::new(0),
        }
    }

    pub async fn inspect_request(
        &self,
        request: &mut UnifiedHttpRequest,
    ) -> Option<InspectionResult> {
        if request
            .get_metadata("network.server_public_ip_exempt")
            .map(|value| value == "true")
            .unwrap_or(false)
        {
            request.add_metadata(
                "l7.behavior.skipped".to_string(),
                "server_public_ip".to_string(),
            );
            return None;
        }
        if request_utils::has_valid_behavior_clearance(request) {
            request.add_metadata(
                "l7.behavior.skipped".to_string(),
                "behavior_clearance".to_string(),
            );
            return None;
        }
        if request
            .get_metadata("ai.visitor.reduce_friction")
            .is_some_and(|value| value == "true")
        {
            request.add_metadata(
                "l7.behavior.skipped".to_string(),
                "visitor_reduce_friction".to_string(),
            );
            return None;
        }
        if matches!(
            request
                .get_metadata("client.trust_class")
                .map(String::as_str),
            Some("internal" | "verified_good_bot")
        ) {
            request.add_metadata(
                "l7.behavior.skipped".to_string(),
                request
                    .get_metadata("client.trust_class")
                    .map(|value| format!("client_trust:{value}"))
                    .unwrap_or_else(|| "client_trust".to_string()),
            );
            return None;
        }
        let defense_depth = runtime_defense_depth(request);
        if defense_depth == crate::core::DefenseDepth::Survival {
            request.add_metadata(
                "l7.behavior.skipped".to_string(),
                "resource_survival".to_string(),
            );
            return None;
        }
        let sample_stride =
            runtime_u64_metadata(request, "runtime.budget.behavior_sample_stride", 1);
        if sample_stride > 1 {
            let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed) + 1;
            if !sequence.is_multiple_of(sample_stride) {
                request.add_metadata(
                    "l7.behavior.skipped".to_string(),
                    "resource_sampling".to_string(),
                );
                return None;
            }
        }
        let bucket_limit = runtime_usize_metadata(
            request,
            "runtime.budget.behavior_bucket_limit",
            MAX_BEHAVIOR_BUCKETS,
        )
        .clamp(512, MAX_BEHAVIOR_BUCKETS);
        let route = request
            .get_metadata("l7.cc.route")
            .cloned()
            .unwrap_or_else(|| normalized_route_path(request_path(&request.uri)));
        let kind = request_kind(request);
        let client_ip = request
            .client_ip
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let user_agent = behavior_user_agent(request);
        let header_signature = behavior_header_signature(request);
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let window = Duration::from_secs(BEHAVIOR_WINDOW_SECS);
        let aggregate_keys = behavior_aggregate_keys(request, &route, kind);
        let active_aggregate_enforcement = self.active_aggregate_enforcement(&aggregate_keys, now);
        if active_aggregate_enforcement
            .as_ref()
            .is_some_and(|enforcement| {
                matches!(enforcement.action, AggregateEnforcementAction::Block)
            })
        {
            let enforcement = active_aggregate_enforcement.expect("checked above");
            request.add_metadata(
                "l7.behavior.identity".to_string(),
                enforcement.identity.clone(),
            );
            request.add_metadata(
                "l7.behavior.score".to_string(),
                enforcement.score.to_string(),
            );
            request.add_metadata(
                "l7.behavior.action".to_string(),
                enforcement.action.as_str().to_string(),
            );
            request.add_metadata(
                "l7.behavior.aggregate_enforcement".to_string(),
                "active".to_string(),
            );
            request.add_metadata("l7.behavior.flags".to_string(), enforcement.flags.join(","));
            let reason = format!(
                "l7 behavior guard aggregate enforcement: identity={} score={} flags={}",
                enforcement.identity,
                enforcement.score,
                enforcement.flags.join("|"),
            );
            request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
            request.add_metadata(
                "l7.drop_reason".to_string(),
                "behavior_aggregate_enforcement".to_string(),
            );
            request.add_metadata("l4.force_close".to_string(), "true".to_string());
            return Some(InspectionResult::drop(InspectionLayer::L7, reason));
        }
        if let Some(result) = self.inspect_route_burst(
            request,
            &route,
            kind,
            client_ip.clone(),
            user_agent.clone(),
            header_signature.clone(),
            now,
            unix_now,
            bucket_limit,
        ) {
            return Some(result);
        }
        let identity_assessment = request_identity(request).map(|identity| {
            self.observe_and_assess(
                &identity,
                route.clone(),
                kind,
                client_ip.clone(),
                user_agent.clone(),
                header_signature.clone(),
                now,
                unix_now,
                window,
                bucket_limit,
            )
        });
        let aggregate_assessment = aggregate_keys
            .into_iter()
            .map(|(key, aggregate_route)| {
                self.observe_aggregate_and_assess(
                    &key,
                    aggregate_route,
                    kind,
                    client_ip.clone(),
                    user_agent.clone(),
                    header_signature.clone(),
                    now,
                    unix_now,
                    window,
                    bucket_limit,
                )
            })
            .max_by_key(|assessment| assessment.score);
        let Some(mut assessment) =
            select_behavior_assessment(identity_assessment, aggregate_assessment)
        else {
            if let Some(enforcement) = active_aggregate_enforcement {
                return Some(self.respond_to_aggregate_challenge(request, enforcement));
            }
            return None;
        };
        let ai_score_boost = request
            .get_metadata("ai.behavior.score_boost")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(0);
        let ai_force_watch = request
            .get_metadata("ai.behavior.force_watch")
            .map(|value| value == "true")
            .unwrap_or(false);
        if ai_score_boost > 0 {
            assessment.score = assessment.score.saturating_add(ai_score_boost).min(100);
            assessment.flags.push("ai_temp_risk");
        }
        if ai_force_watch && assessment.score < DELAY_SCORE {
            assessment.score = DELAY_SCORE;
            assessment.flags.push("ai_temp_watch");
        }
        let client_trust_class = request
            .get_metadata("client.trust_class")
            .map(String::as_str);
        if client_trust_class == Some("claimed_good_bot") {
            let reduction = if request.get_metadata("bot.policy").map(String::as_str)
                == Some("reduce_friction")
            {
                30
            } else {
                15
            };
            assessment.score = assessment.score.saturating_sub(reduction);
            assessment.flags.push("known_crawler_library");
        }
        if client_trust_class == Some("suspect_bot") {
            assessment.score = assessment.score.saturating_add(20).min(100);
            assessment.flags.push("crawler_ua_ip_mismatch");
        }

        request.add_metadata(
            "l7.behavior.identity".to_string(),
            assessment.identity.clone(),
        );
        request.add_metadata(
            "l7.behavior.score".to_string(),
            assessment.score.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_routes".to_string(),
            assessment.distinct_routes.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_client_ips".to_string(),
            assessment.distinct_client_ips.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_user_agents".to_string(),
            assessment.distinct_user_agents.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_header_signatures".to_string(),
            assessment.distinct_header_signatures.to_string(),
        );
        request.add_metadata(
            "l7.behavior.repeated_ratio".to_string(),
            assessment.repeated_ratio_percent.to_string(),
        );
        request.add_metadata(
            "l7.behavior.client_ip_repeated_ratio".to_string(),
            assessment.client_ip_repeated_ratio_percent.to_string(),
        );
        request.add_metadata(
            "l7.behavior.document_repeated_ratio".to_string(),
            assessment.document_repeated_ratio_percent.to_string(),
        );
        request.add_metadata(
            "l7.behavior.document_requests".to_string(),
            assessment.document_requests.to_string(),
        );
        request.add_metadata(
            "l7.behavior.api_requests".to_string(),
            assessment.api_requests.to_string(),
        );
        request.add_metadata(
            "l7.behavior.non_document_requests".to_string(),
            assessment.non_document_requests.to_string(),
        );
        request.add_metadata(
            "l7.behavior.api_repeated_ratio".to_string(),
            assessment.api_repeated_ratio_percent.to_string(),
        );
        request.add_metadata(
            "l7.behavior.challenge_count_window".to_string(),
            assessment.recent_challenges.to_string(),
        );
        request.add_metadata(
            "l7.behavior.session_span_secs".to_string(),
            assessment.session_span_secs.to_string(),
        );
        if !assessment.flags.is_empty() {
            request.add_metadata("l7.behavior.flags".to_string(), assessment.flags.join(","));
        }
        if let Some(route) = assessment.dominant_route.as_ref() {
            request.add_metadata("l7.behavior.dominant_route".to_string(), route.clone());
        }
        if let Some(route) = assessment.focused_document_route.as_ref() {
            request.add_metadata(
                "l7.behavior.focused_document_route".to_string(),
                route.clone(),
            );
        }
        if let Some(route) = assessment.focused_api_route.as_ref() {
            request.add_metadata("l7.behavior.focused_api_route".to_string(), route.clone());
        }
        if let Some(jitter_ms) = assessment.jitter_ms {
            request.add_metadata(
                "l7.behavior.interval_jitter_ms".to_string(),
                jitter_ms.to_string(),
            );
        }

        self.maybe_cleanup(unix_now);

        let should_auto_block = assessment.score >= BLOCK_SCORE
            || (assessment.score >= CHALLENGE_SCORE
                && assessment.recent_challenges >= CHALLENGES_BEFORE_AUTO_BLOCK);

        if should_auto_block {
            self.activate_aggregate_enforcement(
                &assessment,
                AggregateEnforcementAction::Block,
                now,
            );
            self.record_block(&assessment.identity, now, window);
            request.add_metadata("l7.behavior.action".to_string(), "block".to_string());
            request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
            request.add_metadata(
                "l7.drop_reason".to_string(),
                "behavior_auto_block".to_string(),
            );
            request.add_metadata("l4.force_close".to_string(), "true".to_string());
            let reason = format!(
                "l7 behavior guard blocked suspicious session: score={} repeated_ratio={} document_repeated_ratio={} distinct_routes={} dominant_route={} recent_challenges={} flags={}",
                assessment.score,
                assessment.repeated_ratio_percent,
                assessment.document_repeated_ratio_percent,
                assessment.distinct_routes,
                assessment.dominant_route.as_deref().unwrap_or("*"),
                assessment.recent_challenges,
                assessment.flags.join("|"),
            );
            return Some(InspectionResult::drop_and_persist_ip(
                InspectionLayer::L7,
                reason,
            ));
        }

        if assessment.score >= CHALLENGE_SCORE {
            self.activate_aggregate_enforcement(
                &assessment,
                AggregateEnforcementAction::Challenge,
                now,
            );
            self.record_challenge(&assessment.identity, now, window);
            request.add_metadata("l7.behavior.action".to_string(), "challenge".to_string());
            let reason = format!(
                "l7 behavior guard challenged suspicious session: score={} repeated_ratio={} document_repeated_ratio={} distinct_routes={} dominant_route={} recent_challenges={} flags={}",
                assessment.score,
                assessment.repeated_ratio_percent,
                assessment.document_repeated_ratio_percent,
                assessment.distinct_routes,
                assessment.dominant_route.as_deref().unwrap_or("*"),
                assessment.recent_challenges,
                assessment.flags.join("|"),
            );
            return Some(InspectionResult::respond(
                InspectionLayer::L7,
                reason.clone(),
                build_behavior_response(request, 429, "访问行为异常，请稍后再试", &reason),
            ));
        }

        if let Some(enforcement) = active_aggregate_enforcement {
            return Some(self.respond_to_aggregate_challenge(request, enforcement));
        }

        if assessment.score >= DELAY_SCORE {
            if should_drop_delay_under_pressure(request) {
                self.record_challenge(&assessment.identity, now, window);
                request.add_metadata("l7.behavior.action".to_string(), "challenge".to_string());
                let reason = format!(
                    "l7 behavior guard upgraded delay to challenge under runtime pressure: score={} repeated_ratio={} document_repeated_ratio={} distinct_routes={} dominant_route={} flags={}",
                    assessment.score,
                    assessment.repeated_ratio_percent,
                    assessment.document_repeated_ratio_percent,
                    assessment.distinct_routes,
                    assessment.dominant_route.as_deref().unwrap_or("*"),
                    assessment.flags.join("|"),
                );
                return Some(InspectionResult::respond(
                    InspectionLayer::L7,
                    reason.clone(),
                    build_behavior_response(request, 429, "系统繁忙，请稍后重试", &reason),
                ));
            }
            request.add_metadata(
                "l7.behavior.action".to_string(),
                format!("delay:{DELAY_MS}ms"),
            );
            tokio::time::sleep(Duration::from_millis(DELAY_MS)).await;
        }

        None
    }

    fn respond_to_aggregate_challenge(
        &self,
        request: &mut UnifiedHttpRequest,
        enforcement: AggregateEnforcement,
    ) -> InspectionResult {
        request.add_metadata(
            "l7.behavior.identity".to_string(),
            enforcement.identity.clone(),
        );
        request.add_metadata(
            "l7.behavior.score".to_string(),
            enforcement.score.to_string(),
        );
        request.add_metadata(
            "l7.behavior.action".to_string(),
            enforcement.action.as_str().to_string(),
        );
        request.add_metadata(
            "l7.behavior.aggregate_enforcement".to_string(),
            "active".to_string(),
        );
        request.add_metadata("l7.behavior.flags".to_string(), enforcement.flags.join(","));
        let reason = format!(
            "l7 behavior guard aggregate enforcement: identity={} score={} flags={}",
            enforcement.identity,
            enforcement.score,
            enforcement.flags.join("|"),
        );
        InspectionResult::respond(
            InspectionLayer::L7,
            reason.clone(),
            build_behavior_response(request, 429, "访问行为异常，请稍后再试", &reason),
        )
    }

    fn observe_and_assess(
        &self,
        identity: &str,
        route: String,
        kind: RequestKind,
        client_ip: Option<String>,
        user_agent: Option<String>,
        header_signature: Option<String>,
        now: Instant,
        unix_now: i64,
        window: Duration,
        bucket_limit: usize,
    ) -> BehaviorAssessment {
        let identity = bounded_dashmap_key(
            &self.buckets,
            compact_component("identity", &identity, MAX_BEHAVIOR_KEY_LEN),
            bucket_limit,
            "behavior",
            OVERFLOW_SHARDS,
        );
        let mut entry = self
            .buckets
            .entry(identity.clone())
            .or_insert_with(BehaviorWindow::new);
        entry.observe_and_assess(
            identity,
            route,
            kind,
            client_ip,
            user_agent,
            header_signature,
            now,
            unix_now,
            window,
        )
    }

    fn observe_aggregate_and_assess(
        &self,
        identity: &str,
        route: String,
        kind: RequestKind,
        client_ip: Option<String>,
        user_agent: Option<String>,
        header_signature: Option<String>,
        now: Instant,
        unix_now: i64,
        window: Duration,
        bucket_limit: usize,
    ) -> BehaviorAssessment {
        let identity = bounded_dashmap_key(
            &self.aggregate_buckets,
            compact_component("aggregate", identity, MAX_BEHAVIOR_KEY_LEN),
            bucket_limit,
            "behavior-aggregate",
            OVERFLOW_SHARDS,
        );
        let mut entry = self
            .aggregate_buckets
            .entry(identity.clone())
            .or_insert_with(BehaviorWindow::new);
        entry.observe_and_assess(
            identity,
            route,
            kind,
            client_ip,
            user_agent,
            header_signature,
            now,
            unix_now,
            window,
        )
    }

    fn maybe_cleanup(&self, unix_now: i64) {
        let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        if !sequence.is_multiple_of(CLEANUP_EVERY_REQUESTS) {
            return;
        }

        let stale_before = unix_now - (BEHAVIOR_WINDOW_SECS as i64 * 3).max(180);
        let keys = self
            .buckets
            .iter()
            .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in keys {
            self.buckets.remove(&key);
        }

        let aggregate_keys = self
            .aggregate_buckets
            .iter()
            .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in aggregate_keys {
            self.aggregate_buckets.remove(&key);
        }

        let stale_burst_before = unix_now - (ROUTE_BURST_WINDOW_SECS as i64 * 6).max(30);
        let route_burst_keys = self
            .route_burst_buckets
            .iter()
            .filter(|entry| {
                entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_burst_before
            })
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in route_burst_keys {
            self.route_burst_buckets.remove(&key);
        }

        let expired_enforcements = self
            .aggregate_enforcements
            .iter()
            .filter(|entry| entry.value().expires_at <= Instant::now())
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in expired_enforcements {
            self.aggregate_enforcements.remove(&key);
        }
    }

    fn active_aggregate_enforcement(
        &self,
        aggregate_keys: &[(String, String)],
        now: Instant,
    ) -> Option<AggregateEnforcement> {
        let mut selected = None;
        for (key, _) in aggregate_keys {
            let key = aggregate_enforcement_key(key);
            let Some(entry) = self.aggregate_enforcements.get(&key) else {
                continue;
            };
            if entry.expires_at <= now {
                drop(entry);
                self.aggregate_enforcements.remove(&key);
                continue;
            }
            let enforcement = entry.clone();
            if matches!(enforcement.action, AggregateEnforcementAction::Block) {
                return Some(enforcement);
            }
            selected = Some(enforcement);
        }
        selected
    }

    fn activate_aggregate_enforcement(
        &self,
        assessment: &BehaviorAssessment,
        action: AggregateEnforcementAction,
        now: Instant,
    ) {
        if !assessment_allows_aggregate_enforcement(assessment) {
            return;
        }
        let ttl = match action {
            AggregateEnforcementAction::Challenge => AGGREGATE_CHALLENGE_ENFORCEMENT_SECS,
            AggregateEnforcementAction::Block => AGGREGATE_BLOCK_ENFORCEMENT_SECS,
        };
        self.aggregate_enforcements.insert(
            aggregate_enforcement_key(&assessment.identity),
            AggregateEnforcement {
                identity: assessment.identity.clone(),
                action,
                score: assessment.score,
                flags: assessment
                    .flags
                    .iter()
                    .map(|flag| (*flag).to_string())
                    .collect(),
                expires_at: now + Duration::from_secs(ttl),
            },
        );
    }

    fn inspect_route_burst(
        &self,
        request: &mut UnifiedHttpRequest,
        route: &str,
        kind: RequestKind,
        client_ip: Option<String>,
        user_agent: Option<String>,
        header_signature: Option<String>,
        now: Instant,
        unix_now: i64,
        bucket_limit: usize,
    ) -> Option<InspectionResult> {
        if !matches!(kind, RequestKind::Document | RequestKind::Api) || route_burst_exempt(route) {
            return None;
        }
        let keys = route_burst_keys(request, route, kind);
        if keys.is_empty() {
            return None;
        }
        let script_like = request_is_script_like_document(request);
        let mut selected = None;
        for key in keys {
            let key = bounded_dashmap_key(
                &self.route_burst_buckets,
                compact_component("route-burst", &key, MAX_BEHAVIOR_KEY_LEN),
                bucket_limit,
                "behavior-route-burst",
                OVERFLOW_SHARDS,
            );
            let mut entry = self
                .route_burst_buckets
                .entry(key.clone())
                .or_insert_with(RouteBurstWindow::new);
            let mut assessment = entry.observe_and_assess(
                RouteBurstSample {
                    client_ip: client_ip.clone(),
                    user_agent: user_agent.clone(),
                    header_signature: header_signature.clone(),
                    script_like,
                    at: now,
                },
                unix_now,
            );
            assessment.identity = key;
            if selected
                .as_ref()
                .map_or(true, |candidate: &RouteBurstAssessment| {
                    assessment.rank() > candidate.rank()
                })
            {
                selected = Some(assessment);
            }
        }
        let assessment = selected?;
        if assessment.action == RouteBurstAction::None {
            return None;
        }
        request.add_metadata(
            "l7.behavior.identity".to_string(),
            assessment.identity.clone(),
        );
        request.add_metadata(
            "l7.behavior.score".to_string(),
            assessment.score.to_string(),
        );
        request.add_metadata(
            "l7.behavior.action".to_string(),
            assessment.action.as_str().to_string(),
        );
        request.add_metadata(
            "l7.behavior.aggregate_enforcement".to_string(),
            "route_burst".to_string(),
        );
        request.add_metadata(
            "l7.behavior.flags".to_string(),
            "route_burst_gate".to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_client_ips".to_string(),
            assessment.distinct_client_ips.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_user_agents".to_string(),
            assessment.distinct_user_agents.to_string(),
        );
        request.add_metadata(
            "l7.behavior.distinct_header_signatures".to_string(),
            assessment.distinct_header_signatures.to_string(),
        );
        let reason = format!(
            "l7 behavior route burst gate: identity={} total={} distinct_client_ips={} script_like_ratio={} distinct_user_agents={} distinct_header_signatures={}",
            assessment.identity,
            assessment.total,
            assessment.distinct_client_ips,
            assessment.script_like_ratio_percent,
            assessment.distinct_user_agents,
            assessment.distinct_header_signatures,
        );
        match assessment.action {
            RouteBurstAction::Block => {
                request.add_metadata("l7.enforcement".to_string(), "drop".to_string());
                request.add_metadata(
                    "l7.drop_reason".to_string(),
                    "behavior_route_burst".to_string(),
                );
                request.add_metadata("l4.force_close".to_string(), "true".to_string());
                Some(InspectionResult::drop(InspectionLayer::L7, reason))
            }
            RouteBurstAction::Challenge => Some(InspectionResult::respond(
                InspectionLayer::L7,
                reason.clone(),
                build_behavior_response(request, 429, "访问行为异常，请稍后再试", &reason),
            )),
            RouteBurstAction::None => None,
        }
    }

    fn record_challenge(&self, identity: &str, now: Instant, window: Duration) {
        if let Some(mut entry) = self.buckets.get_mut(identity) {
            entry.record_challenge(now, window);
            return;
        }
        if let Some(mut entry) = self.aggregate_buckets.get_mut(identity) {
            entry.record_challenge(now, window);
        }
    }

    fn record_block(&self, identity: &str, now: Instant, window: Duration) {
        if let Some(mut entry) = self.buckets.get_mut(identity) {
            entry.record_block(now, window);
            return;
        }
        if let Some(mut entry) = self.aggregate_buckets.get_mut(identity) {
            entry.record_block(now, window);
        }
    }

    pub fn snapshot_profiles(&self, limit: usize) -> Vec<BehaviorProfileSnapshot> {
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let window = Duration::from_secs(BEHAVIOR_WINDOW_SECS);
        let mut profiles = self
            .buckets
            .iter()
            .filter_map(|entry| {
                let last_seen_unix = entry.value().last_seen_unix.load(Ordering::Relaxed);
                if unix_now.saturating_sub(last_seen_unix) > ACTIVE_PROFILE_IDLE_SECS {
                    return None;
                }
                entry.value().snapshot(entry.key().clone(), now, window)
            })
            .collect::<Vec<_>>();
        profiles.sort_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| right.latest_seen_unix.cmp(&left.latest_seen_unix))
        });
        if limit > 0 && profiles.len() > limit {
            profiles.truncate(limit);
        }
        profiles
    }
}

#[derive(Debug, Clone)]
struct AggregateEnforcement {
    identity: String,
    action: AggregateEnforcementAction,
    score: u32,
    flags: Vec<String>,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AggregateEnforcementAction {
    Challenge,
    Block,
}

impl AggregateEnforcementAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Challenge => "aggregate_challenge",
            Self::Block => "aggregate_block",
        }
    }
}

#[derive(Debug)]
struct RouteBurstWindow {
    samples: Mutex<VecDeque<RouteBurstSample>>,
    last_seen_unix: AtomicI64,
}

#[derive(Debug, Clone)]
struct RouteBurstSample {
    client_ip: Option<String>,
    user_agent: Option<String>,
    header_signature: Option<String>,
    script_like: bool,
    at: Instant,
}

#[derive(Debug, Clone)]
struct RouteBurstAssessment {
    identity: String,
    action: RouteBurstAction,
    score: u32,
    total: usize,
    distinct_client_ips: usize,
    distinct_user_agents: usize,
    distinct_header_signatures: usize,
    script_like_ratio_percent: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteBurstAction {
    None,
    Challenge,
    Block,
}

impl RouteBurstAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Challenge => "aggregate_challenge",
            Self::Block => "aggregate_block",
        }
    }
}

impl RouteBurstAssessment {
    fn rank(&self) -> u8 {
        match self.action {
            RouteBurstAction::Block => 2,
            RouteBurstAction::Challenge => 1,
            RouteBurstAction::None => 0,
        }
    }
}

impl RouteBurstWindow {
    fn new() -> Self {
        Self {
            samples: Mutex::new(VecDeque::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    fn observe_and_assess(
        &mut self,
        sample: RouteBurstSample,
        unix_now: i64,
    ) -> RouteBurstAssessment {
        let now = sample.at;
        let mut samples = self.samples.lock().expect("route burst lock poisoned");
        while let Some(front) = samples.front() {
            if now.duration_since(front.at) > Duration::from_secs(ROUTE_BURST_WINDOW_SECS)
                || samples.len() > MAX_BURST_SAMPLES_PER_ROUTE
            {
                samples.pop_front();
            } else {
                break;
            }
        }
        samples.push_back(sample);
        while samples.len() > MAX_BURST_SAMPLES_PER_ROUTE {
            samples.pop_front();
        }
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        assess_route_burst(&samples)
    }
}

fn assess_route_burst(samples: &VecDeque<RouteBurstSample>) -> RouteBurstAssessment {
    let total = samples.len();
    let distinct_client_ips = samples
        .iter()
        .filter_map(|sample| sample.client_ip.as_deref())
        .collect::<HashSet<_>>()
        .len();
    let distinct_user_agents = samples
        .iter()
        .filter_map(|sample| sample.user_agent.as_deref())
        .collect::<HashSet<_>>()
        .len();
    let distinct_header_signatures = samples
        .iter()
        .filter_map(|sample| sample.header_signature.as_deref())
        .collect::<HashSet<_>>()
        .len();
    let script_like_count = samples.iter().filter(|sample| sample.script_like).count();
    let script_like_ratio_percent = if total == 0 {
        0
    } else {
        ((script_like_count * 100) / total) as u32
    };
    let scripted_or_mechanical = script_like_ratio_percent >= 70
        || (distinct_header_signatures <= 2 && distinct_user_agents <= 4);
    let action = if total >= ROUTE_BURST_BLOCK_TOTAL
        && distinct_client_ips >= ROUTE_BURST_BLOCK_DISTINCT_IPS
        && scripted_or_mechanical
    {
        RouteBurstAction::Block
    } else if total >= ROUTE_BURST_CHALLENGE_TOTAL
        && distinct_client_ips >= ROUTE_BURST_CHALLENGE_DISTINCT_IPS
        && scripted_or_mechanical
    {
        RouteBurstAction::Challenge
    } else {
        RouteBurstAction::None
    };
    let score = match action {
        RouteBurstAction::Block => 100,
        RouteBurstAction::Challenge => CHALLENGE_SCORE,
        RouteBurstAction::None => 0,
    };
    RouteBurstAssessment {
        identity: "route_burst".to_string(),
        action,
        score,
        total,
        distinct_client_ips,
        distinct_user_agents,
        distinct_header_signatures,
        script_like_ratio_percent,
    }
}

fn runtime_defense_depth(request: &UnifiedHttpRequest) -> crate::core::DefenseDepth {
    request
        .get_metadata("runtime.defense.depth")
        .map(|value| crate::core::DefenseDepth::from_str(value))
        .unwrap_or(crate::core::DefenseDepth::Balanced)
}

fn behavior_aggregate_keys(
    request: &UnifiedHttpRequest,
    route: &str,
    kind: RequestKind,
) -> Vec<(String, String)> {
    if matches!(kind, RequestKind::Static) {
        return Vec::new();
    }
    let host = behavior_host(request);
    let mut keys = vec![(
        format!("site:{host}|route:{route}|kind:{}", kind.as_str()),
        route.to_string(),
    )];
    let client_ip = request
        .client_ip
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| compact_component("client", value, MAX_BEHAVIOR_KEY_LEN));
    if let Some(client_ip) = client_ip.as_ref() {
        keys.push((
            format!(
                "site:{host}|client:{client_ip}|route:{route}|kind:{}",
                kind.as_str()
            ),
            route.to_string(),
        ));
    }
    if let Some(family) = route_family(&request.uri, route) {
        keys.push((
            format!("site:{host}|family:{family}|kind:{}", kind.as_str()),
            format!("family:{family}"),
        ));
        if let Some(client_ip) = client_ip.as_ref() {
            keys.push((
                format!(
                    "site:{host}|client:{client_ip}|family:{family}|kind:{}",
                    kind.as_str()
                ),
                format!("family:{family}"),
            ));
        }
    }
    keys
}

fn route_burst_keys(request: &UnifiedHttpRequest, route: &str, kind: RequestKind) -> Vec<String> {
    let host = behavior_host(request);
    let mut keys = vec![format!(
        "site:{host}|route:{route}|kind:{}|burst",
        kind.as_str()
    )];
    if let Some(family) = route_family(&request.uri, route) {
        keys.push(format!(
            "site:{host}|family:{family}|kind:{}|burst",
            kind.as_str()
        ));
    }
    keys
}

fn route_burst_exempt(route: &str) -> bool {
    let route = route.to_ascii_lowercase();
    route == "/robots.txt"
        || route == "/sitemap.xml"
        || route.starts_with("/sitemap")
        || route == "/favicon.ico"
        || route.starts_with("/.well-known/")
}

fn behavior_user_agent(request: &UnifiedHttpRequest) -> Option<String> {
    request
        .get_header("user-agent")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| compact_component("ua", value, MAX_BEHAVIOR_KEY_LEN))
}

fn behavior_host(request: &UnifiedHttpRequest) -> String {
    let raw = request
        .get_header("host")
        .or_else(|| request.get_metadata("authority"))
        .map(String::as_str)
        .unwrap_or("-")
        .trim();
    if raw.is_empty() {
        return "-".to_string();
    }
    if let Ok(uri) = format!("http://{raw}").parse::<http::Uri>() {
        if let Some(authority) = uri.authority() {
            return compact_component(
                "host",
                &authority.host().to_ascii_lowercase(),
                MAX_BEHAVIOR_KEY_LEN,
            );
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
    compact_component("host", &normalized, MAX_BEHAVIOR_KEY_LEN)
}

fn request_is_script_like_document(request: &UnifiedHttpRequest) -> bool {
    let ua = request
        .get_header("user-agent")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let accept = request
        .get_header("accept")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_default();
    let accept_language_missing = request
        .get_header("accept-language")
        .map(|value| value.trim().is_empty())
        .unwrap_or(true);
    let sec_fetch_dest = request
        .get_header("sec-fetch-dest")
        .map(|value| value.to_ascii_lowercase());
    let sec_fetch_mode = request
        .get_header("sec-fetch-mode")
        .map(|value| value.to_ascii_lowercase());
    let browser_navigation = sec_fetch_dest.as_deref() == Some("document")
        || sec_fetch_mode.as_deref() == Some("navigate");
    let automation_ua = [
        "curl",
        "wget",
        "python",
        "go-http-client",
        "okhttp",
        "httpclient",
        "postman",
        "http_request",
    ]
    .iter()
    .any(|needle| ua.contains(needle));
    automation_ua
        || (!browser_navigation
            && (accept.is_empty() || accept == "*/*" || !accept.contains("text/html")))
        || (!browser_navigation && accept_language_missing && !accept.contains("text/html"))
}

fn behavior_header_signature(request: &UnifiedHttpRequest) -> Option<String> {
    let fields = [
        "accept",
        "accept-language",
        "accept-encoding",
        "sec-fetch-dest",
        "sec-fetch-mode",
        "sec-fetch-site",
        "x-requested-with",
    ];
    let signature = fields
        .iter()
        .map(|key| {
            request
                .get_header(key)
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "-".to_string())
        })
        .collect::<Vec<_>>()
        .join("|");
    (signature != "-|-|-|-|-|-|-")
        .then(|| compact_component("hdr", &signature, MAX_BEHAVIOR_KEY_LEN))
}

fn select_behavior_assessment(
    identity_assessment: Option<BehaviorAssessment>,
    aggregate_assessment: Option<BehaviorAssessment>,
) -> Option<BehaviorAssessment> {
    let aggregate_assessment = aggregate_assessment
        .filter(distributed_assessment_is_actionable)
        .map(normalize_distributed_assessment_score);
    match (identity_assessment, aggregate_assessment) {
        (Some(identity), Some(aggregate)) if aggregate.score > identity.score => Some(aggregate),
        (Some(identity), _) => Some(identity),
        (None, Some(aggregate)) => Some(aggregate),
        (None, None) => None,
    }
}

fn distributed_assessment_is_actionable(assessment: &BehaviorAssessment) -> bool {
    assessment.score >= DELAY_SCORE
        && assessment.flags.iter().any(|flag| {
            matches!(
                *flag,
                "distributed_document_burst"
                    | "distributed_document_probe"
                    | "distributed_api_burst"
            ) || (assessment.identity.contains("|client:")
                && matches!(
                    *flag,
                    "single_source_document_loop" | "single_source_identity_rotation"
                ))
        })
}

fn normalize_distributed_assessment_score(
    mut assessment: BehaviorAssessment,
) -> BehaviorAssessment {
    let has_burst_flag = assessment.flags.iter().any(|flag| {
        matches!(
            *flag,
            "distributed_document_burst" | "distributed_api_burst"
        )
    });
    if !has_burst_flag {
        assessment.score = assessment.score.min(CHALLENGE_SCORE);
    }
    assessment
}

fn assessment_is_aggregate(identity: &str) -> bool {
    identity.starts_with("site:")
        || identity.starts_with("aggregate:")
        || identity.starts_with("__overflow__:behavior-aggregate")
}

fn assessment_allows_aggregate_enforcement(assessment: &BehaviorAssessment) -> bool {
    assessment_is_aggregate(&assessment.identity)
        && assessment.flags.iter().any(|flag| {
            matches!(
                *flag,
                "distributed_document_burst"
                    | "distributed_document_probe"
                    | "distributed_api_burst"
            )
        })
}

fn aggregate_enforcement_key(identity: &str) -> String {
    compact_component("aggregate-enforcement", identity, MAX_BEHAVIOR_KEY_LEN)
}

fn runtime_usize_metadata(request: &UnifiedHttpRequest, key: &str, default: usize) -> usize {
    request
        .get_metadata(key)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn runtime_u64_metadata(request: &UnifiedHttpRequest, key: &str, default: u64) -> u64 {
    request
        .get_metadata(key)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(default)
}

impl BehaviorWindow {
    fn new() -> Self {
        Self {
            samples: Mutex::new(VecDeque::new()),
            challenge_hits: Mutex::new(VecDeque::new()),
            last_seen_unix: AtomicI64::new(unix_timestamp()),
        }
    }

    fn observe_and_assess(
        &mut self,
        identity: String,
        route: String,
        kind: RequestKind,
        client_ip: Option<String>,
        user_agent: Option<String>,
        header_signature: Option<String>,
        now: Instant,
        unix_now: i64,
        window: Duration,
    ) -> BehaviorAssessment {
        let mut samples = self.samples.lock().expect("behavior window lock poisoned");
        while let Some(front) = samples.front() {
            if now.duration_since(front.at) > window || samples.len() > MAX_SAMPLES_PER_IDENTITY {
                samples.pop_front();
            } else {
                break;
            }
        }
        samples.push_back(RequestSample {
            route: route.clone(),
            kind,
            client_ip,
            user_agent,
            header_signature,
            at: now,
        });
        while samples.len() > MAX_SAMPLES_PER_IDENTITY {
            samples.pop_front();
        }
        self.last_seen_unix.store(unix_now, Ordering::Relaxed);
        let recent_challenges = self.recent_challenges(now, window);

        assess_samples(identity, &samples, now, recent_challenges)
    }

    fn recent_challenges(&self, now: Instant, window: Duration) -> usize {
        let mut challenge_hits = self
            .challenge_hits
            .lock()
            .expect("behavior challenge lock poisoned");
        while let Some(front) = challenge_hits.front() {
            if now.duration_since(*front) > window {
                challenge_hits.pop_front();
            } else {
                break;
            }
        }
        challenge_hits.len()
    }

    fn record_challenge(&mut self, now: Instant, window: Duration) {
        let mut challenge_hits = self
            .challenge_hits
            .lock()
            .expect("behavior challenge lock poisoned");
        while let Some(front) = challenge_hits.front() {
            if now.duration_since(*front) > window {
                challenge_hits.pop_front();
            } else {
                break;
            }
        }
        challenge_hits.push_back(now);
    }

    fn record_block(&mut self, now: Instant, window: Duration) {
        let mut challenge_hits = self
            .challenge_hits
            .lock()
            .expect("behavior challenge lock poisoned");
        while let Some(front) = challenge_hits.front() {
            if now.duration_since(*front) > window {
                challenge_hits.pop_front();
            } else {
                break;
            }
        }
        challenge_hits.clear();
    }

    fn snapshot(
        &self,
        identity: String,
        now: Instant,
        window: Duration,
    ) -> Option<BehaviorProfileSnapshot> {
        let mut samples = self.samples.lock().expect("behavior window lock poisoned");
        while let Some(front) = samples.front() {
            if now.duration_since(front.at) > window || samples.len() > MAX_SAMPLES_PER_IDENTITY {
                samples.pop_front();
            } else {
                break;
            }
        }
        if samples.is_empty() {
            return None;
        }
        let samples_snapshot = samples.iter().cloned().collect::<VecDeque<_>>();
        drop(samples);

        let assessment = assess_samples(
            identity.clone(),
            &samples_snapshot,
            now,
            self.recent_challenges(now, window),
        );
        let latest = samples_snapshot.back().cloned()?;
        Some(BehaviorProfileSnapshot {
            identity,
            source_ip: latest.client_ip,
            latest_seen_unix: self.last_seen_unix.load(Ordering::Relaxed),
            score: assessment.score,
            dominant_route: assessment.dominant_route,
            focused_document_route: assessment.focused_document_route,
            focused_api_route: assessment.focused_api_route,
            distinct_routes: assessment.distinct_routes,
            distinct_client_ips: assessment.distinct_client_ips,
            distinct_user_agents: assessment.distinct_user_agents,
            distinct_header_signatures: assessment.distinct_header_signatures,
            repeated_ratio_percent: assessment.repeated_ratio_percent,
            client_ip_repeated_ratio_percent: assessment.client_ip_repeated_ratio_percent,
            document_repeated_ratio_percent: assessment.document_repeated_ratio_percent,
            api_repeated_ratio_percent: assessment.api_repeated_ratio_percent,
            jitter_ms: assessment.jitter_ms,
            document_requests: assessment.document_requests,
            api_requests: assessment.api_requests,
            non_document_requests: assessment.non_document_requests,
            recent_challenges: assessment.recent_challenges,
            session_span_secs: assessment.session_span_secs,
            flags: assessment.flags.into_iter().map(str::to_string).collect(),
            latest_route: latest.route,
            latest_kind: latest.kind.as_str(),
        })
    }
}

impl RequestKind {
    fn as_str(self) -> &'static str {
        match self {
            RequestKind::Document => "document",
            RequestKind::Static => "static",
            RequestKind::Api => "api",
            RequestKind::Other => "other",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::HttpVersion;

    fn request(method: &str, uri: &str, accept: &str) -> UnifiedHttpRequest {
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, method.to_string(), uri.to_string());
        request.set_client_ip("203.0.113.10".to_string());
        request.add_header("host".to_string(), "example.com".to_string());
        request.add_header("accept".to_string(), accept.to_string());
        request.add_header("user-agent".to_string(), "MobileSafari".to_string());
        request
    }

    #[tokio::test]
    async fn repeated_document_requests_trigger_behavior_response() {
        let guard = L7BehaviorGuard::new();
        let mut last = None;
        for _ in 0..6 {
            let mut request = request("GET", "/", "text/html");
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), "/".to_string());
            last = guard.inspect_request(&mut request).await;
        }
        assert!(last.is_some());
    }

    #[tokio::test]
    async fn mixed_navigation_keeps_behavior_score_low() {
        let guard = L7BehaviorGuard::new();
        let mut doc = request("GET", "/", "text/html");
        doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        doc.add_metadata("l7.cc.route".to_string(), "/".to_string());
        assert!(guard.inspect_request(&mut doc).await.is_none());

        let mut js = request("GET", "/app.js", "*/*");
        js.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
        js.add_metadata("l7.cc.route".to_string(), "/app.js".to_string());
        assert!(guard.inspect_request(&mut js).await.is_none());

        let mut api = request("GET", "/api/feed", "application/json");
        api.add_metadata("l7.cc.request_kind".to_string(), "api".to_string());
        api.add_metadata("l7.cc.route".to_string(), "/api/feed".to_string());
        assert!(guard.inspect_request(&mut api).await.is_none());
        assert!(
            api.get_metadata("l7.behavior.score")
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or_default()
                < CHALLENGE_SCORE
        );
    }

    #[tokio::test]
    async fn repeated_document_refreshes_with_sparse_assets_trigger_challenge() {
        let guard = L7BehaviorGuard::new();
        let mut last = None;
        for index in 0..8 {
            let mut doc = request("GET", "/", "text/html");
            doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            doc.add_metadata("l7.cc.route".to_string(), "/".to_string());
            last = guard.inspect_request(&mut doc).await;

            if index % 2 == 0 {
                let mut favicon = request("GET", "/favicon.ico", "*/*");
                favicon.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
                favicon.add_metadata("l7.cc.route".to_string(), "/favicon.ico".to_string());
                let _ = guard.inspect_request(&mut favicon).await;
            }
        }

        assert!(last.is_some());
    }

    #[tokio::test]
    async fn repeated_full_page_reloads_with_many_assets_trigger_challenge() {
        let guard = L7BehaviorGuard::new();
        let mut last = None;

        for _cycle in 0..4 {
            let mut doc = request("GET", "/article.html", "text/html");
            doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            doc.add_metadata("l7.cc.route".to_string(), "/article.html".to_string());
            last = guard.inspect_request(&mut doc).await;

            for asset in 0..12 {
                let mut static_request = request("GET", &format!("/static/{asset}.js"), "*/*");
                static_request.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
                static_request
                    .add_metadata("l7.cc.route".to_string(), format!("/static/{asset}.js"));
                let _ = guard.inspect_request(&mut static_request).await;
            }
        }

        assert!(last.is_some());
    }

    #[tokio::test]
    async fn distributed_document_burst_triggers_aggregate_behavior_response() {
        let guard = L7BehaviorGuard::new();
        let mut last = None;

        for index in 0..8 {
            let mut request = request("GET", "/", "text/html");
            request.set_client_ip(format!("203.0.113.{}", index + 1));
            request.add_header(
                "user-agent".to_string(),
                format!("DistributedTestBrowser/{index}"),
            );
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), "/".to_string());
            last = guard.inspect_request(&mut request).await;
        }

        assert!(last.is_some());
        let mut request = request("GET", "/", "text/html");
        request.set_client_ip("203.0.113.99".to_string());
        request.add_header(
            "user-agent".to_string(),
            "DistributedTestBrowser/final".to_string(),
        );
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), "/".to_string());
        let _ = guard.inspect_request(&mut request).await;

        assert!(request
            .get_metadata("l7.behavior.flags")
            .is_some_and(|flags| flags.contains("distributed_document")));
        assert!(request
            .get_metadata("l7.behavior.distinct_client_ips")
            .and_then(|value| value.parse::<usize>().ok())
            .is_some_and(|count| count >= 4));
    }

    #[tokio::test]
    async fn route_burst_gate_blocks_scripted_multi_source_documents_within_seconds() {
        let guard = L7BehaviorGuard::new();
        let mut last = None;

        for index in 0..10 {
            let mut request = request("GET", "/", "*/*");
            request.set_client_ip(format!("203.0.113.{}", index + 1));
            request.add_header("user-agent".to_string(), "curl/8.0".to_string());
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), "/".to_string());
            last = guard.inspect_request(&mut request).await;
        }

        let result = last.expect("route burst gate should block scripted burst");
        assert_eq!(result.action, crate::core::InspectionAction::Drop);
        assert_eq!(
            result.persist_blocked_ip, false,
            "route burst gate should not persistently block rotating IPs"
        );
        let mut followup = request("GET", "/", "*/*");
        followup.set_client_ip("203.0.113.250".to_string());
        followup.add_header("user-agent".to_string(), "curl/8.0".to_string());
        followup.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        followup.add_metadata("l7.cc.route".to_string(), "/".to_string());
        let result = guard
            .inspect_request(&mut followup)
            .await
            .expect("route burst gate should keep blocking during burst window");
        assert_eq!(result.action, crate::core::InspectionAction::Drop);
        assert_eq!(
            followup
                .get_metadata("l7.behavior.action")
                .map(String::as_str),
            Some("aggregate_block")
        );
        assert_eq!(
            followup
                .get_metadata("l7.behavior.aggregate_enforcement")
                .map(String::as_str),
            Some("route_burst")
        );
    }

    #[tokio::test]
    async fn route_burst_gate_does_not_block_browser_like_broad_user_agents() {
        let guard = L7BehaviorGuard::new();

        for index in 0..10 {
            let mut request = request("GET", "/", "text/html");
            request.set_client_ip(format!("198.51.100.{}", index + 1));
            request.add_header(
                "user-agent".to_string(),
                format!("Mozilla/5.0 BrowserBurst/{index}"),
            );
            request.add_header("accept-language".to_string(), "zh-CN,zh;q=0.9".to_string());
            request.add_header("sec-fetch-dest".to_string(), "document".to_string());
            request.add_header("sec-fetch-mode".to_string(), "navigate".to_string());
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), "/".to_string());
            let result = guard.inspect_request(&mut request).await;
            assert!(
                request
                    .get_metadata("l7.behavior.aggregate_enforcement")
                    .map_or(true, |value| value != "route_burst"),
                "browser-like simultaneous visits should not trigger the route burst gate"
            );
            drop(result);
        }
    }

    #[tokio::test]
    async fn distributed_document_burst_activates_aggregate_block_enforcement() {
        let guard = L7BehaviorGuard::new();

        for index in 0..12 {
            let mut request = request("GET", "/", "text/html");
            request.set_client_ip(format!("203.0.113.{}", index + 1));
            request.add_header(
                "user-agent".to_string(),
                format!("DistributedBlockBrowser/{index}"),
            );
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), "/".to_string());
            let _ = guard.inspect_request(&mut request).await;
        }

        let mut next = request("GET", "/", "text/html");
        next.set_client_ip("203.0.113.250".to_string());
        next.add_header(
            "user-agent".to_string(),
            "DistributedBlockBrowser/fresh".to_string(),
        );
        next.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        next.add_metadata("l7.cc.route".to_string(), "/".to_string());

        let result = guard
            .inspect_request(&mut next)
            .await
            .expect("aggregate enforcement should block fresh source");

        assert_eq!(result.action, crate::core::InspectionAction::Drop);
        assert!(!result.persist_blocked_ip);
        assert_eq!(
            next.get_metadata("l7.behavior.aggregate_enforcement")
                .map(String::as_str),
            Some("active")
        );
        assert_eq!(
            next.get_metadata("l7.behavior.action").map(String::as_str),
            Some("aggregate_block")
        );
    }

    #[tokio::test]
    async fn aggregate_enforcement_uses_normalized_host() {
        let guard = L7BehaviorGuard::new();

        for index in 0..12 {
            let mut request = request("GET", "/", "text/html");
            request.add_header("host".to_string(), "Example.COM:443".to_string());
            request.set_client_ip(format!("203.0.113.{}", index + 1));
            request.add_header(
                "user-agent".to_string(),
                format!("DistributedHostBrowser/{index}"),
            );
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), "/".to_string());
            let _ = guard.inspect_request(&mut request).await;
        }

        let mut next = request("GET", "/", "text/html");
        next.add_header("host".to_string(), "example.com".to_string());
        next.set_client_ip("203.0.113.250".to_string());
        next.add_header(
            "user-agent".to_string(),
            "DistributedHostBrowser/fresh".to_string(),
        );
        next.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        next.add_metadata("l7.cc.route".to_string(), "/".to_string());

        let result = guard
            .inspect_request(&mut next)
            .await
            .expect("normalized host aggregate enforcement should apply");

        assert_eq!(result.action, crate::core::InspectionAction::Drop);
        assert_eq!(
            next.get_metadata("l7.behavior.action").map(String::as_str),
            Some("aggregate_block")
        );
    }

    #[tokio::test]
    async fn single_source_identity_rotation_triggers_behavior_without_route_enforcement() {
        let guard = L7BehaviorGuard::new();
        let mut last = None;

        for index in 0..8 {
            let mut request = request("GET", "/", "text/html");
            request.set_client_ip("203.0.113.80".to_string());
            request.add_header("user-agent".to_string(), format!("RotatingClient/{index}"));
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), "/".to_string());
            last = guard.inspect_request(&mut request).await;
        }

        let result = last.expect("single-source rotating identities should be challenged");
        assert_eq!(result.action, crate::core::InspectionAction::Respond);

        let mut other_ip = request("GET", "/", "text/html");
        other_ip.set_client_ip("203.0.113.200".to_string());
        other_ip.add_header("user-agent".to_string(), "NormalBrowser".to_string());
        other_ip.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        other_ip.add_metadata("l7.cc.route".to_string(), "/".to_string());

        let result = guard.inspect_request(&mut other_ip).await;
        assert!(
            !matches!(
                other_ip
                    .get_metadata("l7.behavior.aggregate_enforcement")
                    .map(String::as_str),
                Some("active")
            ),
            "single-source identity rotation must not enable route-wide enforcement"
        );
        assert!(
            result.is_none()
                || other_ip
                    .get_metadata("l7.behavior.flags")
                    .map_or(true, |flags| {
                        !flags.contains("single_source_identity_rotation")
                    })
        );
    }

    #[tokio::test]
    async fn distributed_document_probe_activates_aggregate_challenge_enforcement() {
        let guard = L7BehaviorGuard::new();

        for index in 0..8 {
            let mut request = request("GET", "/", "text/html");
            request.set_client_ip(format!("198.51.100.{}", index + 1));
            request.add_header(
                "user-agent".to_string(),
                format!("DistributedProbeBrowser/{index}"),
            );
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), "/".to_string());
            let _ = guard.inspect_request(&mut request).await;
        }

        let mut next = request("GET", "/", "text/html");
        next.set_client_ip("198.51.100.250".to_string());
        next.add_header(
            "user-agent".to_string(),
            "DistributedProbeBrowser/fresh".to_string(),
        );
        next.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        next.add_metadata("l7.cc.route".to_string(), "/".to_string());

        let result = guard
            .inspect_request(&mut next)
            .await
            .expect("aggregate enforcement should challenge fresh source");

        assert_eq!(result.action, crate::core::InspectionAction::Respond);
        assert!(!result.persist_blocked_ip);
        assert!(matches!(
            next.get_metadata("l7.behavior.action").map(String::as_str),
            Some("challenge" | "aggregate_challenge")
        ));
    }

    #[tokio::test]
    async fn distributed_broad_navigation_stays_below_aggregate_behavior_response() {
        let guard = L7BehaviorGuard::new();

        for index in 0..12 {
            let mut request = request("GET", &format!("/article-{index}.html"), "text/html");
            request.set_client_ip(format!("203.0.113.{}", index + 1));
            request.add_header(
                "user-agent".to_string(),
                format!("DistributedNormalBrowser/{index}"),
            );
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), format!("/article-{index}.html"));

            assert!(guard.inspect_request(&mut request).await.is_none());
        }
    }

    #[tokio::test]
    async fn distributed_article_family_burst_triggers_behavior_response() {
        let guard = L7BehaviorGuard::new();
        let mut last = None;

        for index in 0..8 {
            let mut request = request(
                "GET",
                &format!("/20260214{:04}.html", 1900 + index),
                "text/html",
            );
            request.set_client_ip(format!("203.0.113.{}", index + 1));
            request.add_header("user-agent".to_string(), format!("ArticleProbe/{index}"));
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata(
                "l7.cc.route".to_string(),
                format!("/20260214{:04}.html", 1900 + index),
            );
            last = guard.inspect_request(&mut request).await;
        }

        assert!(last.is_some());
    }

    #[tokio::test]
    async fn distributed_wordpress_plugin_family_burst_triggers_behavior_response() {
        let guard = L7BehaviorGuard::new();
        let mut last = None;

        for (index, plugin) in [
            "tabs-responsive",
            "woodly-core",
            "pods",
            "wc-spod",
            "multisafepay",
            "jc-importer",
            "block-slider",
            "mailchimp-forms-by-mailmunch",
        ]
        .iter()
        .enumerate()
        {
            let path = format!("/wp-content/plugins/{plugin}/readme.txt");
            let mut request = request("GET", &path, "text/html");
            request.set_client_ip(format!("203.0.113.{}", index + 1));
            request.add_header("user-agent".to_string(), format!("PluginProbe/{index}"));
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), path);
            last = guard.inspect_request(&mut request).await;
        }

        assert!(last.is_some());
    }

    #[tokio::test]
    async fn crawler_well_known_routes_do_not_trigger_aggregate_behavior_response() {
        let guard = L7BehaviorGuard::new();

        for index in 0..12 {
            let path = if index % 2 == 0 {
                "/robots.txt"
            } else {
                "/sitemap.xml"
            };
            let mut request = request("GET", path, "text/plain");
            request.set_client_ip(format!("203.0.113.{}", index + 1));
            request.add_header("user-agent".to_string(), format!("Crawler/{index}"));
            request.add_metadata("l7.cc.request_kind".to_string(), "other".to_string());
            request.add_metadata("l7.cc.route".to_string(), path.to_string());

            assert!(guard.inspect_request(&mut request).await.is_none());
        }
    }

    #[tokio::test]
    async fn broad_navigation_with_many_assets_stays_below_challenge() {
        let guard = L7BehaviorGuard::new();

        for page in 0..3 {
            let mut doc = request(
                "GET",
                "/wp-admin/edit-tags.php?taxonomy=category",
                "text/html",
            );
            doc.add_header("sec-fetch-dest".to_string(), "document".to_string());
            doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            doc.add_metadata(
                "l7.cc.route".to_string(),
                "/wp-admin/edit-tags.php".to_string(),
            );
            assert!(guard.inspect_request(&mut doc).await.is_none());

            for asset in 0..32 {
                let mut req = request("GET", &format!("/wp-admin/load-{page}-{asset}.css"), "*/*");
                req.add_header("sec-fetch-dest".to_string(), "style".to_string());
                req.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
                req.add_metadata(
                    "l7.cc.route".to_string(),
                    format!("/wp-admin/load-{page}-{asset}.css"),
                );
                assert!(guard.inspect_request(&mut req).await.is_none());
            }

            let mut api = request("POST", "/admin/async/state", "application/json");
            api.add_header(
                "content-type".to_string(),
                "application/json; charset=utf-8".to_string(),
            );
            api.add_header("x-requested-with".to_string(), "XMLHttpRequest".to_string());
            api.add_metadata("l7.cc.request_kind".to_string(), "api".to_string());
            api.add_metadata("l7.cc.route".to_string(), "/admin/async/state".to_string());
            assert!(guard.inspect_request(&mut api).await.is_none());
        }

        let mut summary = request("GET", "/wp-admin/tools.php", "text/html");
        summary.add_header("sec-fetch-dest".to_string(), "document".to_string());
        summary.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        summary.add_metadata("l7.cc.route".to_string(), "/wp-admin/tools.php".to_string());
        let _ = guard.inspect_request(&mut summary).await;

        let score = summary
            .get_metadata("l7.behavior.score")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_default();
        assert!(score < CHALLENGE_SCORE, "unexpected score {score}");
    }

    #[tokio::test]
    async fn repeated_challenges_escalate_to_block_and_persist() {
        let guard = L7BehaviorGuard::new();
        let mut actions = Vec::new();
        let mut persisted = Vec::new();

        for _ in 0..8 {
            let mut request = request("GET", "/", "text/html");
            request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
            request.add_metadata("l7.cc.route".to_string(), "/".to_string());
            let result = guard.inspect_request(&mut request).await;
            actions.push(
                request
                    .get_metadata("l7.behavior.action")
                    .cloned()
                    .unwrap_or_default(),
            );
            persisted.push(result.map(|item| item.persist_blocked_ip).unwrap_or(false));
        }

        assert!(actions.iter().any(|action| action == "challenge"));
        assert!(actions.iter().any(|action| action == "block"));
        assert!(persisted.iter().any(|flag| *flag));
    }

    #[test]
    fn snapshot_profiles_excludes_idle_identities() {
        let guard = L7BehaviorGuard::new();
        let stale_unix = unix_timestamp() - (ACTIVE_PROFILE_IDLE_SECS + 5);
        let stale_window = BehaviorWindow::new();
        {
            let mut samples = stale_window
                .samples
                .lock()
                .expect("behavior window lock poisoned");
            samples.push_back(RequestSample {
                route: "/stale".to_string(),
                kind: RequestKind::Document,
                client_ip: Some("203.0.113.10".to_string()),
                user_agent: None,
                header_signature: None,
                at: Instant::now(),
            });
        }
        stale_window
            .last_seen_unix
            .store(stale_unix, Ordering::Relaxed);
        guard.buckets.insert("fp:stale".to_string(), stale_window);

        let fresh_window = BehaviorWindow::new();
        {
            let mut samples = fresh_window
                .samples
                .lock()
                .expect("behavior window lock poisoned");
            samples.push_back(RequestSample {
                route: "/fresh".to_string(),
                kind: RequestKind::Document,
                client_ip: Some("203.0.113.11".to_string()),
                user_agent: None,
                header_signature: None,
                at: Instant::now(),
            });
        }
        guard.buckets.insert("fp:fresh".to_string(), fresh_window);

        let profiles = guard.snapshot_profiles(16);
        assert!(profiles
            .iter()
            .any(|profile| profile.identity == "fp:fresh"));
        assert!(!profiles
            .iter()
            .any(|profile| profile.identity == "fp:stale"));
    }

    #[test]
    fn request_identity_is_compacted_for_long_values() {
        let mut req = request("GET", "/", "text/html");
        req.add_header("x-browser-fingerprint-id".to_string(), "x".repeat(512));

        let identity = request_identity(&req).expect("identity");

        assert!(identity.len() <= MAX_BEHAVIOR_KEY_LEN);
        assert!(identity.starts_with("identity:"));
    }

    #[test]
    fn bounded_dashmap_key_overflows_when_limit_is_hit() {
        let map = DashMap::new();
        map.insert("first".to_string(), BehaviorWindow::new());
        map.insert("second".to_string(), BehaviorWindow::new());

        let key = bounded_dashmap_key(&map, "third".to_string(), 2, "behavior-test", 4);

        assert!(key.starts_with("__overflow__:behavior-test:"));
    }

    #[test]
    fn cc_other_root_request_is_treated_as_document_behavior() {
        let mut req = request("GET", "/", "*/*");
        req.add_metadata("l7.cc.request_kind".to_string(), "other".to_string());

        assert_eq!(request_kind(&req), RequestKind::Document);
    }

    #[tokio::test]
    async fn delay_is_upgraded_to_challenge_under_runtime_pressure() {
        let guard = L7BehaviorGuard::new();
        let mut request = request("GET", "/", "text/html");
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), "/".to_string());
        request.add_metadata("ai.behavior.force_watch".to_string(), "true".to_string());
        request.add_metadata(
            "runtime.pressure.drop_delay".to_string(),
            "true".to_string(),
        );

        let result = guard.inspect_request(&mut request).await;

        assert!(result.is_some());
        assert_eq!(
            request
                .get_metadata("l7.behavior.action")
                .map(String::as_str),
            Some("challenge")
        );
    }
}
