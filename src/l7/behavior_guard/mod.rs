use crate::core::{InspectionLayer, InspectionResult};
use crate::protocol::UnifiedHttpRequest;
use dashmap::DashMap;
use std::collections::VecDeque;
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
    request_path, should_drop_delay_under_pressure, unix_timestamp,
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

#[derive(Debug)]
pub struct L7BehaviorGuard {
    buckets: DashMap<String, BehaviorWindow>,
    request_sequence: AtomicU64,
}

impl L7BehaviorGuard {
    pub fn new() -> Self {
        Self {
            buckets: DashMap::new(),
            request_sequence: AtomicU64::new(0),
        }
    }

    pub async fn inspect_request(
        &self,
        request: &mut UnifiedHttpRequest,
    ) -> Option<InspectionResult> {
        let Some(identity) = request_identity(request) else {
            return None;
        };
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
        let now = Instant::now();
        let unix_now = unix_timestamp();
        let window = Duration::from_secs(BEHAVIOR_WINDOW_SECS);
        let mut assessment =
            self.observe_and_assess(&identity, route, kind, client_ip, now, unix_now, window);
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
            "l7.behavior.repeated_ratio".to_string(),
            assessment.repeated_ratio_percent.to_string(),
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

    fn observe_and_assess(
        &self,
        identity: &str,
        route: String,
        kind: RequestKind,
        client_ip: Option<String>,
        now: Instant,
        unix_now: i64,
        window: Duration,
    ) -> BehaviorAssessment {
        let identity = bounded_dashmap_key(
            &self.buckets,
            compact_component("identity", &identity, MAX_BEHAVIOR_KEY_LEN),
            MAX_BEHAVIOR_BUCKETS,
            "behavior",
            OVERFLOW_SHARDS,
        );
        let mut entry = self
            .buckets
            .entry(identity.clone())
            .or_insert_with(BehaviorWindow::new);
        entry.observe_and_assess(identity, route, kind, client_ip, now, unix_now, window)
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
    }

    fn record_challenge(&self, identity: &str, now: Instant, window: Duration) {
        if let Some(mut entry) = self.buckets.get_mut(identity) {
            entry.record_challenge(now, window);
        }
    }

    fn record_block(&self, identity: &str, now: Instant, window: Duration) {
        if let Some(mut entry) = self.buckets.get_mut(identity) {
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
            repeated_ratio_percent: assessment.repeated_ratio_percent,
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
