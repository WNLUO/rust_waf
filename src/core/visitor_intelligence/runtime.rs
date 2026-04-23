use super::identity::{cookie_value, visitor_identity};
use super::routing::{
    classify_request_kind, has_same_site_referer, is_admin_route, normalized_route,
    storage_route_profile_matches, update_bucket_flags,
};
use super::scoring::{profile_signal_from_bucket, visitor_decision_from_profile};
use super::types::{
    VisitorIntelligenceBucket, VisitorIntelligenceSnapshot, MAX_VISITOR_BUCKETS,
    MAX_VISITOR_RECENT_ROUTES, MAX_VISITOR_ROUTES, VISITOR_WINDOW_SECS,
};
use super::utils::{compact_text, visitor_priority_rank};
use crate::core::{unix_timestamp, AiRouteResultObservation, WafContext};
use crate::locks::mutex_lock;
use crate::protocol::UnifiedHttpRequest;
use crate::storage::{AiVisitorDecisionUpsert, AiVisitorProfileUpsert};
use std::sync::Mutex;

impl WafContext {
    pub fn note_visitor_route_result(
        &self,
        request: &UnifiedHttpRequest,
        observation: &AiRouteResultObservation,
    ) {
        if !self
            .config_snapshot()
            .integrations
            .ai_audit
            .auto_defense_enabled
        {
            return;
        }
        if request
            .get_metadata("network.server_public_ip_exempt")
            .is_some_and(|value| value == "true")
        {
            return;
        }
        let Some((identity_key, identity_source)) = visitor_identity(request) else {
            return;
        };
        let now = unix_timestamp();
        let window_start = now.div_euclid(VISITOR_WINDOW_SECS) * VISITOR_WINDOW_SECS;
        let site_id = request
            .get_metadata("gateway.site_id")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        let key = format!("{site_id}:{identity_key}");
        if !self.ensure_visitor_intelligence_capacity(&key, window_start) {
            return;
        }
        let entry = self
            .visitor_intelligence_buckets
            .entry(key)
            .or_insert_with(|| Mutex::new(VisitorIntelligenceBucket::default()));
        let mut bucket = mutex_lock(entry.value(), "visitor intelligence");
        if bucket.window_start != window_start {
            *bucket = VisitorIntelligenceBucket {
                window_start,
                identity_key: identity_key.clone(),
                identity_source: identity_source.clone(),
                site_id: site_id.clone(),
                client_ip: request.client_ip.clone().unwrap_or_else(|| "-".to_string()),
                user_agent: request
                    .get_header("user-agent")
                    .map(|value| compact_text(value, 180))
                    .unwrap_or_else(|| "-".to_string()),
                first_seen_at: now,
                last_seen_at: now,
                ..VisitorIntelligenceBucket::default()
            };
        }
        bucket.identity_key = identity_key;
        bucket.identity_source = identity_source;
        bucket.site_id = site_id.clone();
        bucket.client_ip = request
            .client_ip
            .clone()
            .unwrap_or_else(|| bucket.client_ip.clone());
        bucket.user_agent = request
            .get_header("user-agent")
            .map(|value| compact_text(value, 180))
            .unwrap_or_else(|| bucket.user_agent.clone());
        if bucket.first_seen_at == 0 {
            bucket.first_seen_at = now;
        }
        bucket.last_seen_at = now;
        bucket.request_count = bucket.request_count.saturating_add(1);
        let route = normalized_route(&request.uri);
        let kind = classify_request_kind(request, &route);
        match kind {
            "document" => bucket.document_count = bucket.document_count.saturating_add(1),
            "api" => bucket.api_count = bucket.api_count.saturating_add(1),
            "static" => bucket.static_count = bucket.static_count.saturating_add(1),
            _ => {}
        }
        if is_admin_route(&route) {
            bucket.admin_count = bucket.admin_count.saturating_add(1);
        }
        if request
            .get_metadata("l7.cc.action")
            .is_some_and(|value| value.contains("challenge"))
            || request
                .get_metadata("l7.behavior.action")
                .is_some_and(|value| value.contains("challenge"))
        {
            bucket.challenge_count = bucket.challenge_count.saturating_add(1);
        }
        if request
            .get_metadata("l7.cc.challenge_verified")
            .is_some_and(|value| value == "true")
            || request.get_header("x-browser-fingerprint-id").is_some()
            || cookie_value(request, "rwaf_fp").is_some()
        {
            bucket.challenge_verified_count = bucket.challenge_verified_count.saturating_add(1);
            bucket.fingerprint_seen = true;
        }
        if observation.local_response {
            bucket.local_response_count = bucket.local_response_count.saturating_add(1);
        }
        if observation.blocked {
            bucket.blocked_response_count = bucket.blocked_response_count.saturating_add(1);
        }
        if observation.upstream_error {
            bucket.upstream_error_count = bucket.upstream_error_count.saturating_add(1);
        }
        if !observation.local_response {
            match observation.status_code {
                200..=299 => {
                    bucket.upstream_success_count = bucket.upstream_success_count.saturating_add(1);
                }
                300..=399 => {
                    bucket.upstream_redirect_count =
                        bucket.upstream_redirect_count.saturating_add(1);
                }
                400..=499 => {
                    bucket.upstream_client_error_count =
                        bucket.upstream_client_error_count.saturating_add(1);
                }
                _ => {}
            }
        }
        *bucket
            .status_codes
            .entry(observation.status_code.to_string())
            .or_insert(0) += 1;
        if let Some(profile) = self.ai_business_route_profile(&site_id, &route) {
            if profile.route_type != "unknown" {
                *bucket
                    .business_route_types
                    .entry(profile.route_type.clone())
                    .or_insert(0) += 1;
            }
            if matches!(profile.auth_required.as_str(), "true" | "mixed") {
                bucket.auth_required_route_count =
                    bucket.auth_required_route_count.saturating_add(1);
                match observation.status_code {
                    200..=399 => {
                        bucket.auth_success_count = bucket.auth_success_count.saturating_add(1);
                    }
                    401 | 403 => {
                        bucket.auth_rejected_count = bucket.auth_rejected_count.saturating_add(1);
                    }
                    _ => {}
                }
            }
        }
        if bucket.route_counts.contains_key(&route)
            || bucket.route_counts.len() < MAX_VISITOR_ROUTES
        {
            *bucket.route_counts.entry(route.clone()).or_insert(0) += 1;
        }
        bucket.recent_routes.push_back(route.clone());
        while bucket.recent_routes.len() > MAX_VISITOR_RECENT_ROUTES {
            bucket.recent_routes.pop_front();
        }
        if has_same_site_referer(request) {
            bucket.same_site_referer_count = bucket.same_site_referer_count.saturating_add(1);
        } else if kind == "document" {
            bucket.no_referer_document_count = bucket.no_referer_document_count.saturating_add(1);
        }
        update_bucket_flags(&mut bucket, request, &route, kind);
    }

    pub fn note_visitor_fingerprint_report(
        &self,
        request: &UnifiedHttpRequest,
        fingerprint_id: &str,
        payload: Option<&serde_json::Value>,
    ) {
        let Some(site_id) = request
            .get_metadata("gateway.site_id")
            .cloned()
            .or_else(|| request.get_metadata("provider_site_id").cloned())
        else {
            return;
        };
        let identity_key = format!("fp:{}", compact_text(fingerprint_id, 96));
        let key = format!("{site_id}:{identity_key}");
        let now = unix_timestamp();
        let entry = self
            .visitor_intelligence_buckets
            .entry(key)
            .or_insert_with(|| Mutex::new(VisitorIntelligenceBucket::default()));
        let mut bucket = mutex_lock(entry.value(), "visitor intelligence");
        if bucket.first_seen_at == 0 {
            bucket.first_seen_at = now;
        }
        bucket.window_start = now.div_euclid(VISITOR_WINDOW_SECS) * VISITOR_WINDOW_SECS;
        bucket.identity_key = identity_key;
        bucket.identity_source = "fingerprint".to_string();
        bucket.site_id = site_id;
        bucket.client_ip = request.client_ip.clone().unwrap_or_default();
        bucket.user_agent = request
            .get_header("user-agent")
            .map(|value| compact_text(value, 180))
            .unwrap_or_default();
        bucket.last_seen_at = now;
        bucket.fingerprint_seen = true;
        bucket.challenge_verified_count = bucket.challenge_verified_count.saturating_add(1);
        bucket.challenge_page_report_count = bucket.challenge_page_report_count.saturating_add(1);
        if payload.and_then(|value| value.get("challenge")).is_some() {
            bucket.challenge_js_report_count = bucket.challenge_js_report_count.saturating_add(1);
            bucket.flags.insert("challenge_js_report_seen".to_string());
        }
        bucket.flags.insert("browser_fingerprint_seen".to_string());
    }

    pub fn visitor_intelligence_snapshot(&self, limit: usize) -> VisitorIntelligenceSnapshot {
        let now = unix_timestamp();
        let pressure = self.runtime_pressure_snapshot();
        let degraded_reason = if pressure.level == "attack" || pressure.defense_depth == "survival"
        {
            Some("visitor_ai_degraded_under_attack_pressure".to_string())
        } else {
            None
        };
        let mut profiles = self
            .visitor_intelligence_buckets
            .iter()
            .filter_map(|entry| {
                let bucket = entry.value().lock().ok()?;
                if now.saturating_sub(bucket.last_seen_at) > VISITOR_WINDOW_SECS {
                    return None;
                }
                Some(profile_signal_from_bucket(&bucket))
            })
            .collect::<Vec<_>>();
        profiles.sort_by(|left, right| {
            visitor_priority_rank(&right.tracking_priority)
                .cmp(&visitor_priority_rank(&left.tracking_priority))
                .then_with(|| right.abuse_risk.cmp(&left.abuse_risk))
                .then_with(|| right.automation_risk.cmp(&left.automation_risk))
                .then_with(|| right.request_count.cmp(&left.request_count))
        });
        let active_profile_count = profiles.len();
        profiles.truncate(limit);
        let recommendations = if degraded_reason.is_some() {
            Vec::new()
        } else {
            profiles
                .iter()
                .filter_map(visitor_decision_from_profile)
                .take(limit)
                .collect()
        };
        VisitorIntelligenceSnapshot {
            generated_at: now,
            enabled: self
                .config_snapshot()
                .integrations
                .ai_audit
                .auto_defense_enabled,
            degraded_reason,
            active_profile_count,
            profiles,
            recommendations,
        }
    }

    pub(crate) fn persist_visitor_intelligence_snapshot(&self, limit: usize) {
        let Some(store) = self.sqlite_store.as_ref().cloned() else {
            return;
        };
        let snapshot = self.visitor_intelligence_snapshot(limit);
        tokio::spawn(async move {
            for profile in snapshot.profiles {
                let _ = store
                    .upsert_ai_visitor_profile(&AiVisitorProfileUpsert::from(profile))
                    .await;
            }
            for decision in snapshot.recommendations {
                let _ = store
                    .upsert_ai_visitor_decision(&AiVisitorDecisionUpsert::from(decision))
                    .await;
            }
        });
    }

    fn ensure_visitor_intelligence_capacity(&self, key: &str, window_start: i64) -> bool {
        if self.visitor_intelligence_buckets.contains_key(key)
            || self.visitor_intelligence_buckets.len() < MAX_VISITOR_BUCKETS
        {
            return true;
        }
        let mut removed = 0usize;
        self.visitor_intelligence_buckets.retain(|_, value| {
            if removed >= 512 {
                return true;
            }
            let stale = value
                .lock()
                .map(|bucket| bucket.window_start < window_start)
                .unwrap_or(true);
            if stale {
                removed += 1;
            }
            !stale
        });
        self.visitor_intelligence_buckets.contains_key(key)
            || self.visitor_intelligence_buckets.len() < MAX_VISITOR_BUCKETS
    }

    fn ai_business_route_profile(
        &self,
        site_id: &str,
        route: &str,
    ) -> Option<crate::storage::AiRouteProfileEntry> {
        self.active_ai_route_profiles().into_iter().find(|profile| {
            profile.site_id == site_id && storage_route_profile_matches(profile, route)
        })
    }
}
