use super::{unix_timestamp, AiRouteResultObservation, WafContext};
use crate::protocol::UnifiedHttpRequest;
use crate::storage::{AiVisitorDecisionUpsert, AiVisitorProfileUpsert};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::sync::Mutex;

const VISITOR_WINDOW_SECS: i64 = 15 * 60;
const MAX_VISITOR_BUCKETS: usize = 16_384;
const MAX_VISITOR_ROUTES: usize = 24;
const MAX_VISITOR_RECENT_ROUTES: usize = 16;

#[derive(Debug, Clone, Default)]
pub(super) struct VisitorIntelligenceBucket {
    pub window_start: i64,
    pub identity_key: String,
    pub identity_source: String,
    pub site_id: String,
    pub client_ip: String,
    pub user_agent: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub request_count: u64,
    pub document_count: u64,
    pub api_count: u64,
    pub static_count: u64,
    pub admin_count: u64,
    pub challenge_count: u64,
    pub challenge_verified_count: u64,
    pub challenge_page_report_count: u64,
    pub challenge_js_report_count: u64,
    pub local_response_count: u64,
    pub blocked_response_count: u64,
    pub upstream_error_count: u64,
    pub upstream_success_count: u64,
    pub upstream_redirect_count: u64,
    pub upstream_client_error_count: u64,
    pub auth_required_route_count: u64,
    pub auth_success_count: u64,
    pub auth_rejected_count: u64,
    pub same_site_referer_count: u64,
    pub no_referer_document_count: u64,
    pub fingerprint_seen: bool,
    pub route_counts: BTreeMap<String, u64>,
    pub business_route_types: BTreeMap<String, u64>,
    pub status_codes: BTreeMap<String, u64>,
    pub recent_routes: VecDeque<String>,
    pub flags: HashSet<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VisitorIntelligenceSnapshot {
    pub generated_at: i64,
    pub enabled: bool,
    pub degraded_reason: Option<String>,
    pub active_profile_count: usize,
    pub profiles: Vec<VisitorProfileSignal>,
    pub recommendations: Vec<VisitorDecisionSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisitorProfileSignal {
    pub identity_key: String,
    pub identity_source: String,
    pub site_id: String,
    pub client_ip: String,
    pub user_agent: String,
    pub state: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub request_count: u64,
    pub document_count: u64,
    pub api_count: u64,
    pub static_count: u64,
    pub admin_count: u64,
    pub challenge_count: u64,
    pub challenge_verified_count: u64,
    pub challenge_page_report_count: u64,
    pub challenge_js_report_count: u64,
    pub fingerprint_seen: bool,
    pub upstream_success_count: u64,
    pub upstream_redirect_count: u64,
    pub upstream_client_error_count: u64,
    pub upstream_error_count: u64,
    pub auth_required_route_count: u64,
    pub auth_success_count: u64,
    pub auth_rejected_count: u64,
    pub human_confidence: u8,
    pub automation_risk: u8,
    pub probe_risk: u8,
    pub abuse_risk: u8,
    pub false_positive_risk: String,
    pub tracking_priority: String,
    pub route_summary: Vec<VisitorRouteSummary>,
    pub business_route_types: BTreeMap<String, u64>,
    pub status_codes: BTreeMap<String, u64>,
    pub flags: Vec<String>,
    pub ai_rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisitorRouteSummary {
    pub route: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisitorDecisionSignal {
    pub decision_key: String,
    pub identity_key: String,
    pub site_id: String,
    pub action: String,
    pub confidence: u8,
    pub ttl_secs: u64,
    pub rationale: String,
    pub applied: bool,
    pub effect_status: String,
}

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
        let mut bucket = entry.lock().expect("visitor intelligence lock poisoned");
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
        let mut bucket = entry.lock().expect("visitor intelligence lock poisoned");
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

fn profile_signal_from_bucket(bucket: &VisitorIntelligenceBucket) -> VisitorProfileSignal {
    let mut flags = bucket.flags.iter().cloned().collect::<Vec<_>>();
    flags.sort();
    let route_summary = top_routes(&bucket.route_counts, 8);
    let route_diversity = bucket.route_counts.len() as u64;
    let mut human = 20u8;
    let mut automation = 0u8;
    let mut probe = 0u8;
    let mut abuse = 0u8;

    if bucket.fingerprint_seen {
        human = human.saturating_add(30);
    }
    if bucket.challenge_verified_count > 0 {
        human = human.saturating_add(25);
    }
    if bucket.challenge_js_report_count > 0 {
        human = human.saturating_add(10);
    }
    if bucket.static_count >= bucket.document_count.max(1) {
        human = human.saturating_add(10);
    }
    if bucket.same_site_referer_count > 0 {
        human = human.saturating_add(10);
    }
    if bucket.admin_count > 0 && (bucket.fingerprint_seen || bucket.same_site_referer_count > 0) {
        human = human.saturating_add(10);
    }
    if bucket.document_count >= 8 && bucket.static_count == 0 {
        automation = automation.saturating_add(35);
    }
    if bucket.document_count >= 6 && route_diversity <= 2 {
        automation = automation.saturating_add(25);
    }
    if bucket.no_referer_document_count >= 5 {
        automation = automation.saturating_add(15);
    }
    if bucket.admin_count >= 3 && !bucket.fingerprint_seen {
        probe = probe.saturating_add(40);
    }
    if bucket.auth_rejected_count >= 3 && bucket.auth_success_count == 0 {
        probe = probe.saturating_add(25);
    }
    if bucket.status_codes.get("404").copied().unwrap_or(0) >= 3
        || bucket.status_codes.get("403").copied().unwrap_or(0) >= 3
    {
        probe = probe.saturating_add(20);
    }
    if bucket.blocked_response_count > 0 {
        abuse = abuse.saturating_add(25);
    }
    if bucket.challenge_count >= 2 && bucket.challenge_verified_count == 0 {
        abuse = abuse.saturating_add(25);
    }
    if bucket.api_count >= 10 && !bucket.fingerprint_seen {
        abuse = abuse.saturating_add(20);
    }
    if human >= 70 {
        automation = automation.saturating_sub(20);
        probe = probe.saturating_sub(15);
        abuse = abuse.saturating_sub(10);
    }

    let false_positive_risk = if human >= 75 && (automation >= 35 || abuse >= 25) {
        "high"
    } else if human >= 55 {
        "medium"
    } else {
        "low"
    }
    .to_string();
    let state = if bucket.fingerprint_seen && bucket.admin_count > 0 {
        "admin_session"
    } else if human >= 75 {
        "trusted_session"
    } else if probe >= 45 {
        "suspected_probe"
    } else if automation >= 50 {
        "suspected_crawler"
    } else if abuse >= 45 {
        "suspected_abuse"
    } else if bucket.challenge_count > 0 {
        "challenged"
    } else {
        "observing"
    }
    .to_string();
    let tracking_priority = if matches!(state.as_str(), "suspected_probe" | "suspected_abuse") {
        "high"
    } else if automation >= 35 || false_positive_risk != "low" {
        "medium"
    } else {
        "low"
    }
    .to_string();
    let ai_rationale = format!(
        "state={} human={} automation={} probe={} abuse={} docs={} static={} api={} admin={} verified={} fp={} challenge_js={} upstream_success={} upstream_error={} auth_required={} auth_success={} auth_rejected={} business_types={:?} routes={}",
        state,
        human,
        automation,
        probe,
        abuse,
        bucket.document_count,
        bucket.static_count,
        bucket.api_count,
        bucket.admin_count,
        bucket.challenge_verified_count,
        bucket.fingerprint_seen,
        bucket.challenge_js_report_count,
        bucket.upstream_success_count,
        bucket.upstream_error_count,
        bucket.auth_required_route_count,
        bucket.auth_success_count,
        bucket.auth_rejected_count,
        bucket.business_route_types,
        bucket.route_counts.len()
    );
    VisitorProfileSignal {
        identity_key: bucket.identity_key.clone(),
        identity_source: bucket.identity_source.clone(),
        site_id: bucket.site_id.clone(),
        client_ip: bucket.client_ip.clone(),
        user_agent: bucket.user_agent.clone(),
        state,
        first_seen_at: bucket.first_seen_at,
        last_seen_at: bucket.last_seen_at,
        request_count: bucket.request_count,
        document_count: bucket.document_count,
        api_count: bucket.api_count,
        static_count: bucket.static_count,
        admin_count: bucket.admin_count,
        challenge_count: bucket.challenge_count,
        challenge_verified_count: bucket.challenge_verified_count,
        challenge_page_report_count: bucket.challenge_page_report_count,
        challenge_js_report_count: bucket.challenge_js_report_count,
        fingerprint_seen: bucket.fingerprint_seen,
        upstream_success_count: bucket.upstream_success_count,
        upstream_redirect_count: bucket.upstream_redirect_count,
        upstream_client_error_count: bucket.upstream_client_error_count,
        upstream_error_count: bucket.upstream_error_count,
        auth_required_route_count: bucket.auth_required_route_count,
        auth_success_count: bucket.auth_success_count,
        auth_rejected_count: bucket.auth_rejected_count,
        human_confidence: human.min(100),
        automation_risk: automation.min(100),
        probe_risk: probe.min(100),
        abuse_risk: abuse.min(100),
        false_positive_risk,
        tracking_priority,
        route_summary,
        business_route_types: bucket.business_route_types.clone(),
        status_codes: bucket.status_codes.clone(),
        flags,
        ai_rationale,
    }
}

fn visitor_decision_from_profile(profile: &VisitorProfileSignal) -> Option<VisitorDecisionSignal> {
    if profile.request_count < 6 && profile.admin_count < 2 {
        return None;
    }
    let (action, confidence, ttl_secs, rationale) = if profile.false_positive_risk == "high" {
        (
            "reduce_friction",
            86,
            900,
            "visitor has strong human signals while still receiving friction",
        )
    } else if matches!(
        profile.state.as_str(),
        "suspected_probe" | "suspected_abuse"
    ) {
        (
            "increase_challenge",
            88,
            900,
            "visitor shows sensitive-route probing or abuse signals",
        )
    } else if profile.state == "suspected_crawler" {
        (
            "watch_visitor",
            84,
            900,
            "visitor looks automated but not severe enough for blocking",
        )
    } else if profile.state == "trusted_session" || profile.state == "admin_session" {
        (
            "mark_trusted_temporarily",
            82,
            900,
            "visitor has browser verification and normal session signals",
        )
    } else {
        return None;
    };
    Some(VisitorDecisionSignal {
        decision_key: format!("visitor:{}:{}", action, stable_hash(&profile.identity_key)),
        identity_key: profile.identity_key.clone(),
        site_id: profile.site_id.clone(),
        action: action.to_string(),
        confidence,
        ttl_secs,
        rationale: format!("{}; {}", rationale, profile.ai_rationale),
        applied: false,
        effect_status: "pending".to_string(),
    })
}

fn visitor_identity(request: &UnifiedHttpRequest) -> Option<(String, String)> {
    if let Some(value) = cookie_value(request, "rwaf_fp") {
        return Some((
            format!("fp:{}", compact_text(&value, 96)),
            "fingerprint".to_string(),
        ));
    }
    if let Some(value) = request.get_header("x-browser-fingerprint-id") {
        let value = value.trim();
        if !value.is_empty() {
            return Some((
                format!("fp:{}", compact_text(value, 96)),
                "fingerprint".to_string(),
            ));
        }
    }
    if let Some(value) = cookie_value(request, "rwaf_cc") {
        return Some((
            format!("cc:{}", compact_text(&value, 96)),
            "challenge_cookie".to_string(),
        ));
    }
    if let Some(value) = cookie_value(request, "rwaf_behavior") {
        return Some((
            format!("behavior:{}", compact_text(&value, 96)),
            "behavior_cookie".to_string(),
        ));
    }
    let ip = request.client_ip.as_deref()?.trim();
    if ip.is_empty() {
        return None;
    }
    let ua = request
        .get_header("user-agent")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("-");
    Some((
        format!("ipua:{}|{}", ip, compact_text(ua, 96)),
        "ip_user_agent".to_string(),
    ))
}

fn update_bucket_flags(
    bucket: &mut VisitorIntelligenceBucket,
    request: &UnifiedHttpRequest,
    route: &str,
    kind: &str,
) {
    if kind == "document" && !has_same_site_referer(request) {
        bucket.flags.insert("document_without_referer".to_string());
    }
    if kind == "document" && bucket.static_count == 0 && bucket.document_count >= 4 {
        bucket.flags.insert("document_without_assets".to_string());
    }
    if is_admin_route(route) {
        bucket.flags.insert("admin_route".to_string());
    }
    if route.contains("xmlrpc.php") || route.contains("wp-login.php") {
        bucket.flags.insert("sensitive_wordpress_route".to_string());
    }
    if request
        .get_metadata("l7.cc.challenge_verified")
        .is_some_and(|value| value == "true")
    {
        bucket.flags.insert("challenge_verified".to_string());
    }
    if request.get_metadata("ai.policy.matched_ids").is_some() {
        bucket.flags.insert("ai_policy_matched".to_string());
    }
}

fn storage_route_profile_matches(
    profile: &crate::storage::AiRouteProfileEntry,
    route: &str,
) -> bool {
    match profile.match_mode.as_str() {
        "exact" => route == profile.route_pattern,
        "prefix" => route.starts_with(&profile.route_pattern),
        "wildcard" => wildcard_route_matches(&profile.route_pattern, route),
        _ => false,
    }
}

fn wildcard_route_matches(pattern: &str, route: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let Some((prefix, suffix)) = pattern.split_once('*') else {
        return route == pattern;
    };
    route.starts_with(prefix) && route.ends_with(suffix)
}

fn classify_request_kind(request: &UnifiedHttpRequest, route: &str) -> &'static str {
    let method = request.method.to_ascii_uppercase();
    if method != "GET" && method != "HEAD" {
        return "api";
    }
    let lower = route.to_ascii_lowercase();
    if lower.contains("/wp-admin/admin-ajax.php")
        || lower.starts_with("/api/")
        || lower.contains("ajax")
    {
        return "api";
    }
    if lower.ends_with(".css")
        || lower.ends_with(".js")
        || lower.ends_with(".png")
        || lower.ends_with(".jpg")
        || lower.ends_with(".jpeg")
        || lower.ends_with(".webp")
        || lower.ends_with(".gif")
        || lower.ends_with(".svg")
        || lower.ends_with(".woff")
        || lower.ends_with(".woff2")
        || lower.ends_with(".ttf")
    {
        return "static";
    }
    "document"
}

fn normalized_route(uri: &str) -> String {
    let path = uri.split('?').next().unwrap_or(uri).trim();
    if path.is_empty() {
        "/".to_string()
    } else {
        compact_text(path.trim_end_matches('/'), 180)
    }
}

fn is_admin_route(route: &str) -> bool {
    let lower = route.to_ascii_lowercase();
    lower.contains("/wp-admin") || lower.contains("/wp-login") || lower.contains("xmlrpc.php")
}

fn has_same_site_referer(request: &UnifiedHttpRequest) -> bool {
    let Some(referer) = request.get_header("referer") else {
        return false;
    };
    let Some(host) = request.get_header("host") else {
        return false;
    };
    let host = host.split(':').next().unwrap_or(host).trim();
    !host.is_empty() && referer.contains(host)
}

fn cookie_value(request: &UnifiedHttpRequest, name: &str) -> Option<String> {
    request.get_header("cookie").and_then(|value| {
        value.split(';').find_map(|item| {
            let (key, value) = item.trim().split_once('=')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    })
}

fn top_routes(routes: &BTreeMap<String, u64>, limit: usize) -> Vec<VisitorRouteSummary> {
    let mut items = routes
        .iter()
        .map(|(route, count)| VisitorRouteSummary {
            route: route.clone(),
            count: *count,
        })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.route.cmp(&right.route))
    });
    items.truncate(limit);
    items
}

fn compact_text(value: &str, limit: usize) -> String {
    let trimmed = value.trim().replace('\n', " ").replace('\r', " ");
    if trimmed.chars().count() <= limit {
        trimmed
    } else {
        format!("{}...", trimmed.chars().take(limit).collect::<String>())
    }
}

fn visitor_priority_rank(value: &str) -> u8 {
    match value {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn stable_hash(value: &str) -> String {
    let mut hash = 1469598103934665603u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(1099511628211);
    }
    format!("{hash:016x}")
}

impl From<VisitorProfileSignal> for AiVisitorProfileUpsert {
    fn from(value: VisitorProfileSignal) -> Self {
        let summary_json = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
        Self {
            identity_key: value.identity_key,
            identity_source: value.identity_source,
            site_id: value.site_id,
            client_ip: value.client_ip,
            user_agent: value.user_agent,
            first_seen_at: value.first_seen_at,
            last_seen_at: value.last_seen_at,
            request_count: value.request_count as i64,
            document_count: value.document_count as i64,
            api_count: value.api_count as i64,
            static_count: value.static_count as i64,
            admin_count: value.admin_count as i64,
            challenge_count: value.challenge_count as i64,
            challenge_verified_count: value.challenge_verified_count as i64,
            fingerprint_seen: value.fingerprint_seen,
            human_confidence: i64::from(value.human_confidence),
            automation_risk: i64::from(value.automation_risk),
            probe_risk: i64::from(value.probe_risk),
            abuse_risk: i64::from(value.abuse_risk),
            false_positive_risk: value.false_positive_risk,
            state: value.state,
            summary_json,
            last_ai_review_at: Some(unix_timestamp()),
            ai_rationale: value.ai_rationale,
            expires_at: unix_timestamp() + VISITOR_WINDOW_SECS,
        }
    }
}

impl From<VisitorDecisionSignal> for AiVisitorDecisionUpsert {
    fn from(value: VisitorDecisionSignal) -> Self {
        Self {
            decision_key: value.decision_key,
            identity_key: value.identity_key,
            site_id: value.site_id,
            created_at: unix_timestamp(),
            action: value.action,
            confidence: i64::from(value.confidence),
            ttl_secs: value.ttl_secs as i64,
            rationale: value.rationale,
            applied: value.applied,
            effect_json: serde_json::json!({
                "status": value.effect_status,
            })
            .to_string(),
        }
    }
}
