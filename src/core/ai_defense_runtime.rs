use super::{
    unix_timestamp, AiDefenseDecision, AiDefenseIdentitySignal, AiDefenseL4Signal,
    AiDefensePolicySignal, AiDefensePortSignal, AiDefenseRouteProfileSignal, AiDefenseRunResult,
    AiDefenseRuntimePressureSignal, AiDefenseSignalSnapshot, AiDefenseUpstreamSignal,
    AiDefenseUserAgentSignal, LocalDefenseRecommendation, WafContext,
};
use crate::protocol::UnifiedHttpRequest;
use crate::storage::{
    AiRouteProfileEntry, AiRouteProfileUpsert, AiTempPolicyEffectStats, AiTempPolicyEntry,
    AiTempPolicyUpsert,
};
use anyhow::Result;

const MAX_AI_DEFENSE_IDENTITY_BUCKETS: usize = 8_192;
const MAX_AI_DEFENSE_DISTINCT_CLIENTS_PER_BUCKET: usize = 256;
const MAX_AI_DEFENSE_USER_AGENTS_PER_BUCKET: usize = 16;

impl WafContext {
    pub fn active_ai_route_profiles(&self) -> Vec<AiRouteProfileEntry> {
        self.ai_route_profiles
            .read()
            .expect("ai_route_profiles lock poisoned")
            .clone()
    }

    pub async fn refresh_ai_route_profiles(&self) -> Result<()> {
        let Some(store) = self.sqlite_store.as_ref() else {
            return Ok(());
        };
        let mut profiles = store
            .list_ai_route_profiles(None, Some("active"), 1_000)
            .await?;
        profiles.extend(
            store
                .list_ai_route_profiles(None, Some("approved"), 1_000)
                .await?,
        );
        let mut guard = self
            .ai_route_profiles
            .write()
            .expect("ai_route_profiles lock poisoned");
        *guard = profiles;
        Ok(())
    }

    pub(crate) fn note_ai_defense_route_trigger(
        &self,
        site_id: &str,
        route: &str,
        depth: &str,
        soft_events: u64,
        hard_events: u64,
        now: i64,
    ) {
        let config = self.config_snapshot().integrations.ai_audit;
        if !config.auto_defense_enabled || !config.auto_defense_auto_apply {
            return;
        }
        let mut guard = self
            .ai_defense_trigger_runtime
            .lock()
            .expect("ai_defense_trigger_runtime lock poisoned");
        if guard.last_trigger_at.is_some_and(|last| {
            now.saturating_sub(last) < config.auto_defense_trigger_cooldown_secs as i64
        }) {
            return;
        }
        guard.pending = true;
        guard.pending_since.get_or_insert(now);
        guard.last_trigger_at = Some(now);
        guard.pending_reason = Some(format!(
            "route_pressure:{}:{}:{}:soft={}:hard={}",
            site_id, route, depth, soft_events, hard_events
        ));
    }

    pub(crate) fn note_ai_defense_identity_signal(
        &self,
        site_id: &str,
        route: &str,
        request: &UnifiedHttpRequest,
        now: i64,
    ) {
        if !self
            .config_snapshot()
            .integrations
            .ai_audit
            .auto_defense_enabled
        {
            return;
        }
        if !ai_defense_route_allowed(route) {
            return;
        }
        let window_start = now.div_euclid(60) * 60;
        let key = ai_defense_identity_key(site_id, route);
        if !self.ensure_ai_defense_identity_capacity(&key, window_start) {
            return;
        }
        let entry = self
            .ai_defense_identity_buckets
            .entry(key)
            .or_insert_with(|| std::sync::Mutex::new(super::AiDefenseIdentityBucket::default()));
        let mut bucket = entry
            .lock()
            .expect("ai defense identity bucket lock poisoned");
        if bucket.window_start != window_start {
            *bucket = super::AiDefenseIdentityBucket {
                window_start,
                ..super::AiDefenseIdentityBucket::default()
            };
        }
        bucket.total_events = bucket.total_events.saturating_add(1);
        if metadata_true(request, "network.client_ip_unresolved") {
            bucket.unresolved_events = bucket.unresolved_events.saturating_add(1);
        }
        if metadata_true(request, "network.trusted_proxy_peer") {
            bucket.trusted_proxy_events = bucket.trusted_proxy_events.saturating_add(1);
        }
        if metadata_true(request, "l7.cc.challenge_verified") {
            bucket.verified_challenge_events = bucket.verified_challenge_events.saturating_add(1);
        }
        if metadata_true(request, "l7.cc.interactive_session") {
            bucket.interactive_session_events = bucket.interactive_session_events.saturating_add(1);
        }
        if request
            .get_metadata("network.identity_state")
            .is_some_and(|state| state == "spoofed_forward_header")
        {
            bucket.spoofed_forward_header_events =
                bucket.spoofed_forward_header_events.saturating_add(1);
        }
        if bucket.distinct_clients.len() < MAX_AI_DEFENSE_DISTINCT_CLIENTS_PER_BUCKET {
            if let Some(client) = request
                .client_ip
                .as_deref()
                .or_else(|| {
                    request
                        .get_metadata("network.client_ip")
                        .map(String::as_str)
                })
                .map(compact_identity_value)
            {
                bucket.distinct_clients.insert(client);
            }
        }
        if let Some(user_agent) = request
            .get_header("user-agent")
            .map(|value| compact_user_agent(value))
            .filter(|value| !value.is_empty())
        {
            if bucket.user_agents.contains_key(&user_agent)
                || bucket.user_agents.len() < MAX_AI_DEFENSE_USER_AGENTS_PER_BUCKET
            {
                *bucket.user_agents.entry(user_agent).or_insert(0) += 1;
            }
        }
    }

    pub(crate) fn consume_ai_auto_defense_trigger(&self, now: i64) -> Option<String> {
        let config = self.config_snapshot().integrations.ai_audit;
        if !config.auto_defense_enabled || !config.auto_defense_auto_apply {
            return None;
        }
        let mut guard = self
            .ai_defense_trigger_runtime
            .lock()
            .expect("ai_defense_trigger_runtime lock poisoned");
        if guard.pending {
            guard.pending = false;
            guard.last_run_at = Some(now);
            return guard
                .pending_reason
                .take()
                .or_else(|| Some("event_signal_threshold".to_string()));
        }
        let fallback_due = guard.last_run_at.is_some_and(|last| {
            now.saturating_sub(last) >= config.auto_defense_fallback_interval_secs as i64
        });
        if fallback_due {
            guard.last_run_at = Some(now);
            return Some("fallback_sweep".to_string());
        }
        None
    }

    pub async fn ai_defense_signal_snapshot(
        &self,
        now: i64,
        trigger_reason: Option<String>,
    ) -> Result<AiDefenseSignalSnapshot> {
        let config = self.config_snapshot();
        let max_active_temp_policy_count =
            config.integrations.ai_audit.max_active_temp_policies.max(1);
        let active_policies = match self.sqlite_store.as_ref() {
            Some(store) => store.list_active_ai_temp_policies(now).await?,
            None => Vec::new(),
        };
        let active_temp_policy_count = active_policies.len() as u32;
        let trigger_pending_secs = self
            .ai_defense_trigger_runtime
            .lock()
            .expect("ai_defense_trigger_runtime lock poisoned")
            .pending_since
            .map(|pending_since| now.saturating_sub(pending_since).max(0) as u64)
            .unwrap_or(0);
        let runtime_pressure = self.runtime_pressure_snapshot();
        let auto_tuning = self.auto_tuning_snapshot();
        let upstream = self.upstream_health_snapshot();

        Ok(AiDefenseSignalSnapshot {
            generated_at: now,
            sqlite_available: self.sqlite_store.is_some(),
            active_temp_policy_count,
            max_active_temp_policy_count,
            trigger_reason,
            trigger_pending_secs,
            runtime_pressure: AiDefenseRuntimePressureSignal {
                level: runtime_pressure.level.to_string(),
                defense_depth: runtime_pressure.defense_depth.to_string(),
                prefer_drop: runtime_pressure.prefer_drop,
                trim_event_persistence: runtime_pressure.trim_event_persistence,
                l7_friction_pressure_percent: auto_tuning
                    .last_observed_l7_friction_pressure_percent,
                identity_pressure_percent: auto_tuning
                    .last_observed_identity_resolution_pressure_percent,
                avg_proxy_latency_ms: auto_tuning.last_observed_avg_proxy_latency_ms,
            },
            l4_pressure: self.ai_defense_l4_signal(),
            upstream_health: AiDefenseUpstreamSignal {
                healthy: upstream.healthy,
                last_error: upstream.last_error,
            },
            active_policy_summaries: active_policies
                .iter()
                .map(ai_defense_policy_signal)
                .take(12)
                .collect(),
            identity_summaries: self.ai_defense_identity_summaries(now, 24),
            route_profiles: self.ai_defense_route_profile_signals(24),
            local_recommendations: self.local_defense_recommendations(24),
        })
    }

    pub async fn run_ai_auto_defense(
        &self,
        now: i64,
        trigger_reason: Option<String>,
    ) -> Result<AiDefenseRunResult> {
        let config = self.config_snapshot();
        let ai_config = config.integrations.ai_audit;
        if !ai_config.auto_defense_enabled {
            return Ok(AiDefenseRunResult {
                generated_at: now,
                trigger_reason,
                disabled_reason: Some("auto_defense_disabled".to_string()),
                ..AiDefenseRunResult::default()
            });
        }
        if !ai_config.auto_defense_auto_apply {
            return Ok(AiDefenseRunResult {
                generated_at: now,
                trigger_reason,
                disabled_reason: Some("auto_defense_auto_apply_disabled".to_string()),
                ..AiDefenseRunResult::default()
            });
        }

        let Some(store) = self.sqlite_store.as_ref() else {
            return Ok(AiDefenseRunResult {
                generated_at: now,
                trigger_reason,
                disabled_reason: Some("sqlite_unavailable".to_string()),
                ..AiDefenseRunResult::default()
            });
        };

        let snapshot = self
            .ai_defense_signal_snapshot(now, trigger_reason.clone())
            .await?;
        if !snapshot.sqlite_available {
            return Ok(AiDefenseRunResult {
                generated_at: now,
                trigger_reason,
                disabled_reason: Some("sqlite_unavailable".to_string()),
                ..AiDefenseRunResult::default()
            });
        }
        if snapshot.active_temp_policy_count >= snapshot.max_active_temp_policy_count {
            return Ok(AiDefenseRunResult {
                generated_at: now,
                trigger_reason,
                disabled_reason: Some("max_active_temp_policies_reached".to_string()),
                ..AiDefenseRunResult::default()
            });
        }

        let active_policies = store.list_active_ai_temp_policies(now).await?;
        let active_count = active_policies.len() as u32;
        let remaining_capacity = snapshot
            .max_active_temp_policy_count
            .saturating_sub(active_count);
        let max_apply = ai_config
            .auto_defense_max_apply_per_tick
            .min(remaining_capacity)
            .max(0) as usize;
        if max_apply == 0 {
            return Ok(AiDefenseRunResult {
                generated_at: now,
                trigger_reason,
                disabled_reason: Some("auto_defense_apply_budget_empty".to_string()),
                ..AiDefenseRunResult::default()
            });
        }

        let mut result = AiDefenseRunResult {
            generated_at: now,
            trigger_reason,
            ..AiDefenseRunResult::default()
        };
        let baseline = self.auto_tuning_snapshot();

        for recommendation in &snapshot.local_recommendations {
            let Some(decision) =
                ai_defense_decision_from_local_recommendation(&snapshot, recommendation)
            else {
                result.skipped += 1;
                continue;
            };
            if result.applied >= max_apply {
                result.skipped += 1;
                result.decisions.push(decision);
                continue;
            }
            if !ai_defense_decision_allowed(&decision, ai_config.auto_defense_min_confidence) {
                result.skipped += 1;
                result.decisions.push(decision);
                continue;
            }
            if active_policies.iter().any(|policy| {
                policy.policy_key == decision.key
                    && policy.scope_type == decision.scope_type
                    && policy.scope_value == decision.scope_value
                    && policy.suggested_value == decision.suggested_value
                    && policy.expires_at.saturating_sub(now) > 120
            }) {
                result.skipped += 1;
                result.decisions.push(decision);
                continue;
            }

            let ttl_secs = decision.ttl_secs.clamp(300, 1_800);
            store
                .upsert_ai_temp_policy(&AiTempPolicyUpsert {
                    source_report_id: None,
                    policy_key: decision.key.clone(),
                    title: decision.title.clone(),
                    policy_type: decision.action.clone(),
                    layer: decision.layer.clone(),
                    scope_type: decision.scope_type.clone(),
                    scope_value: decision.scope_value.clone(),
                    action: decision.action.clone(),
                    operator: decision.operator.clone(),
                    suggested_value: decision.suggested_value.clone(),
                    rationale: decision.rationale.clone(),
                    confidence: i64::from(decision.confidence),
                    auto_applied: true,
                    expires_at: now.saturating_add(ttl_secs as i64),
                    effect_stats: Some(AiTempPolicyEffectStats {
                        baseline_l7_friction_percent: Some(
                            baseline.last_observed_l7_friction_pressure_percent,
                        ),
                        baseline_identity_pressure_percent: Some(
                            baseline.last_observed_identity_resolution_pressure_percent,
                        ),
                        last_effectiveness_check_at: Some(unix_timestamp()),
                        ..AiTempPolicyEffectStats::default()
                    }),
                })
                .await?;
            result.applied += 1;
            result.decisions.push(decision);
        }

        if result.applied > 0 {
            self.refresh_ai_temp_policies().await?;
        }
        if result.applied > 0 || result.skipped > 0 {
            let mut guard = self
                .ai_defense_trigger_runtime
                .lock()
                .expect("ai_defense_trigger_runtime lock poisoned");
            guard.pending_since = None;
        }
        if let Err(err) = self
            .generate_ai_route_profile_candidates_from_snapshot(store.as_ref(), &snapshot, now)
            .await
        {
            log::warn!("Failed to generate AI route profile candidates: {}", err);
        }
        Ok(result)
    }

    async fn generate_ai_route_profile_candidates_from_snapshot(
        &self,
        store: &crate::storage::SqliteStore,
        snapshot: &AiDefenseSignalSnapshot,
        now: i64,
    ) -> Result<usize> {
        let existing = store
            .list_ai_route_profiles(None, None, 1_000)
            .await?
            .into_iter()
            .map(|profile| {
                (
                    profile.site_id,
                    profile.route_pattern,
                    profile.match_mode,
                    profile.status,
                )
            })
            .collect::<Vec<_>>();
        let mut generated = 0usize;
        for recommendation in &snapshot.local_recommendations {
            if generated >= 8 {
                break;
            }
            let relearn_after_rejected =
                existing
                    .iter()
                    .any(|(site_id, route_pattern, match_mode, status)| {
                        site_id == &recommendation.site_id
                            && route_pattern == &recommendation.route
                            && match_mode == "exact"
                            && status == "rejected"
                    });
            if existing
                .iter()
                .any(|(site_id, route_pattern, match_mode, status)| {
                    site_id == &recommendation.site_id
                        && route_pattern == &recommendation.route
                        && match_mode == "exact"
                        && status != "rejected"
                })
            {
                continue;
            }
            let identity = snapshot.identity_summaries.iter().find(|identity| {
                identity.site_id == recommendation.site_id && identity.route == recommendation.route
            });
            let candidate = infer_route_profile_candidate(
                recommendation,
                identity,
                now,
                relearn_after_rejected,
            );
            store.upsert_ai_route_profile(&candidate).await?;
            generated += 1;
        }
        Ok(generated)
    }

    fn ai_defense_l4_signal(&self) -> Option<AiDefenseL4Signal> {
        let stats = self.l4_inspector()?.get_statistics();
        let mut ports = stats
            .per_port_stats
            .values()
            .map(|port| AiDefensePortSignal {
                port: port.port.clone(),
                connections: port.connections,
                blocks: port.blocks,
                ddos_events: port.ddos_events,
            })
            .collect::<Vec<_>>();
        ports.sort_by(|left, right| {
            right
                .blocks
                .cmp(&left.blocks)
                .then_with(|| right.ddos_events.cmp(&left.ddos_events))
                .then_with(|| right.connections.cmp(&left.connections))
        });
        ports.truncate(5);
        Some(AiDefenseL4Signal {
            active_connections: stats.connections.active_connections,
            blocked_connections: stats.connections.blocked_connections,
            rate_limit_hits: stats.connections.rate_limit_hits,
            ddos_events: stats.ddos_events,
            protocol_anomalies: stats.protocol_anomalies,
            defense_actions: stats.defense_actions,
            top_ports: ports,
        })
    }

    fn ai_defense_identity_summaries(
        &self,
        now: i64,
        limit: usize,
    ) -> Vec<AiDefenseIdentitySignal> {
        let mut summaries = self
            .ai_defense_identity_buckets
            .iter()
            .filter_map(|entry| {
                let (site_id, route) = split_ai_defense_identity_key(entry.key())?;
                let bucket = entry
                    .value()
                    .lock()
                    .expect("ai defense identity bucket lock poisoned");
                if now.saturating_sub(bucket.window_start) > 75 {
                    return None;
                }
                let mut top_user_agents = bucket
                    .user_agents
                    .iter()
                    .map(|(value, count)| AiDefenseUserAgentSignal {
                        value: value.clone(),
                        count: *count,
                    })
                    .collect::<Vec<_>>();
                top_user_agents.sort_by(|left, right| right.count.cmp(&left.count));
                top_user_agents.truncate(5);
                Some(AiDefenseIdentitySignal {
                    site_id,
                    route,
                    total_events: bucket.total_events,
                    distinct_client_count: bucket.distinct_clients.len(),
                    unresolved_events: bucket.unresolved_events,
                    trusted_proxy_events: bucket.trusted_proxy_events,
                    verified_challenge_events: bucket.verified_challenge_events,
                    interactive_session_events: bucket.interactive_session_events,
                    spoofed_forward_header_events: bucket.spoofed_forward_header_events,
                    top_user_agents,
                })
            })
            .collect::<Vec<_>>();
        summaries.sort_by(|left, right| {
            right
                .total_events
                .cmp(&left.total_events)
                .then_with(|| right.distinct_client_count.cmp(&left.distinct_client_count))
        });
        summaries.truncate(limit);
        summaries
    }

    fn ai_defense_route_profile_signals(&self, limit: usize) -> Vec<AiDefenseRouteProfileSignal> {
        self.active_ai_route_profiles()
            .into_iter()
            .take(limit)
            .map(ai_defense_route_profile_signal)
            .collect()
    }

    fn ensure_ai_defense_identity_capacity(&self, key: &str, window_start: i64) -> bool {
        if self.ai_defense_identity_buckets.contains_key(key)
            || self.ai_defense_identity_buckets.len() < MAX_AI_DEFENSE_IDENTITY_BUCKETS
        {
            return true;
        }
        let stale_before = window_start.saturating_sub(120);
        let stale_keys = self
            .ai_defense_identity_buckets
            .iter()
            .filter_map(|entry| {
                let bucket = entry
                    .value()
                    .lock()
                    .expect("ai defense identity bucket lock poisoned");
                (bucket.window_start < stale_before).then(|| entry.key().clone())
            })
            .take(256)
            .collect::<Vec<_>>();
        for stale_key in stale_keys {
            self.ai_defense_identity_buckets.remove(&stale_key);
        }
        self.ai_defense_identity_buckets.len() < MAX_AI_DEFENSE_IDENTITY_BUCKETS
    }
}

fn ai_defense_decision_from_local_recommendation(
    snapshot: &AiDefenseSignalSnapshot,
    recommendation: &LocalDefenseRecommendation,
) -> Option<AiDefenseDecision> {
    if recommendation.action != "tighten_route_cc" {
        return None;
    }
    if !ai_defense_route_allowed(&recommendation.route) {
        return None;
    }
    let mut confidence = recommendation.confidence;
    if snapshot.l4_pressure.as_ref().is_some_and(|l4| {
        l4.blocked_connections > 0 || l4.rate_limit_hits > 0 || l4.ddos_events > 0
    }) {
        confidence = confidence.saturating_add(4).min(100);
    }
    if snapshot.runtime_pressure.defense_depth == "survival" {
        confidence = confidence.saturating_add(3).min(100);
    }
    if let Some(identity) = snapshot.identity_summaries.iter().find(|identity| {
        identity.site_id == recommendation.site_id && identity.route == recommendation.route
    }) {
        if identity.distinct_client_count >= 8 && identity.interactive_session_events == 0 {
            confidence = confidence.saturating_add(5).min(100);
        }
        if identity.spoofed_forward_header_events > 0 {
            confidence = confidence.saturating_add(6).min(100);
        }
        if identity.verified_challenge_events.saturating_mul(2) >= identity.total_events
            || identity.interactive_session_events.saturating_mul(2) >= identity.total_events
        {
            confidence = confidence.saturating_sub(10);
        }
        if identity.unresolved_events.saturating_mul(2) >= identity.total_events
            && identity.distinct_client_count <= 2
        {
            confidence = confidence.saturating_sub(6);
        }
    }
    let route_profile = best_route_profile_for_recommendation(snapshot, recommendation);
    if let Some(profile) = route_profile {
        if profile
            .avoid_actions
            .iter()
            .any(|action| action == &recommendation.action)
        {
            confidence = confidence.saturating_sub(20);
        }
        if profile
            .recommended_actions
            .iter()
            .any(|action| action == &recommendation.action)
        {
            confidence = confidence.saturating_add(4).min(100);
        }
        if matches!(profile.sensitivity.as_str(), "critical" | "high") {
            confidence = confidence.saturating_add(2).min(100);
        }
    }
    if !snapshot.upstream_health.healthy {
        confidence = confidence.saturating_sub(8);
    }

    Some(AiDefenseDecision {
        key: format!("ai_auto_defense:{}", recommendation.key),
        title: format!("AI auto defense for {}", recommendation.route),
        layer: "l7".to_string(),
        scope_type: "route".to_string(),
        scope_value: recommendation.route.clone(),
        action: recommendation.action.clone(),
        operator: "exact".to_string(),
        suggested_value: recommendation.suggested_value.clone(),
        ttl_secs: recommendation.ttl_secs,
        confidence,
        auto_apply: true,
        rationale: format!(
            "{}; auto-applied by local AI defense guardrails for site {}; trigger={}; runtime_depth={}; upstream_healthy={}; route_profile={}",
            recommendation.rationale,
            recommendation.site_id,
            snapshot
                .trigger_reason
                .as_deref()
                .unwrap_or("unknown"),
            snapshot.runtime_pressure.defense_depth,
            snapshot.upstream_health.healthy,
            route_profile
                .map(|profile| profile.route_type.as_str())
                .unwrap_or("unknown")
        ),
    })
}

fn best_route_profile_for_recommendation<'a>(
    snapshot: &'a AiDefenseSignalSnapshot,
    recommendation: &LocalDefenseRecommendation,
) -> Option<&'a AiDefenseRouteProfileSignal> {
    snapshot
        .route_profiles
        .iter()
        .filter(|profile| {
            profile.site_id == recommendation.site_id
                && route_profile_matches(profile, &recommendation.route)
        })
        .max_by(|left, right| {
            profile_match_rank(left)
                .cmp(&profile_match_rank(right))
                .then_with(|| left.confidence.cmp(&right.confidence))
        })
}

fn route_profile_matches(profile: &AiDefenseRouteProfileSignal, route: &str) -> bool {
    match profile.match_mode.as_str() {
        "prefix" | "starts_with" => route.starts_with(&profile.route_pattern),
        "wildcard" if profile.route_pattern.ends_with('*') => {
            route.starts_with(profile.route_pattern.trim_end_matches('*'))
        }
        _ => route == profile.route_pattern,
    }
}

fn profile_match_rank(profile: &AiDefenseRouteProfileSignal) -> u8 {
    match profile.match_mode.as_str() {
        "exact" => 3,
        "prefix" | "starts_with" => 2,
        "wildcard" => 1,
        _ => 0,
    }
}

fn infer_route_profile_candidate(
    recommendation: &LocalDefenseRecommendation,
    identity: Option<&AiDefenseIdentitySignal>,
    now: i64,
    relearn_after_rejected: bool,
) -> AiRouteProfileUpsert {
    let route_lower = recommendation.route.to_ascii_lowercase();
    let mut route_type = "unknown";
    let mut sensitivity = "unknown";
    let mut auth_required = "unknown";
    let mut normal_traffic_pattern = "unknown";
    let mut recommended_actions = vec!["tighten_route_cc".to_string()];
    let mut avoid_actions = Vec::<String>::new();
    let mut confidence = 55i64;

    if route_lower.contains("login")
        || route_lower.contains("signin")
        || route_lower.contains("auth")
        || route_lower.contains("token")
        || route_lower.contains("sso")
    {
        route_type = "authentication";
        sensitivity = "high";
        auth_required = "false";
        normal_traffic_pattern = "interactive";
        recommended_actions.push("increase_challenge".to_string());
        avoid_actions.push("add_temp_block".to_string());
        confidence += 18;
    } else if route_lower.contains("callback")
        || route_lower.contains("webhook")
        || route_lower.contains("notify")
    {
        route_type = "callback";
        sensitivity = "high";
        normal_traffic_pattern = "machine_to_machine";
        avoid_actions.push("increase_challenge".to_string());
        avoid_actions.push("increase_delay".to_string());
        recommended_actions.push("raise_identity_risk".to_string());
        confidence += 14;
    } else if route_lower.starts_with("/api/")
        || route_lower.contains("/api/")
        || route_lower.contains("graphql")
    {
        route_type = "api";
        sensitivity = "medium";
        normal_traffic_pattern = "api";
        recommended_actions.push("raise_identity_risk".to_string());
        confidence += 10;
    } else if route_lower.contains("admin")
        || route_lower.contains("console")
        || route_lower.contains("dashboard")
    {
        route_type = "admin";
        sensitivity = "critical";
        auth_required = "true";
        normal_traffic_pattern = "interactive";
        recommended_actions.push("increase_challenge".to_string());
        avoid_actions.push("add_temp_block".to_string());
        confidence += 18;
    }

    if let Some(identity) = identity {
        if identity.distinct_client_count >= 8 {
            confidence += 6;
        }
        if identity.verified_challenge_events.saturating_mul(2) >= identity.total_events
            || identity.interactive_session_events.saturating_mul(2) >= identity.total_events
        {
            normal_traffic_pattern = "interactive";
            confidence += 4;
        }
        if identity.unresolved_events.saturating_mul(2) >= identity.total_events {
            auth_required = "unknown";
            confidence -= 4;
        }
    }
    if recommendation.defense_depth == "survival" {
        confidence += 6;
    }
    if relearn_after_rejected {
        confidence -= 6;
    }

    recommended_actions.sort();
    recommended_actions.dedup();
    avoid_actions.sort();
    avoid_actions.dedup();

    let evidence_json = serde_json::json!({
        "learning_mode": if relearn_after_rejected {
            "relearn_after_rejected"
        } else {
            "observed_candidate"
        },
        "observed_at": now,
        "route_pressure": {
            "defense_depth": recommendation.defense_depth,
            "soft_events": recommendation.soft_events,
            "hard_events": recommendation.hard_events,
            "total_events": recommendation.total_events,
            "recommended_action": recommendation.action,
            "suggested_value": recommendation.suggested_value,
            "ttl_secs": recommendation.ttl_secs,
            "local_confidence": recommendation.confidence,
            "rationale": recommendation.rationale,
        },
        "identity": identity.map(|identity| serde_json::json!({
            "total_events": identity.total_events,
            "distinct_client_count": identity.distinct_client_count,
            "unresolved_events": identity.unresolved_events,
            "trusted_proxy_events": identity.trusted_proxy_events,
            "verified_challenge_events": identity.verified_challenge_events,
            "interactive_session_events": identity.interactive_session_events,
            "spoofed_forward_header_events": identity.spoofed_forward_header_events,
            "top_user_agents": identity.top_user_agents.iter().map(|ua| serde_json::json!({
                "value": &ua.value,
                "count": ua.count,
            })).collect::<Vec<_>>(),
        })),
        "confidence_inputs": {
            "route_name_heuristic": route_type,
            "sensitivity": sensitivity,
            "auth_required": auth_required,
            "normal_traffic_pattern": normal_traffic_pattern,
            "relearn_penalty_applied": relearn_after_rejected,
        }
    });

    AiRouteProfileUpsert {
        site_id: recommendation.site_id.clone(),
        route_pattern: recommendation.route.clone(),
        match_mode: "exact".to_string(),
        route_type: route_type.to_string(),
        sensitivity: sensitivity.to_string(),
        auth_required: auth_required.to_string(),
        normal_traffic_pattern: normal_traffic_pattern.to_string(),
        recommended_actions,
        avoid_actions,
        evidence_json: evidence_json.to_string(),
        confidence: confidence.clamp(0, 100),
        source: if relearn_after_rejected {
            "local_ai_relearned".to_string()
        } else {
            "local_ai_observed".to_string()
        },
        status: "candidate".to_string(),
        rationale: format!(
            "local AI inferred route profile from {} defense depth with {} total events and {} hard events{}",
            recommendation.defense_depth,
            recommendation.total_events,
            recommendation.hard_events,
            if relearn_after_rejected {
                "; regenerated after previous rejection"
            } else {
                ""
            }
        ),
        last_observed_at: Some(now),
        reviewed_at: None,
    }
}

fn ai_defense_identity_key(site_id: &str, route: &str) -> String {
    format!("{}|{}", site_id, route)
}

fn split_ai_defense_identity_key(value: &str) -> Option<(String, String)> {
    let (site_id, route) = value.split_once('|')?;
    Some((site_id.to_string(), route.to_string()))
}

fn metadata_true(request: &UnifiedHttpRequest, key: &str) -> bool {
    request
        .get_metadata(key)
        .is_some_and(|value| value == "true" || value == "1")
}

fn compact_identity_value(value: &str) -> String {
    value.chars().take(96).collect()
}

fn compact_user_agent(value: &str) -> String {
    let normalized = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if normalized.len() <= 96 {
        normalized
    } else {
        normalized.chars().take(96).collect()
    }
}

fn ai_defense_policy_signal(policy: &AiTempPolicyEntry) -> AiDefensePolicySignal {
    AiDefensePolicySignal {
        policy_key: policy.policy_key.clone(),
        scope_type: policy.scope_type.clone(),
        scope_value: policy.scope_value.clone(),
        action: policy.action.clone(),
        hit_count: policy.hit_count,
        expires_at: policy.expires_at,
    }
}

fn ai_defense_route_profile_signal(profile: AiRouteProfileEntry) -> AiDefenseRouteProfileSignal {
    let raw_confidence = profile.confidence;
    let (confidence, staleness_secs) = route_profile_effective_confidence(&profile);
    AiDefenseRouteProfileSignal {
        site_id: profile.site_id,
        route_pattern: profile.route_pattern,
        match_mode: profile.match_mode,
        route_type: profile.route_type,
        sensitivity: profile.sensitivity,
        auth_required: profile.auth_required,
        normal_traffic_pattern: profile.normal_traffic_pattern,
        recommended_actions: serde_json::from_str(&profile.recommended_actions_json)
            .unwrap_or_default(),
        avoid_actions: serde_json::from_str(&profile.avoid_actions_json).unwrap_or_default(),
        evidence: serde_json::from_str(&profile.evidence_json)
            .unwrap_or_else(|_| serde_json::json!({})),
        raw_confidence,
        staleness_secs,
        confidence,
        source: profile.source,
        status: profile.status,
        rationale: profile.rationale,
    }
}

fn route_profile_effective_confidence(profile: &AiRouteProfileEntry) -> (i64, Option<u64>) {
    let Some(last_observed_at) = profile.last_observed_at else {
        return (profile.confidence, None);
    };
    let staleness_secs = unix_timestamp().saturating_sub(last_observed_at).max(0) as u64;
    let grace_days = if profile.reviewed_at.is_some() {
        30
    } else {
        14
    };
    let stale_days = staleness_secs / 86_400;
    let penalty = stale_days
        .saturating_sub(grace_days)
        .saturating_mul(2)
        .min(30) as i64;
    (
        profile.confidence.saturating_sub(penalty).clamp(0, 100),
        Some(staleness_secs),
    )
}

fn ai_defense_decision_allowed(decision: &AiDefenseDecision, min_confidence: u32) -> bool {
    decision.auto_apply
        && decision.confidence as u32 >= min_confidence
        && matches!(
            decision.action.as_str(),
            "tighten_route_cc"
                | "tighten_host_cc"
                | "increase_delay"
                | "increase_challenge"
                | "raise_identity_risk"
                | "add_behavior_watch"
        )
        && decision.layer == "l7"
        && decision.scope_type == "route"
        && ai_defense_route_allowed(&decision.scope_value)
}

fn ai_defense_route_allowed(route: &str) -> bool {
    route.starts_with('/')
        && route != "/"
        && route.len() <= 256
        && !route.contains("..")
        && route != "/favicon.ico"
        && route != "/robots.txt"
        && route != "/sitemap.xml"
        && !route.starts_with("/.well-known/")
        && !route.starts_with("/assets/")
        && !route.starts_with("/static/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ai_defense_rejects_broad_or_static_routes() {
        assert!(!ai_defense_route_allowed("/"));
        assert!(!ai_defense_route_allowed("/static/app.js"));
        assert!(!ai_defense_route_allowed("/assets/app.css"));
        assert!(!ai_defense_route_allowed("/../admin"));
        assert!(ai_defense_route_allowed("/api/login"));
    }

    #[test]
    fn ai_defense_decision_respects_confidence_guardrail() {
        let mut decision = AiDefenseDecision {
            key: "test".to_string(),
            title: "test".to_string(),
            layer: "l7".to_string(),
            scope_type: "route".to_string(),
            scope_value: "/api/login".to_string(),
            action: "tighten_route_cc".to_string(),
            operator: "exact".to_string(),
            suggested_value: "45".to_string(),
            ttl_secs: 900,
            confidence: 81,
            auto_apply: true,
            rationale: "test".to_string(),
        };

        assert!(!ai_defense_decision_allowed(&decision, 82));
        decision.confidence = 82;
        assert!(ai_defense_decision_allowed(&decision, 82));
        decision.action = "add_temp_block".to_string();
        assert!(!ai_defense_decision_allowed(&decision, 82));
    }

    #[tokio::test]
    async fn ai_defense_snapshot_includes_operational_context() {
        let config = crate::config::Config {
            sqlite_enabled: false,
            ..crate::config::Config::default()
        };
        let context = WafContext::new(config).await.unwrap();
        context.set_upstream_health(false, Some("timeout".to_string()));

        let snapshot = context
            .ai_defense_signal_snapshot(123, Some("test_trigger".to_string()))
            .await
            .unwrap();

        assert_eq!(snapshot.generated_at, 123);
        assert_eq!(snapshot.trigger_reason.as_deref(), Some("test_trigger"));
        assert_eq!(snapshot.runtime_pressure.level, "normal");
        assert!(!snapshot.upstream_health.healthy);
        assert_eq!(
            snapshot.upstream_health.last_error.as_deref(),
            Some("timeout")
        );
        assert!(snapshot.active_policy_summaries.is_empty());
    }

    #[tokio::test]
    async fn ai_defense_snapshot_includes_identity_profile() {
        let config = crate::config::Config {
            sqlite_enabled: false,
            ..crate::config::Config::default()
        };
        let context = WafContext::new(config).await.unwrap();
        let result =
            crate::core::InspectionResult::drop(crate::core::InspectionLayer::L7, "route pressure");

        for idx in 0..3 {
            let mut request = UnifiedHttpRequest::new(
                crate::protocol::HttpVersion::Http1_1,
                "POST".to_string(),
                "/api/login".to_string(),
            );
            request.set_client_ip(format!("203.0.113.{}", idx + 10));
            request.add_header("User-Agent".to_string(), "UnitTest/1.0".to_string());
            request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
            if idx == 0 {
                request.add_metadata(
                    "network.identity_state".to_string(),
                    "spoofed_forward_header".to_string(),
                );
            }
            context.note_site_defense_signal(&request, &result);
        }

        let snapshot = context
            .ai_defense_signal_snapshot(unix_timestamp(), Some("test".to_string()))
            .await
            .unwrap();
        let identity = snapshot
            .identity_summaries
            .iter()
            .find(|item| item.site_id == "site-a" && item.route == "/api/login")
            .expect("identity profile should be present");

        assert_eq!(identity.total_events, 3);
        assert_eq!(identity.distinct_client_count, 3);
        assert_eq!(identity.spoofed_forward_header_events, 1);
        assert_eq!(identity.top_user_agents[0].value, "UnitTest/1.0");
        assert_eq!(identity.top_user_agents[0].count, 3);
    }
}
