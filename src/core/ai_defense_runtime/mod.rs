use super::{
    unix_timestamp, AiDefenseDecision, AiDefenseIdentitySignal, AiDefenseL4Signal,
    AiDefensePolicyEffectSignal, AiDefensePolicySignal, AiDefensePortSignal,
    AiDefenseRouteEffectSignal, AiDefenseRouteProfileSignal, AiDefenseRunResult,
    AiDefenseRuntimePressureSignal, AiDefenseSignalSnapshot, AiDefenseUpstreamSignal,
    AiDefenseUserAgentSignal, AiRouteResultObservation, LocalDefenseRecommendation, WafContext,
};
use crate::protocol::UnifiedHttpRequest;
use crate::storage::{
    AiRouteProfileEntry, AiRouteProfileUpsert, AiTempPolicyEffectStats, AiTempPolicyEntry,
    AiTempPolicyOutcomeRecord, AiTempPolicyUpsert,
};
use anyhow::Result;

mod helpers;

#[cfg(test)]
mod tests;

use helpers::*;

const MAX_AI_DEFENSE_IDENTITY_BUCKETS: usize = 8_192;
const MAX_AI_DEFENSE_DISTINCT_CLIENTS_PER_BUCKET: usize = 256;
const MAX_AI_DEFENSE_USER_AGENTS_PER_BUCKET: usize = 16;
const MAX_AI_ROUTE_RESULT_BUCKETS: usize = 8_192;

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

    pub fn note_ai_route_result(
        &self,
        request: &UnifiedHttpRequest,
        observation: AiRouteResultObservation,
    ) {
        self.note_visitor_route_result(request, &observation);
        if !self
            .config_snapshot()
            .integrations
            .ai_audit
            .auto_defense_enabled
        {
            return;
        }
        let Some(site_id) = request.get_metadata("gateway.site_id").cloned() else {
            return;
        };
        let route = ai_runtime_route_path(&request.uri);
        if !ai_defense_route_allowed(&route) {
            return;
        }
        let now = unix_timestamp();
        let window_start = now.div_euclid(60) * 60;
        let key = ai_defense_identity_key(&site_id, &route);
        if !self.ensure_ai_route_result_capacity(&key, window_start) {
            return;
        }
        let entry = self
            .ai_route_result_buckets
            .entry(key)
            .or_insert_with(|| std::sync::Mutex::new(super::AiRouteResultBucket::default()));
        let mut bucket = entry.lock().expect("ai route result bucket lock poisoned");
        if bucket.window_start != window_start {
            *bucket = super::AiRouteResultBucket {
                window_start,
                ..super::AiRouteResultBucket::default()
            };
        }
        bucket.total_responses = bucket.total_responses.saturating_add(1);
        if observation.upstream_error {
            bucket.upstream_errors = bucket.upstream_errors.saturating_add(1);
        } else if !observation.local_response {
            bucket.upstream_successes = bucket.upstream_successes.saturating_add(1);
        }
        if observation.local_response {
            bucket.local_responses = bucket.local_responses.saturating_add(1);
        }
        if observation.blocked {
            bucket.blocked_responses = bucket.blocked_responses.saturating_add(1);
        }
        let challenge_issued = metadata_true(request, "ai.cc.force_challenge")
            || request
                .get_metadata("l7.enforcement")
                .is_some_and(|value| value == "challenge")
            || request
                .get_metadata("ai.policy.matched_actions")
                .is_some_and(|value| {
                    value
                        .split(',')
                        .any(|action| action == "increase_challenge")
                });
        let challenge_verified = metadata_true(request, "l7.cc.challenge_verified");
        let interactive_session = metadata_true(request, "l7.cc.interactive_session");
        if challenge_issued {
            bucket.challenge_issued = bucket.challenge_issued.saturating_add(1);
        }
        if challenge_verified {
            bucket.challenge_verified = bucket.challenge_verified.saturating_add(1);
        }
        if interactive_session {
            bucket.interactive_sessions = bucket.interactive_sessions.saturating_add(1);
        }
        let policy_matched = request.get_metadata("ai.policy.matched_ids").is_some();
        if policy_matched {
            bucket.policy_matched_responses = bucket.policy_matched_responses.saturating_add(1);
            if let Some(actions) = request.get_metadata("ai.policy.matched_actions") {
                for action in actions.split(',').filter(|value| !value.trim().is_empty()) {
                    *bucket
                        .policy_actions
                        .entry(action.trim().to_string())
                        .or_insert(0) += 1;
                }
            }
        }
        let suspected_false_positive = policy_matched
            && (challenge_verified || interactive_session)
            && matches!(observation.status_code, 401 | 403 | 429);
        if suspected_false_positive {
            bucket.suspected_false_positive_events =
                bucket.suspected_false_positive_events.saturating_add(1);
        }
        let family = format!("{}xx", observation.status_code / 100);
        *bucket.status_families.entry(family).or_insert(0) += 1;
        *bucket
            .status_codes
            .entry(observation.status_code.to_string())
            .or_insert(0) += 1;
        if let Some(latency_ms) = observation.latency_ms {
            bucket.latency_samples = bucket.latency_samples.saturating_add(1);
            bucket.latency_ms_total = bucket.latency_ms_total.saturating_add(latency_ms);
            if latency_ms >= 1_000 {
                bucket.slow_responses = bucket.slow_responses.saturating_add(1);
            }
        }
        drop(bucket);

        self.record_ai_temp_policy_outcomes(
            request,
            observation,
            challenge_issued,
            challenge_verified,
            interactive_session,
            suspected_false_positive,
        );
    }

    pub(crate) fn consume_ai_auto_defense_trigger(&self, now: i64) -> Option<String> {
        let config = self.config_snapshot().integrations.ai_audit;
        if !config.auto_defense_enabled || !config.auto_defense_auto_apply {
            return None;
        }
        let recommendation_trigger = self
            .local_defense_recommendations(1)
            .into_iter()
            .find(|recommendation| {
                recommendation.confidence >= config.auto_defense_min_confidence as u8
                    && recommendation.total_events >= 12
                    && (recommendation.hard_events >= 4 || recommendation.total_events >= 24)
            })
            .map(|recommendation| {
                format!(
                    "local_recommendation_threshold:{}:{}:confidence={}:total={}:hard={}",
                    recommendation.site_id,
                    recommendation.route,
                    recommendation.confidence,
                    recommendation.total_events,
                    recommendation.hard_events
                )
            });
        let visitor_trigger = self
            .visitor_intelligence_snapshot(4)
            .recommendations
            .into_iter()
            .find(|decision| decision.confidence >= config.auto_defense_min_confidence as u8)
            .map(|decision| {
                format!(
                    "visitor_intelligence:{}:{}:confidence={}",
                    decision.action, decision.identity_key, decision.confidence
                )
            });
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
        if let Some(reason) = recommendation_trigger {
            if !guard.last_trigger_at.is_some_and(|last| {
                now.saturating_sub(last) < config.auto_defense_trigger_cooldown_secs as i64
            }) {
                guard.last_trigger_at = Some(now);
                guard.last_run_at = Some(now);
                guard.pending_since = None;
                return Some(reason);
            }
        }
        if let Some(reason) = visitor_trigger {
            if !guard.last_trigger_at.is_some_and(|last| {
                now.saturating_sub(last) < config.auto_defense_trigger_cooldown_secs as i64
            }) {
                guard.last_trigger_at = Some(now);
                guard.last_run_at = Some(now);
                guard.pending_since = None;
                return Some(reason);
            }
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
            route_effects: self.ai_defense_route_effect_signals(now, 24),
            policy_effects: active_policies
                .iter()
                .filter_map(ai_defense_policy_effect_signal)
                .take(24)
                .collect(),
            route_profiles: self.ai_defense_route_profile_signals(24),
            local_recommendations: self.local_defense_recommendations(24),
            server_public_ips: self.server_public_ip_snapshot(),
            visitor_intelligence: self.visitor_intelligence_snapshot(24),
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
        let active_policies = store.list_active_ai_temp_policies(now).await?;
        let revoked = self
            .auto_revoke_harmful_ai_temp_policies(store.as_ref(), &active_policies, now)
            .await?;
        let active_policies = if revoked > 0 {
            self.refresh_ai_temp_policies().await?;
            store.list_active_ai_temp_policies(now).await?
        } else {
            active_policies
        };
        let active_count = active_policies.len() as u32;
        if active_count >= snapshot.max_active_temp_policy_count {
            return Ok(AiDefenseRunResult {
                generated_at: now,
                trigger_reason,
                disabled_reason: Some("max_active_temp_policies_reached".to_string()),
                ..AiDefenseRunResult::default()
            });
        }
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
        let visitor_applied = self
            .apply_visitor_intelligence_decisions(
                store.as_ref(),
                &snapshot.visitor_intelligence.recommendations,
                now,
                max_apply.saturating_sub(result.applied),
            )
            .await?;
        result.applied += visitor_applied;
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
        self.persist_visitor_intelligence_snapshot(48);
        Ok(result)
    }

    async fn apply_visitor_intelligence_decisions(
        &self,
        store: &crate::storage::SqliteStore,
        decisions: &[super::VisitorDecisionSignal],
        now: i64,
        max_apply: usize,
    ) -> Result<usize> {
        let mut applied = 0usize;
        for decision in decisions {
            store
                .upsert_ai_visitor_decision(&crate::storage::AiVisitorDecisionUpsert {
                    decision_key: decision.decision_key.clone(),
                    identity_key: decision.identity_key.clone(),
                    site_id: decision.site_id.clone(),
                    created_at: now,
                    action: decision.action.clone(),
                    confidence: i64::from(decision.confidence),
                    ttl_secs: decision.ttl_secs as i64,
                    rationale: decision.rationale.clone(),
                    applied: false,
                    effect_json: serde_json::json!({"status":"observed"}).to_string(),
                })
                .await?;
            if applied >= max_apply {
                continue;
            }
            let Some((policy_action, suggested_value)) =
                visitor_decision_policy_action(&decision.action)
            else {
                continue;
            };
            store
                .upsert_ai_temp_policy(&AiTempPolicyUpsert {
                    source_report_id: None,
                    policy_key: format!("ai_visitor:{}", decision.decision_key),
                    title: format!("AI visitor intelligence: {}", decision.action),
                    policy_type: policy_action.to_string(),
                    layer: "L7".to_string(),
                    scope_type: "identity".to_string(),
                    scope_value: decision.identity_key.clone(),
                    action: policy_action.to_string(),
                    operator: "exact".to_string(),
                    suggested_value: suggested_value.to_string(),
                    rationale: decision.rationale.clone(),
                    confidence: i64::from(decision.confidence),
                    auto_applied: true,
                    expires_at: now.saturating_add(decision.ttl_secs as i64),
                    effect_stats: Some(AiTempPolicyEffectStats {
                        last_effectiveness_check_at: Some(now),
                        ..AiTempPolicyEffectStats::default()
                    }),
                })
                .await?;
            store
                .upsert_ai_visitor_decision(&crate::storage::AiVisitorDecisionUpsert {
                    decision_key: decision.decision_key.clone(),
                    identity_key: decision.identity_key.clone(),
                    site_id: decision.site_id.clone(),
                    created_at: now,
                    action: decision.action.clone(),
                    confidence: i64::from(decision.confidence),
                    ttl_secs: decision.ttl_secs as i64,
                    rationale: decision.rationale.clone(),
                    applied: true,
                    effect_json:
                        serde_json::json!({"status":"applied","policy_action":policy_action})
                            .to_string(),
                })
                .await?;
            applied += 1;
        }
        if applied > 0 {
            self.refresh_ai_temp_policies().await?;
        }
        Ok(applied)
    }

    async fn auto_revoke_harmful_ai_temp_policies(
        &self,
        store: &crate::storage::SqliteStore,
        policies: &[AiTempPolicyEntry],
        now: i64,
    ) -> Result<usize> {
        let mut revoked = 0usize;
        for policy in policies {
            if !policy.auto_applied {
                continue;
            }
            let mut effect = serde_json::from_str::<AiTempPolicyEffectStats>(&policy.effect_json)
                .unwrap_or_default();
            let harmful = effect.outcome_status.as_deref() == Some("harmful")
                || effect.suspected_false_positive_events >= 3
                || (effect.post_policy_observations >= 5
                    && effect.post_policy_upstream_errors.saturating_mul(2)
                        >= effect.post_policy_observations);
            if !harmful {
                continue;
            }
            effect.auto_revoked = true;
            effect.auto_revoke_reason = Some(format!(
                "AI effect feedback marked policy harmful: false_positive_events={}, upstream_errors={}, observations={}",
                effect.suspected_false_positive_events,
                effect.post_policy_upstream_errors,
                effect.post_policy_observations
            ));
            effect.outcome_status = Some("harmful".to_string());
            if store
                .revoke_ai_temp_policy_with_effect(policy.id, &effect, now)
                .await?
            {
                revoked += 1;
            }
        }
        Ok(revoked)
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
            let route_effect = snapshot.route_effects.iter().find(|effect| {
                effect.site_id == recommendation.site_id && effect.route == recommendation.route
            });
            let candidate = infer_route_profile_candidate(
                recommendation,
                identity,
                route_effect,
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

    fn ai_defense_route_effect_signals(
        &self,
        now: i64,
        limit: usize,
    ) -> Vec<AiDefenseRouteEffectSignal> {
        let mut signals = self
            .ai_route_result_buckets
            .iter()
            .filter_map(|entry| {
                let (site_id, route) = split_ai_defense_identity_key(entry.key())?;
                let bucket = entry
                    .value()
                    .lock()
                    .expect("ai route result bucket lock poisoned");
                if now.saturating_sub(bucket.window_start) > 75 {
                    return None;
                }
                let false_positive_risk = classify_false_positive_risk(
                    bucket.total_responses,
                    bucket.suspected_false_positive_events,
                    bucket.challenge_verified,
                    bucket.interactive_sessions,
                    bucket.blocked_responses,
                );
                let effectiveness_hint = classify_route_effectiveness(&bucket);
                Some(AiDefenseRouteEffectSignal {
                    site_id,
                    route,
                    total_responses: bucket.total_responses,
                    upstream_successes: bucket.upstream_successes,
                    upstream_errors: bucket.upstream_errors,
                    local_responses: bucket.local_responses,
                    blocked_responses: bucket.blocked_responses,
                    challenge_issued: bucket.challenge_issued,
                    challenge_verified: bucket.challenge_verified,
                    interactive_sessions: bucket.interactive_sessions,
                    policy_matched_responses: bucket.policy_matched_responses,
                    suspected_false_positive_events: bucket.suspected_false_positive_events,
                    status_families: bucket.status_families.clone(),
                    status_codes: bucket.status_codes.clone(),
                    policy_actions: bucket.policy_actions.clone(),
                    avg_latency_ms: (bucket.latency_samples > 0)
                        .then(|| bucket.latency_ms_total / bucket.latency_samples),
                    slow_responses: bucket.slow_responses,
                    false_positive_risk: false_positive_risk.to_string(),
                    effectiveness_hint: effectiveness_hint.to_string(),
                })
            })
            .collect::<Vec<_>>();
        signals.sort_by(|left, right| {
            right
                .suspected_false_positive_events
                .cmp(&left.suspected_false_positive_events)
                .then_with(|| right.upstream_errors.cmp(&left.upstream_errors))
                .then_with(|| right.total_responses.cmp(&left.total_responses))
        });
        signals.truncate(limit);
        signals
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

    fn ensure_ai_route_result_capacity(&self, key: &str, window_start: i64) -> bool {
        if self.ai_route_result_buckets.contains_key(key)
            || self.ai_route_result_buckets.len() < MAX_AI_ROUTE_RESULT_BUCKETS
        {
            return true;
        }
        let stale_before = window_start.saturating_sub(120);
        let stale_keys = self
            .ai_route_result_buckets
            .iter()
            .filter_map(|entry| {
                let bucket = entry
                    .value()
                    .lock()
                    .expect("ai route result bucket lock poisoned");
                (bucket.window_start < stale_before).then(|| entry.key().clone())
            })
            .take(256)
            .collect::<Vec<_>>();
        for stale_key in stale_keys {
            self.ai_route_result_buckets.remove(&stale_key);
        }
        self.ai_route_result_buckets.len() < MAX_AI_ROUTE_RESULT_BUCKETS
    }

    fn record_ai_temp_policy_outcomes(
        &self,
        request: &UnifiedHttpRequest,
        observation: AiRouteResultObservation,
        challenge_issued: bool,
        challenge_verified: bool,
        interactive_session: bool,
        suspected_false_positive: bool,
    ) {
        let Some(ids) = request.get_metadata("ai.policy.matched_ids").cloned() else {
            return;
        };
        let Some(store) = self.sqlite_store.as_ref().cloned() else {
            return;
        };
        let route_still_under_pressure = request
            .get_metadata("runtime.route.defense_depth")
            .is_some_and(|value| matches!(value.as_str(), "lean" | "survival"));
        let outcomes = ids
            .split(',')
            .filter_map(|value| value.trim().parse::<i64>().ok())
            .map(|id| AiTempPolicyOutcomeRecord {
                id,
                status_code: observation.status_code,
                latency_ms: observation.latency_ms,
                upstream_error: observation.upstream_error,
                challenge_issued,
                challenge_verified,
                interactive_session,
                suspected_false_positive,
                route_still_under_pressure,
            })
            .collect::<Vec<_>>();
        if outcomes.is_empty() {
            return;
        }
        tokio::spawn(async move {
            let now = unix_timestamp();
            for outcome in outcomes {
                let _ = store.record_ai_temp_policy_outcome(&outcome, now).await;
            }
        });
    }
}
