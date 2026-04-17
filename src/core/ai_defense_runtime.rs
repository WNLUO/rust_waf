use super::{
    unix_timestamp, AiDefenseDecision, AiDefenseRunResult, AiDefenseSignalSnapshot,
    LocalDefenseRecommendation, WafContext,
};
use crate::storage::{AiTempPolicyEffectStats, AiTempPolicyUpsert};
use anyhow::Result;

impl WafContext {
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
        let active_temp_policy_count = match self.sqlite_store.as_ref() {
            Some(store) => store.list_active_ai_temp_policies(now).await?.len() as u32,
            None => 0,
        };
        let trigger_pending_secs = self
            .ai_defense_trigger_runtime
            .lock()
            .expect("ai_defense_trigger_runtime lock poisoned")
            .pending_since
            .map(|pending_since| now.saturating_sub(pending_since).max(0) as u64)
            .unwrap_or(0);

        Ok(AiDefenseSignalSnapshot {
            generated_at: now,
            sqlite_available: self.sqlite_store.is_some(),
            active_temp_policy_count,
            max_active_temp_policy_count,
            trigger_reason,
            trigger_pending_secs,
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

        for recommendation in snapshot.local_recommendations {
            let Some(decision) = ai_defense_decision_from_local_recommendation(&recommendation)
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
        Ok(result)
    }
}

fn ai_defense_decision_from_local_recommendation(
    recommendation: &LocalDefenseRecommendation,
) -> Option<AiDefenseDecision> {
    if recommendation.action != "tighten_route_cc" {
        return None;
    }
    if !ai_defense_route_allowed(&recommendation.route) {
        return None;
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
        confidence: recommendation.confidence,
        auto_apply: true,
        rationale: format!(
            "{}; auto-applied by local AI defense guardrails for site {}",
            recommendation.rationale, recommendation.site_id
        ),
    })
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
}
