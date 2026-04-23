use super::*;

impl WafContext {
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
                .map(|guard| guard)
                .unwrap_or_else(|poisoned| {
                    log::warn!(
                        "ai_defense_trigger_runtime lock poisoned; recovering with current value"
                    );
                    poisoned.into_inner()
                });
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
        decisions: &[VisitorDecisionSignal],
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
}
