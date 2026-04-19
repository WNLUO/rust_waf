use super::*;

impl WafEngine {
    pub(super) async fn run_maintenance(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        if let Err(err) = self.context.refresh_rules_from_storage().await {
            warn!("Failed to refresh rules from SQLite: {}", err);
        }

        if let Some(store) = self.context.sqlite_store.as_ref() {
            if let Err(err) = store.flush_aggregated_security_events().await {
                warn!(
                    "Failed to flush aggregated security events before maintenance: {}",
                    err
                );
            }
            let storage_policy = self.context.config_snapshot().storage_policy;
            let thresholds = [
                (
                    "security events",
                    store
                        .purge_old_security_events(now.saturating_sub(
                            (storage_policy.security_event_retention_days * 24 * 3600) as i64,
                        ))
                        .await,
                ),
                (
                    "behavior events",
                    store
                        .purge_old_behavior_events(now.saturating_sub(
                            (storage_policy.behavior_event_retention_days * 24 * 3600) as i64,
                        ))
                        .await,
                ),
                (
                    "behavior sessions",
                    store
                        .purge_old_behavior_sessions(now.saturating_sub(
                            (storage_policy.behavior_session_retention_days * 24 * 3600) as i64,
                        ))
                        .await,
                ),
                (
                    "fingerprint profiles",
                    store
                        .purge_old_fingerprint_profiles(now.saturating_sub(
                            (storage_policy.fingerprint_profile_retention_days * 24 * 3600) as i64,
                        ))
                        .await,
                ),
                (
                    "AI audit reports",
                    store
                        .purge_old_ai_audit_reports(now.saturating_sub(
                            (storage_policy.ai_audit_report_retention_days * 24 * 3600) as i64,
                        ))
                        .await,
                ),
                (
                    "inactive AI temp policies",
                    store
                        .purge_inactive_ai_temp_policies(now.saturating_sub(
                            (storage_policy.ai_audit_report_retention_days * 24 * 3600) as i64,
                        ))
                        .await,
                ),
            ];
            for (label, result) in thresholds {
                match result {
                    Ok(removed) if removed > 0 => {
                        debug!("Maintenance purged {} stale {}", removed, label);
                    }
                    Ok(_) => {}
                    Err(err) => warn!("Failed to purge stale {}: {}", label, err),
                }
            }

            if let Err(err) = self.auto_govern_ai_temp_policies(store.as_ref(), now).await {
                warn!("Failed to auto-govern AI temp policies: {}", err);
            }
            if let Some(trigger_reason) = self.context.consume_ai_auto_defense_trigger(now) {
                match self
                    .context
                    .run_ai_auto_defense(now, Some(trigger_reason.clone()))
                    .await
                {
                    Ok(result) if result.applied > 0 => {
                        info!(
                            "AI auto defense applied {} temporary policy decision(s), skipped={}, trigger={}",
                            result.applied, result.skipped, trigger_reason
                        );
                    }
                    Ok(result) if result.disabled_reason.is_some() => {
                        debug!(
                            "AI auto defense skipped: {}",
                            result.disabled_reason.unwrap_or_default()
                        );
                    }
                    Ok(_) => {}
                    Err(err) => warn!("Failed to run AI auto defense: {}", err),
                }
            }
        }

        if let Err(err) = self.context.refresh_ai_temp_policies().await {
            warn!("Failed to refresh AI temp policies: {}", err);
        }
        if let Err(err) = self.context.refresh_ai_route_profiles().await {
            warn!("Failed to refresh AI route profiles: {}", err);
        }
        if let Err(err) = self.context.refresh_server_public_ip_allowlist(false).await {
            debug!("Server public IP allowlist refresh did not update: {}", err);
        }

        #[cfg(feature = "api")]
        if let Err(err) = self.run_ai_auto_audit(now).await {
            warn!("Failed to run AI auto audit: {}", err);
        }

        if let Some(l4_inspector) = self.context.l4_inspector() {
            l4_inspector.maintenance_tick();
            if matches!(
                self.context.config_snapshot().runtime_profile,
                RuntimeProfile::Standard
            ) {
                let stats = l4_inspector.get_statistics();
                debug!(
                    "Maintenance tick: active_connections={}, blocked_connections={}, rate_limit_hits={}",
                    stats.connections.active_connections,
                    stats.connections.blocked_connections,
                    stats.connections.rate_limit_hits
                );
                debug!(
                    "L4 counters: ddos_events={}, protocol_anomalies={}, traffic={}, defense_actions={}",
                    stats.ddos_events,
                    stats.protocol_anomalies,
                    stats.traffic,
                    stats.defense_actions
                );

                if !stats.per_port_stats.is_empty() {
                    debug!("=== Per-Port Statistics ===");
                    for (port, port_stats) in &stats.per_port_stats {
                        debug!(
                            "Port {}: connections={}, blocks={}, ddos_events={}",
                            port, port_stats.connections, port_stats.blocks, port_stats.ddos_events
                        );
                    }
                    debug!("=============================");
                }
            }
        }
    }

    async fn auto_govern_ai_temp_policies(
        &self,
        store: &crate::storage::SqliteStore,
        now: i64,
    ) -> Result<()> {
        let current_identity = self
            .context
            .auto_tuning_snapshot()
            .last_observed_identity_resolution_pressure_percent;
        let current_l7 = self
            .context
            .auto_tuning_snapshot()
            .last_observed_l7_friction_pressure_percent;
        let ai_config = self.context.config_snapshot().integrations.ai_audit;
        let policies = store.list_active_ai_temp_policies(now).await?;

        for policy in policies {
            let mut effect = serde_json::from_str::<crate::storage::AiTempPolicyEffectStats>(
                &policy.effect_json,
            )
            .unwrap_or_default();
            effect.last_effectiveness_check_at = Some(now);

            let age_secs = now.saturating_sub(policy.created_at);
            let ttl_remaining = policy.expires_at.saturating_sub(now);
            let l7_improved = effect
                .baseline_l7_friction_percent
                .map(|baseline| current_l7 <= baseline - 3.0)
                .unwrap_or(false);
            let identity_improved = effect
                .baseline_identity_pressure_percent
                .map(|baseline| current_identity <= baseline - 1.5)
                .unwrap_or(false);
            let governance_mode = ai_temp_policy_governance_mode(
                policy.action.as_str(),
                policy.hit_count,
                l7_improved,
                identity_improved,
            );
            let outcome_status = effect.outcome_status.as_deref().unwrap_or("warming");
            let harmful_feedback = matches!(outcome_status, "harmful")
                || effect.suspected_false_positive_events >= 3
                || (effect.post_policy_observations >= 5
                    && effect.post_policy_upstream_errors.saturating_mul(2)
                        >= effect.post_policy_observations);
            let effective_feedback = outcome_status == "effective"
                || (effect.post_policy_observations >= 5 && effect.outcome_score >= 12);

            let should_revoke = ai_config.auto_apply_temp_policies
                && (harmful_feedback
                    || (age_secs >= ai_config.auto_revoke_warmup_secs as i64
                        && governance_mode == "cold"))
                && !effect.auto_revoked;
            if should_revoke {
                effect.auto_revoked = true;
                effect.auto_revoke_reason = Some(if harmful_feedback {
                    format!(
                        "harmful_effect_feedback: outcome={}, false_positive_events={}, upstream_errors={}, observations={}",
                        outcome_status,
                        effect.suspected_false_positive_events,
                        effect.post_policy_upstream_errors,
                        effect.post_policy_observations
                    )
                } else {
                    format!("{}_after_warmup", policy.action.replace(':', "_"))
                });
                if harmful_feedback {
                    effect.outcome_status = Some("harmful".to_string());
                }
                let _ = store
                    .revoke_ai_temp_policy_with_effect(policy.id, &effect, now)
                    .await?;
                continue;
            }

            let should_extend = ai_config.allow_auto_extend_effective_policies
                && ttl_remaining <= 300
                && (governance_mode == "effective" || effective_feedback)
                && effect.auto_extensions < 2;
            if should_extend {
                effect.auto_extensions += 1;
                let extension_secs = match policy.action.as_str() {
                    "add_temp_block" => 300,
                    "increase_delay" => 600,
                    "tighten_route_cc" | "tighten_host_cc" | "increase_challenge" => 900,
                    "raise_identity_risk" | "add_behavior_watch" => 600,
                    _ => 300,
                };
                let _ = store
                    .extend_ai_temp_policy_expiry_with_effect(
                        policy.id,
                        policy.expires_at.saturating_add(extension_secs),
                        &effect,
                        now,
                    )
                    .await?;
                continue;
            }

            if effect.last_effectiveness_check_at == Some(now) {
                let _ = store
                    .extend_ai_temp_policy_expiry_with_effect(
                        policy.id,
                        policy.expires_at,
                        &effect,
                        now,
                    )
                    .await?;
            }
        }

        Ok(())
    }
}

fn ai_temp_policy_governance_mode(
    action: &str,
    hit_count: i64,
    l7_improved: bool,
    identity_improved: bool,
) -> &'static str {
    match action {
        "increase_delay" => {
            if hit_count >= 3 && l7_improved {
                "effective"
            } else if hit_count == 0 {
                "cold"
            } else {
                "watch"
            }
        }
        "tighten_route_cc" | "tighten_host_cc" | "increase_challenge" => {
            if hit_count >= 2 && l7_improved {
                "effective"
            } else if hit_count == 0 {
                "cold"
            } else {
                "watch"
            }
        }
        "raise_identity_risk" | "add_behavior_watch" => {
            if hit_count >= 2 && identity_improved {
                "effective"
            } else if hit_count == 0 {
                "cold"
            } else {
                "watch"
            }
        }
        "add_temp_block" => {
            if hit_count >= 1 && (l7_improved || identity_improved) {
                "effective"
            } else if hit_count == 0 {
                "cold"
            } else {
                "watch"
            }
        }
        _ => {
            if hit_count == 0 {
                "cold"
            } else {
                "watch"
            }
        }
    }
}
