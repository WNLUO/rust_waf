impl SqliteStore {
    pub async fn upsert_ai_temp_policy(&self, policy: &AiTempPolicyUpsert) -> Result<i64> {
        let now = unix_timestamp();
        let effect_json = serde_json::to_string(policy.effect_stats.as_ref().unwrap_or(
            &crate::storage::AiTempPolicyEffectStats::default(),
        ))?;
        let result = sqlx::query(
            r#"
            INSERT INTO ai_temp_policies (
                created_at, updated_at, expires_at, status, source_report_id, policy_key, title,
                policy_type, layer, scope_type, scope_value, action, operator, suggested_value,
                rationale, confidence, auto_applied, hit_count, last_hit_at, effect_json
            )
            VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, NULL, ?)
            ON CONFLICT(policy_key, scope_type, scope_value, status) DO UPDATE SET
                updated_at = excluded.updated_at,
                expires_at = excluded.expires_at,
                source_report_id = excluded.source_report_id,
                title = excluded.title,
                policy_type = excluded.policy_type,
                layer = excluded.layer,
                action = excluded.action,
                operator = excluded.operator,
                suggested_value = excluded.suggested_value,
                rationale = excluded.rationale,
                confidence = excluded.confidence,
                auto_applied = excluded.auto_applied,
                effect_json = CASE
                    WHEN ai_temp_policies.effect_json = '{}' THEN excluded.effect_json
                    ELSE ai_temp_policies.effect_json
                END
            "#
        )
        .bind(now)
        .bind(now)
        .bind(policy.expires_at)
        .bind(policy.source_report_id)
        .bind(&policy.policy_key)
        .bind(&policy.title)
        .bind(&policy.policy_type)
        .bind(&policy.layer)
        .bind(&policy.scope_type)
        .bind(&policy.scope_value)
        .bind(&policy.action)
        .bind(&policy.operator)
        .bind(&policy.suggested_value)
        .bind(&policy.rationale)
        .bind(policy.confidence)
        .bind(policy.auto_applied)
        .bind(effect_json)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn list_active_ai_temp_policies(&self, now: i64) -> Result<Vec<AiTempPolicyEntry>> {
        let rows = sqlx::query_as::<_, AiTempPolicyEntry>(
            r#"
            SELECT id, created_at, updated_at, expires_at, status, source_report_id, policy_key, title,
                   policy_type, layer, scope_type, scope_value, action, operator, suggested_value,
                   rationale, confidence, auto_applied, hit_count, last_hit_at, effect_json
            FROM ai_temp_policies
            WHERE status = 'active' AND expires_at > ?
            ORDER BY expires_at DESC, updated_at DESC, id DESC
            "#,
        )
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn expire_ai_temp_policies(&self, now: i64) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE ai_temp_policies SET status = 'expired', updated_at = ? WHERE status = 'active' AND expires_at <= ?",
        )
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }

    pub async fn delete_ai_temp_policy(&self, id: i64) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE ai_temp_policies SET status = 'revoked', updated_at = ? WHERE id = ? AND status = 'active'",
        )
        .bind(unix_timestamp())
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn revoke_ai_temp_policy_with_effect(
        &self,
        id: i64,
        effect: &crate::storage::AiTempPolicyEffectStats,
        now: i64,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE ai_temp_policies SET status = 'revoked', updated_at = ?, effect_json = ? WHERE id = ? AND status = 'active'",
        )
        .bind(now)
        .bind(serde_json::to_string(effect)?)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn extend_ai_temp_policy_expiry_with_effect(
        &self,
        id: i64,
        expires_at: i64,
        effect: &crate::storage::AiTempPolicyEffectStats,
        now: i64,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE ai_temp_policies SET expires_at = ?, updated_at = ?, effect_json = ? WHERE id = ? AND status = 'active'",
        )
        .bind(expires_at)
        .bind(now)
        .bind(serde_json::to_string(effect)?)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn record_ai_temp_policy_hit(
        &self,
        hit: &crate::storage::AiTempPolicyHitRecord,
        now: i64,
    ) -> Result<bool> {
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT effect_json FROM ai_temp_policies WHERE id = ? AND status = 'active'",
        )
        .bind(hit.id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(effect_json) = existing else {
            return Ok(false);
        };

        let mut effect = serde_json::from_str::<crate::storage::AiTempPolicyEffectStats>(
            &effect_json,
        )
        .unwrap_or_default();
        effect.total_hits += 1;
        effect.first_hit_at = effect.first_hit_at.or(Some(now));
        effect.last_hit_at = Some(now);
        effect.last_scope_type = Some(hit.scope_type.clone());
        effect.last_scope_value = Some(hit.scope_value.clone());
        effect.last_matched_value = Some(hit.matched_value.clone());
        effect.last_match_mode = Some(hit.match_mode.clone());
        *effect.action_hits.entry(hit.action.clone()).or_insert(0) += 1;
        *effect.match_modes.entry(hit.match_mode.clone()).or_insert(0) += 1;
        *effect.scope_hits.entry(hit.scope_type.clone()).or_insert(0) += 1;
        *effect
            .matched_value_hits
            .entry(hit.matched_value.clone())
            .or_insert(0) += 1;

        let result = sqlx::query(
            r#"
            UPDATE ai_temp_policies
            SET hit_count = hit_count + 1,
                last_hit_at = ?,
                updated_at = ?,
                effect_json = ?
            WHERE id = ? AND status = 'active'
            "#,
        )
        .bind(now)
        .bind(now)
        .bind(serde_json::to_string(&effect)?)
        .bind(hit.id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn record_ai_temp_policy_outcome(
        &self,
        outcome: &crate::storage::AiTempPolicyOutcomeRecord,
        now: i64,
    ) -> Result<bool> {
        let existing = sqlx::query_scalar::<_, String>(
            "SELECT effect_json FROM ai_temp_policies WHERE id = ? AND status = 'active'",
        )
        .bind(outcome.id)
        .fetch_optional(&self.pool)
        .await?;

        let Some(effect_json) = existing else {
            return Ok(false);
        };

        let mut effect =
            serde_json::from_str::<crate::storage::AiTempPolicyEffectStats>(&effect_json)
                .unwrap_or_default();
        effect.post_policy_observations += 1;
        effect.last_effectiveness_check_at = Some(now);
        if outcome.upstream_error || outcome.status_code >= 500 {
            effect.post_policy_upstream_errors += 1;
        }
        let family = format!("{}xx", outcome.status_code / 100);
        *effect.post_policy_status_families.entry(family).or_insert(0) += 1;
        *effect
            .post_policy_status_codes
            .entry(outcome.status_code.to_string())
            .or_insert(0) += 1;
        if let Some(latency_ms) = outcome.latency_ms {
            effect.post_policy_latency_samples += 1;
            effect.post_policy_latency_ms_total = effect
                .post_policy_latency_ms_total
                .saturating_add(latency_ms.min(i64::MAX as u64) as i64);
            if latency_ms >= 1_000 {
                effect.post_policy_slow_responses += 1;
            }
        }
        if outcome.challenge_issued {
            effect.post_policy_challenge_issued += 1;
        }
        if outcome.challenge_verified {
            effect.post_policy_challenge_verified += 1;
        }
        if outcome.interactive_session {
            effect.post_policy_interactive_sessions += 1;
        }
        if outcome.suspected_false_positive {
            effect.suspected_false_positive_events += 1;
        }
        if outcome.route_still_under_pressure {
            effect.pressure_after_observations += 1;
        }
        effect.outcome_score = score_ai_temp_policy_effect(&effect);
        effect.outcome_status = Some(classify_ai_temp_policy_effect(&effect).to_string());

        let result = sqlx::query(
            r#"
            UPDATE ai_temp_policies
            SET updated_at = ?,
                effect_json = ?
            WHERE id = ? AND status = 'active'
            "#,
        )
        .bind(now)
        .bind(serde_json::to_string(&effect)?)
        .bind(outcome.id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    pub async fn purge_inactive_ai_temp_policies(&self, updated_before: i64) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM ai_temp_policies WHERE status != 'active' AND updated_at < ?",
        )
        .bind(updated_before)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected())
    }
}

fn score_ai_temp_policy_effect(effect: &crate::storage::AiTempPolicyEffectStats) -> i64 {
    let observations = effect.post_policy_observations.max(1);
    let mut score = 0i64;
    score += effect.total_hits.min(50);
    score -= effect.pressure_after_observations.saturating_mul(3);
    score -= effect.post_policy_upstream_errors.saturating_mul(4);
    score -= effect.suspected_false_positive_events.saturating_mul(8);
    if effect.post_policy_challenge_issued > 0 {
        let verified_ratio =
            effect.post_policy_challenge_verified.saturating_mul(100) / effect.post_policy_challenge_issued.max(1);
        if verified_ratio >= 60 {
            score -= 12;
        } else if verified_ratio <= 20 {
            score += 6;
        }
    }
    if effect.post_policy_slow_responses.saturating_mul(100) / observations >= 30 {
        score -= 8;
    }
    score.clamp(-100, 100)
}

fn classify_ai_temp_policy_effect(effect: &crate::storage::AiTempPolicyEffectStats) -> &'static str {
    if effect.suspected_false_positive_events >= 3
        || effect.post_policy_upstream_errors >= 5
        || effect.outcome_score <= -20
    {
        "harmful"
    } else if effect.post_policy_observations >= 5 && effect.outcome_score >= 12 {
        "effective"
    } else if effect.post_policy_observations >= 5 {
        "neutral"
    } else {
        "warming"
    }
}
