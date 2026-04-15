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
