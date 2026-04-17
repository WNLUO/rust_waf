impl SqliteStore {
    pub async fn upsert_ai_visitor_profile(
        &self,
        profile: &AiVisitorProfileUpsert,
    ) -> Result<i64> {
        let result = sqlx::query(
            r#"
            INSERT INTO ai_visitor_profiles (
                identity_key, identity_source, site_id, client_ip, user_agent, first_seen_at,
                last_seen_at, request_count, document_count, api_count, static_count, admin_count,
                challenge_count, challenge_verified_count, fingerprint_seen, human_confidence,
                automation_risk, probe_risk, abuse_risk, false_positive_risk, state,
                summary_json, last_ai_review_at, ai_rationale, expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(identity_key, site_id) DO UPDATE SET
                identity_source = excluded.identity_source,
                client_ip = excluded.client_ip,
                user_agent = excluded.user_agent,
                first_seen_at = MIN(ai_visitor_profiles.first_seen_at, excluded.first_seen_at),
                last_seen_at = excluded.last_seen_at,
                request_count = excluded.request_count,
                document_count = excluded.document_count,
                api_count = excluded.api_count,
                static_count = excluded.static_count,
                admin_count = excluded.admin_count,
                challenge_count = excluded.challenge_count,
                challenge_verified_count = excluded.challenge_verified_count,
                fingerprint_seen = excluded.fingerprint_seen,
                human_confidence = excluded.human_confidence,
                automation_risk = excluded.automation_risk,
                probe_risk = excluded.probe_risk,
                abuse_risk = excluded.abuse_risk,
                false_positive_risk = excluded.false_positive_risk,
                state = excluded.state,
                summary_json = excluded.summary_json,
                last_ai_review_at = excluded.last_ai_review_at,
                ai_rationale = excluded.ai_rationale,
                expires_at = excluded.expires_at
            "#,
        )
        .bind(&profile.identity_key)
        .bind(&profile.identity_source)
        .bind(&profile.site_id)
        .bind(&profile.client_ip)
        .bind(&profile.user_agent)
        .bind(profile.first_seen_at)
        .bind(profile.last_seen_at)
        .bind(profile.request_count)
        .bind(profile.document_count)
        .bind(profile.api_count)
        .bind(profile.static_count)
        .bind(profile.admin_count)
        .bind(profile.challenge_count)
        .bind(profile.challenge_verified_count)
        .bind(profile.fingerprint_seen)
        .bind(profile.human_confidence)
        .bind(profile.automation_risk)
        .bind(profile.probe_risk)
        .bind(profile.abuse_risk)
        .bind(&profile.false_positive_risk)
        .bind(&profile.state)
        .bind(&profile.summary_json)
        .bind(profile.last_ai_review_at)
        .bind(&profile.ai_rationale)
        .bind(profile.expires_at)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }

    pub async fn upsert_ai_visitor_decision(
        &self,
        decision: &AiVisitorDecisionUpsert,
    ) -> Result<i64> {
        let result = sqlx::query(
            r#"
            INSERT INTO ai_visitor_decisions (
                decision_key, identity_key, site_id, created_at, action, confidence,
                ttl_secs, rationale, applied, effect_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(decision_key) DO UPDATE SET
                created_at = excluded.created_at,
                action = excluded.action,
                confidence = excluded.confidence,
                ttl_secs = excluded.ttl_secs,
                rationale = excluded.rationale,
                applied = excluded.applied,
                effect_json = excluded.effect_json
            "#,
        )
        .bind(&decision.decision_key)
        .bind(&decision.identity_key)
        .bind(&decision.site_id)
        .bind(decision.created_at)
        .bind(&decision.action)
        .bind(decision.confidence)
        .bind(decision.ttl_secs)
        .bind(&decision.rationale)
        .bind(decision.applied)
        .bind(&decision.effect_json)
        .execute(&self.pool)
        .await?;
        Ok(result.last_insert_rowid())
    }
}
