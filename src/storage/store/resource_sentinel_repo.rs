impl SqliteStore {
    pub async fn upsert_resource_sentinel_attack_session(
        &self,
        snapshot: &crate::core::ResourceSentinelPersistenceSnapshot,
    ) -> Result<()> {
        let now = unix_timestamp();
        let diagnosis_json = serde_json::to_string(&snapshot.diagnosis)?;
        let lifecycle_json = serde_json::to_string(&snapshot.lifecycle)?;
        let session_json = serde_json::to_string(&snapshot.session)?;
        let top_clusters_json = serde_json::to_string(&snapshot.top_clusters)?;
        let defense_effects_json = serde_json::to_string(&snapshot.defense_effects)?;
        let decision_traces_json = serde_json::to_string(&snapshot.decision_traces)?;
        let ingress_gap_json = serde_json::to_string(&snapshot.ingress_gap_analysis)?;
        let resource_pressure_json = serde_json::to_string(&snapshot.resource_pressure_feedback)?;
        let migrations_json = serde_json::to_string(&snapshot.attack_migrations)?;
        let report_json = snapshot
            .attack_report
            .as_ref()
            .map(serde_json::to_string)
            .transpose()?;

        sqlx::query(
            r#"
            INSERT INTO resource_sentinel_attack_sessions (
                session_id, phase, started_at_ms, ended_at_ms, duration_ms, peak_severity,
                peak_attack_score, primary_pressure, final_outcome, summary, diagnosis_json,
                lifecycle_json, session_json, top_clusters_json, defense_effects_json,
                decision_traces_json, ingress_gap_json, resource_pressure_json, migrations_json,
                report_json, pre_admission_rejections, aggregated_events, defense_actions,
                defense_extensions, defense_relaxations, audit_event_count, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                phase = excluded.phase,
                ended_at_ms = excluded.ended_at_ms,
                duration_ms = excluded.duration_ms,
                peak_severity = excluded.peak_severity,
                peak_attack_score = excluded.peak_attack_score,
                primary_pressure = excluded.primary_pressure,
                final_outcome = excluded.final_outcome,
                summary = excluded.summary,
                diagnosis_json = excluded.diagnosis_json,
                lifecycle_json = excluded.lifecycle_json,
                session_json = excluded.session_json,
                top_clusters_json = excluded.top_clusters_json,
                defense_effects_json = excluded.defense_effects_json,
                decision_traces_json = excluded.decision_traces_json,
                ingress_gap_json = excluded.ingress_gap_json,
                resource_pressure_json = excluded.resource_pressure_json,
                migrations_json = excluded.migrations_json,
                report_json = excluded.report_json,
                pre_admission_rejections = excluded.pre_admission_rejections,
                aggregated_events = excluded.aggregated_events,
                defense_actions = excluded.defense_actions,
                defense_extensions = excluded.defense_extensions,
                defense_relaxations = excluded.defense_relaxations,
                audit_event_count = excluded.audit_event_count,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(snapshot.session.session_id as i64)
        .bind(&snapshot.session.phase)
        .bind(snapshot.session.started_at_ms as i64)
        .bind(snapshot.session.ended_at_ms.map(|value| value as i64))
        .bind(snapshot.session.duration_ms as i64)
        .bind(&snapshot.session.peak_severity)
        .bind(snapshot.session.peak_attack_score as i64)
        .bind(&snapshot.session.primary_pressure)
        .bind(&snapshot.session.final_outcome)
        .bind(&snapshot.session.summary)
        .bind(diagnosis_json)
        .bind(lifecycle_json)
        .bind(session_json)
        .bind(top_clusters_json)
        .bind(defense_effects_json)
        .bind(decision_traces_json)
        .bind(ingress_gap_json)
        .bind(resource_pressure_json)
        .bind(migrations_json)
        .bind(report_json)
        .bind(snapshot.session.pre_admission_rejections as i64)
        .bind(snapshot.session.aggregated_events as i64)
        .bind(snapshot.session.defense_actions as i64)
        .bind(snapshot.session.defense_extensions as i64)
        .bind(snapshot.session.defense_relaxations as i64)
        .bind(snapshot.session.audit_event_count as i64)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn upsert_resource_sentinel_defense_memory(
        &self,
        record: &crate::core::ResourceSentinelDefenseMemoryExport,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO resource_sentinel_defense_memory (
                attack_type, preferred_action, effective_score, ineffective_score, weak_score,
                harmful_score, last_outcome, last_rejection_delta, last_score_delta,
                last_seen_ms, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(attack_type) DO UPDATE SET
                preferred_action = excluded.preferred_action,
                effective_score = excluded.effective_score,
                ineffective_score = excluded.ineffective_score,
                weak_score = excluded.weak_score,
                harmful_score = excluded.harmful_score,
                last_outcome = excluded.last_outcome,
                last_rejection_delta = excluded.last_rejection_delta,
                last_score_delta = excluded.last_score_delta,
                last_seen_ms = excluded.last_seen_ms,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&record.attack_type)
        .bind(&record.preferred_action)
        .bind(record.effective_score as i64)
        .bind(record.ineffective_score as i64)
        .bind(record.weak_score as i64)
        .bind(record.harmful_score as i64)
        .bind(&record.last_outcome)
        .bind(record.last_rejection_delta as i64)
        .bind(record.last_score_delta)
        .bind(record.last_seen_ms as i64)
        .bind(unix_timestamp())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn list_resource_sentinel_defense_memory(
        &self,
    ) -> Result<Vec<ResourceSentinelDefenseMemoryEntry>> {
        let entries = sqlx::query_as::<_, ResourceSentinelDefenseMemoryEntry>(
            r#"
            SELECT attack_type, preferred_action, effective_score, ineffective_score, weak_score,
                   harmful_score, last_outcome, last_rejection_delta, last_score_delta,
                   last_seen_ms, updated_at
            FROM resource_sentinel_defense_memory
            ORDER BY updated_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(entries)
    }

    #[cfg(any(feature = "api", test))]
    pub async fn list_resource_sentinel_attack_sessions(
        &self,
        limit: u32,
    ) -> Result<Vec<ResourceSentinelAttackSessionEntry>> {
        let entries = sqlx::query_as::<_, ResourceSentinelAttackSessionEntry>(
            r#"
            SELECT id, session_id, phase, started_at_ms, ended_at_ms, duration_ms,
                   peak_severity, peak_attack_score, primary_pressure, final_outcome,
                   summary, report_json, updated_at
            FROM resource_sentinel_attack_sessions
            ORDER BY updated_at DESC, id DESC
            LIMIT ?
            "#,
        )
        .bind(i64::from(limit.min(100)))
        .fetch_all(&self.pool)
        .await?;
        Ok(entries)
    }
}
