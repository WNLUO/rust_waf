impl SqliteStore {
    pub async fn upsert_ai_route_profile(
        &self,
        profile: &AiRouteProfileUpsert,
    ) -> Result<i64> {
        let now = unix_timestamp();
        let recommended_actions_json = serde_json::to_string(&profile.recommended_actions)?;
        let avoid_actions_json = serde_json::to_string(&profile.avoid_actions)?;
        let result = sqlx::query(
            r#"
            INSERT INTO ai_route_profiles (
                created_at, updated_at, last_observed_at, site_id, route_pattern, match_mode,
                route_type, sensitivity, auth_required, normal_traffic_pattern,
                recommended_actions_json, avoid_actions_json, confidence, source, status,
                rationale, reviewed_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(site_id, route_pattern, match_mode) DO UPDATE SET
                updated_at = excluded.updated_at,
                last_observed_at = COALESCE(excluded.last_observed_at, ai_route_profiles.last_observed_at),
                route_type = excluded.route_type,
                sensitivity = excluded.sensitivity,
                auth_required = excluded.auth_required,
                normal_traffic_pattern = excluded.normal_traffic_pattern,
                recommended_actions_json = excluded.recommended_actions_json,
                avoid_actions_json = excluded.avoid_actions_json,
                confidence = excluded.confidence,
                source = excluded.source,
                status = excluded.status,
                rationale = excluded.rationale,
                reviewed_at = COALESCE(excluded.reviewed_at, ai_route_profiles.reviewed_at)
            "#,
        )
        .bind(now)
        .bind(now)
        .bind(profile.last_observed_at)
        .bind(&profile.site_id)
        .bind(&profile.route_pattern)
        .bind(&profile.match_mode)
        .bind(&profile.route_type)
        .bind(&profile.sensitivity)
        .bind(&profile.auth_required)
        .bind(&profile.normal_traffic_pattern)
        .bind(recommended_actions_json)
        .bind(avoid_actions_json)
        .bind(profile.confidence)
        .bind(&profile.source)
        .bind(&profile.status)
        .bind(&profile.rationale)
        .bind(profile.reviewed_at)
        .execute(&self.pool)
        .await?;

        Ok(result.last_insert_rowid())
    }

    pub async fn list_ai_route_profiles(
        &self,
        site_id: Option<&str>,
        status: Option<&str>,
        limit: u32,
    ) -> Result<Vec<AiRouteProfileEntry>> {
        let mut query = QueryBuilder::<Sqlite>::new(
            r#"
            SELECT id, created_at, updated_at, last_observed_at, site_id, route_pattern, match_mode,
                   route_type, sensitivity, auth_required, normal_traffic_pattern,
                   recommended_actions_json, avoid_actions_json, confidence, source, status,
                   rationale, reviewed_at
            FROM ai_route_profiles
            WHERE 1=1
            "#,
        );
        if let Some(site_id) = site_id.filter(|value| !value.trim().is_empty()) {
            query.push(" AND site_id = ");
            query.push_bind(site_id);
        }
        if let Some(status) = status.filter(|value| !value.trim().is_empty()) {
            query.push(" AND status = ");
            query.push_bind(status);
        }
        query.push(" ORDER BY updated_at DESC, confidence DESC, id DESC LIMIT ");
        query.push_bind(limit.clamp(1, 500) as i64);

        Ok(query
            .build_query_as::<AiRouteProfileEntry>()
            .fetch_all(&self.pool)
            .await?)
    }
}
