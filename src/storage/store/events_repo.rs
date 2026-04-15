impl SqliteStore {
    #[cfg(any(feature = "api", test))]
    pub async fn list_fingerprint_profiles(
        &self,
        limit: u32,
    ) -> Result<Vec<FingerprintProfileEntry>> {
        let limit = normalized_limit(limit).min(500);
        let items = sqlx::query_as::<_, FingerprintProfileEntry>(
            r#"
            SELECT identity, identity_kind, source_ip, first_seen_at, last_seen_at,
                   first_site_domain, last_site_domain, first_user_agent, last_user_agent,
                   total_security_events, total_behavior_events, total_challenges, total_blocks,
                   latest_score, max_score, latest_action, reputation_score, notes
            FROM fingerprint_profiles
            ORDER BY last_seen_at DESC, max_score DESC, total_behavior_events DESC
            LIMIT ?
            "#,
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        Ok(items)
    }

    #[cfg(any(feature = "api", test))]
    pub async fn list_behavior_sessions(
        &self,
        limit: u32,
    ) -> Result<Vec<BehaviorSessionEntry>> {
        let limit = normalized_limit(limit).min(500);
        let items = sqlx::query_as::<_, BehaviorSessionEntry>(
            r#"
            SELECT session_key, identity, source_ip, site_domain, opened_at, last_seen_at,
                   event_count, challenge_count, block_count, latest_action, latest_uri,
                   latest_reason, dominant_route, focused_document_route, focused_api_route,
                   distinct_routes, repeated_ratio, document_repeated_ratio, api_repeated_ratio,
                   document_requests, api_requests, non_document_requests, interval_jitter_ms,
                   session_span_secs, flags_json
            FROM behavior_sessions
            ORDER BY last_seen_at DESC, block_count DESC, challenge_count DESC, event_count DESC
            LIMIT ?
            "#,
        )
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        Ok(items)
    }

    pub async fn latest_rules_version(&self) -> Result<i64> {
        let latest_version: Option<i64> = sqlx::query_scalar("SELECT MAX(updated_at) FROM rules")
            .fetch_one(&self.pool)
            .await?;
        Ok(latest_version.unwrap_or(0))
    }

    pub async fn rules_state(&self) -> Result<(u64, i64)> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rules")
            .fetch_one(&self.pool)
            .await?;
        let latest_version = self.latest_rules_version().await?;
        Ok((count.max(0) as u64, latest_version))
    }

    #[cfg(any(feature = "api", test))]
    pub async fn list_security_events(
        &self,
        query: &SecurityEventQuery,
    ) -> Result<PagedResult<SecurityEventEntry>> {
        let limit = normalized_limit(query.limit);
        let offset = query.offset;

        let mut builder = QueryBuilder::<Sqlite>::new(
            r#"
            SELECT id, layer, provider, provider_event_id, provider_site_id, provider_site_name,
                   provider_site_domain, action, reason, details_json, source_ip, dest_ip, source_port,
                   dest_port, protocol, http_method, uri, http_version,
                   created_at, handled, handled_at
            FROM security_events
            WHERE 1=1
            "#,
        );
        append_security_event_filters(&mut builder, query);
        append_event_sort(&mut builder, query);

        let items = builder
            .build_query_as::<SecurityEventEntry>()
            .fetch_all(&self.pool)
            .await?;
        let filtered_items = items
            .into_iter()
            .filter(|entry| security_event_matches_derived_filters(entry, query))
            .collect::<Vec<_>>();
        let total = filtered_items.len() as u64;
        let items = filtered_items
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect::<Vec<_>>();

        Ok(PagedResult {
            total,
            limit,
            offset,
            items,
        })
    }

    #[cfg(any(feature = "api", test))]
    pub async fn list_blocked_ips(
        &self,
        query: &BlockedIpQuery,
    ) -> Result<PagedResult<BlockedIpEntry>> {
        let limit = normalized_limit(query.limit);
        let offset = query.offset;

        let mut count_builder =
            QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM blocked_ips WHERE 1=1");
        append_blocked_ip_filters(&mut count_builder, query);
        let total: i64 = count_builder
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await?;

        let mut builder = QueryBuilder::<Sqlite>::new(
            "SELECT id, provider, provider_remote_id, ip, reason, blocked_at, expires_at FROM blocked_ips WHERE 1=1",
        );
        append_blocked_ip_filters(&mut builder, query);
        append_blocked_ip_sort(&mut builder, query);
        builder.push(" LIMIT ");
        builder.push_bind(i64::from(limit));
        builder.push(" OFFSET ");
        builder.push_bind(i64::from(offset));

        let items = builder
            .build_query_as::<BlockedIpEntry>()
            .fetch_all(&self.pool)
            .await?;

        Ok(PagedResult {
            total: total.max(0) as u64,
            limit,
            offset,
            items,
        })
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn load_rule(&self, id: &str) -> Result<Option<Rule>> {
        let row = sqlx::query_as::<_, StoredRuleRow>(
            r#"
            SELECT id, name, enabled, layer, pattern, action, severity, plugin_template_id, response_template_json
            FROM rules
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn insert_rule(&self, rule: &Rule) -> Result<bool> {
        let result = sqlx::query(
            r#"
            INSERT OR IGNORE INTO rules (
                id, name, enabled, layer, pattern, action, severity, plugin_template_id, response_template_json, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(rule.enabled)
        .bind(rule.layer.as_str())
        .bind(&rule.pattern)
        .bind(rule.action.as_str())
        .bind(rule.severity.as_str())
        .bind(&rule.plugin_template_id)
        .bind(serialize_rule_response_template(rule.response_template.as_ref())?)
        .bind(unix_timestamp())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn upsert_rule(&self, rule: &Rule) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO rules (id, name, enabled, layer, pattern, action, severity, plugin_template_id, response_template_json, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                enabled = excluded.enabled,
                layer = excluded.layer,
                pattern = excluded.pattern,
                action = excluded.action,
                severity = excluded.severity,
                plugin_template_id = excluded.plugin_template_id,
                response_template_json = excluded.response_template_json,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(rule.enabled)
        .bind(rule.layer.as_str())
        .bind(&rule.pattern)
        .bind(rule.action.as_str())
        .bind(rule.severity.as_str())
        .bind(&rule.plugin_template_id)
        .bind(serialize_rule_response_template(rule.response_template.as_ref())?)
        .bind(unix_timestamp())
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn delete_rule(&self, id: &str) -> Result<bool> {
        let result = sqlx::query("DELETE FROM rules WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn delete_blocked_ip(&self, id: i64) -> Result<bool> {
        let result = sqlx::query("DELETE FROM blocked_ips WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn load_blocked_ip(&self, id: i64) -> Result<Option<BlockedIpEntry>> {
        let row = sqlx::query_as::<_, BlockedIpEntry>(
            r#"
            SELECT id, provider, provider_remote_id, ip, reason, blocked_at, expires_at
            FROM blocked_ips
            WHERE id = ?
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn load_active_local_blocked_ip_by_ip(
        &self,
        ip: &str,
    ) -> Result<Option<BlockedIpEntry>> {
        let row = sqlx::query_as::<_, BlockedIpEntry>(
            r#"
            SELECT id, provider, provider_remote_id, ip, reason, blocked_at, expires_at
            FROM blocked_ips
            WHERE provider IS NULL
              AND ip = ?
              AND expires_at > ?
            ORDER BY expires_at DESC, blocked_at DESC
            LIMIT 1
            "#,
        )
        .bind(ip)
        .bind(unix_timestamp())
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    #[cfg(any(feature = "api", test))]
    pub async fn cleanup_expired_blocked_ips(
        &self,
        query: &BlockedIpCleanupQuery,
    ) -> Result<Vec<BlockedIpEntry>> {
        let mut select_builder = QueryBuilder::<Sqlite>::new(
            "SELECT id, provider, provider_remote_id, ip, reason, blocked_at, expires_at FROM blocked_ips WHERE 1=1",
        );
        append_blocked_ip_cleanup_filters(&mut select_builder, query);
        let items = select_builder
            .build_query_as::<BlockedIpEntry>()
            .fetch_all(&self.pool)
            .await?;

        if items.is_empty() {
            return Ok(items);
        }

        for chunk in items.chunks(300) {
            let mut builder = QueryBuilder::<Sqlite>::new("DELETE FROM blocked_ips WHERE id IN (");
            {
                let mut separated = builder.separated(", ");
                for item in chunk {
                    separated.push_bind(item.id);
                }
            }
            builder.push(")");
            builder.build().execute(&self.pool).await?;
        }

        Ok(items)
    }

    pub async fn purge_old_security_events(&self, created_before: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM security_events WHERE created_at < ?")
            .bind(created_before)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn purge_old_behavior_events(&self, created_before: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM behavior_events WHERE created_at < ?")
            .bind(created_before)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn purge_old_behavior_sessions(&self, last_seen_before: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM behavior_sessions WHERE last_seen_at < ?")
            .bind(last_seen_before)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }

    pub async fn purge_old_fingerprint_profiles(&self, last_seen_before: i64) -> Result<u64> {
        let result = sqlx::query("DELETE FROM fingerprint_profiles WHERE last_seen_at < ?")
            .bind(last_seen_before)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected())
    }
}

fn security_event_matches_derived_filters(
    entry: &SecurityEventEntry,
    query: &SecurityEventQuery,
) -> bool {
    if query.identity_state.is_none() && query.primary_signal.is_none() && query.labels.is_empty() {
        return true;
    }

    let summary = derive_security_event_summary(entry);
    if let Some(identity_state) = query.identity_state.as_deref() {
        if summary.identity_state.as_deref() != Some(identity_state) {
            return false;
        }
    }
    if let Some(primary_signal) = query.primary_signal.as_deref() {
        if summary.primary_signal.as_deref() != Some(primary_signal) {
            return false;
        }
    }
    query
        .labels
        .iter()
        .all(|label| summary.labels.iter().any(|candidate| candidate == label))
}

#[derive(Default)]
struct DerivedSecurityEventSummary {
    identity_state: Option<String>,
    primary_signal: Option<String>,
    labels: Vec<String>,
}

fn derive_security_event_summary(entry: &SecurityEventEntry) -> DerivedSecurityEventSummary {
    let details = entry
        .details_json
        .as_deref()
        .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());

    let identity_state = details
        .as_ref()
        .and_then(|value| nested_str(value, &["client_identity", "identity_state"]))
        .or_else(|| nested_str_from_option(details.as_ref(), &["identity_state"]));
    let forward_header_valid =
        nested_bool_from_option(details.as_ref(), &["client_identity", "forward_header_valid"])
            .or_else(|| nested_bool_from_option(details.as_ref(), &["forward_header_valid"]));
    let overload_level =
        nested_str_from_option(details.as_ref(), &["l4_runtime", "overload_level"]);
    let rule_mode =
        nested_str_from_option(details.as_ref(), &["inspection_runtime", "rule_inspection_mode"]);
    let cc_action = nested_str_from_option(details.as_ref(), &["l7", "cc", "action"])
        .or_else(|| nested_str_from_option(details.as_ref(), &["cc_action"]));
    let behavior_action = nested_str_from_option(details.as_ref(), &["l7", "behavior", "action"])
        .or_else(|| nested_str_from_option(details.as_ref(), &["behavior_action"]));
    let primary_signal = derive_primary_signal(
        &entry.reason,
        cc_action.as_deref(),
        behavior_action.as_deref(),
    );
    let labels = derive_security_event_labels(
        &entry.reason,
        identity_state.as_deref(),
        forward_header_valid,
        overload_level.as_deref(),
        rule_mode.as_deref(),
        cc_action.as_deref(),
        behavior_action.as_deref(),
    );

    DerivedSecurityEventSummary {
        identity_state,
        primary_signal: Some(primary_signal),
        labels,
    }
}

fn nested_str(value: &serde_json::Value, path: &[&str]) -> Option<String> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_str().map(|value| value.to_string())
}

fn nested_str_from_option(value: Option<&serde_json::Value>, path: &[&str]) -> Option<String> {
    value.and_then(|value| nested_str(value, path))
}

fn nested_bool_from_option(value: Option<&serde_json::Value>, path: &[&str]) -> Option<bool> {
    let mut current = value?;
    for segment in path {
        current = current.get(*segment)?;
    }
    current.as_bool()
}

fn derive_primary_signal(
    reason: &str,
    cc_action: Option<&str>,
    behavior_action: Option<&str>,
) -> String {
    if let Some(action) = cc_action {
        return format!("l7_cc:{action}");
    }
    if let Some(action) = behavior_action {
        return format!("l7_behavior:{action}");
    }
    if reason.contains("slow attack") {
        return "slow_attack".to_string();
    }
    if reason.contains("SafeLine") {
        return "safeline".to_string();
    }
    if reason.contains("rule") || reason.contains("signature") {
        return "rule_engine".to_string();
    }
    reason.to_ascii_lowercase().replace(' ', "_")
}

fn derive_security_event_labels(
    reason: &str,
    identity_state: Option<&str>,
    forward_header_valid: Option<bool>,
    overload_level: Option<&str>,
    rule_mode: Option<&str>,
    cc_action: Option<&str>,
    behavior_action: Option<&str>,
) -> Vec<String> {
    let mut labels = Vec::new();
    if let Some(identity_state) = identity_state {
        labels.push(format!("identity:{identity_state}"));
    }
    if matches!(forward_header_valid, Some(false)) {
        labels.push("forward_header:invalid".to_string());
    }
    if let Some(level) = overload_level {
        labels.push(format!("l4_overload:{level}"));
    }
    if let Some(mode) = rule_mode {
        labels.push(format!("l7_rules:{mode}"));
    }
    if let Some(action) = cc_action {
        labels.push(format!("cc:{action}"));
    }
    if let Some(action) = behavior_action {
        labels.push(format!("behavior:{action}"));
    }
    if reason.contains("slow attack") {
        labels.push("trigger:slow_attack".to_string());
    }
    if reason.contains("SafeLine") {
        labels.push("trigger:safeline".to_string());
    }
    if reason.contains("rule") || reason.contains("signature") {
        labels.push("trigger:rule_engine".to_string());
    }
    if matches!(identity_state, Some("spoofed_forward_header")) {
        labels.push("trigger:spoofed_header".to_string());
    }
    labels.sort();
    labels.dedup();
    labels
}
