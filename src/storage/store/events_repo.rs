impl SqliteStore {
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

        let mut count_builder =
            QueryBuilder::<Sqlite>::new("SELECT COUNT(*) FROM security_events WHERE 1=1");
        append_security_event_filters(&mut count_builder, query);
        let total: i64 = count_builder
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await?;

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
        builder.push(" LIMIT ");
        builder.push_bind(i64::from(limit));
        builder.push(" OFFSET ");
        builder.push_bind(i64::from(offset));

        let items = builder
            .build_query_as::<SecurityEventEntry>()
            .fetch_all(&self.pool)
            .await?;

        Ok(PagedResult {
            total: total.max(0) as u64,
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
}
