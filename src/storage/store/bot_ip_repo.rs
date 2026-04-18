impl SqliteStore {
    pub async fn list_bot_ip_cache_entries(&self) -> Result<Vec<BotIpCacheEntry>> {
        let items = sqlx::query_as::<_, BotIpCacheEntry>(
            r#"
            SELECT provider, ranges_json, last_refresh_at, last_success_at, last_error, updated_at
            FROM bot_ip_cache
            ORDER BY provider ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(items)
    }

    pub async fn upsert_bot_ip_cache_entry(
        &self,
        provider: &str,
        ranges_json: &str,
        last_refresh_at: Option<i64>,
        last_success_at: Option<i64>,
        last_error: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO bot_ip_cache (
                provider, ranges_json, last_refresh_at, last_success_at, last_error, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider) DO UPDATE SET
                ranges_json = excluded.ranges_json,
                last_refresh_at = excluded.last_refresh_at,
                last_success_at = excluded.last_success_at,
                last_error = excluded.last_error,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(provider)
        .bind(ranges_json)
        .bind(last_refresh_at)
        .bind(last_success_at)
        .bind(last_error)
        .bind(unix_timestamp())
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
