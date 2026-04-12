impl SqliteStore {
    pub async fn seed_app_config(&self, config: &Config) -> Result<bool> {
        let config_json = serde_json::to_string(config)?;
        let result = sqlx::query(
            r#"
            INSERT OR IGNORE INTO app_config (
                id, config_json, updated_at
            )
            VALUES (?, ?, ?)
            "#,
        )
        .bind(1_i64)
        .bind(config_json)
        .bind(unix_timestamp())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn load_app_config(&self) -> Result<Option<Config>> {
        let row = sqlx::query_as::<_, StoredAppConfigRow>(
            r#"
            SELECT config_json
            FROM app_config
            WHERE id = 1
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        row.map(TryInto::try_into).transpose()
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn upsert_app_config(&self, config: &Config) -> Result<()> {
        let config_json = serde_json::to_string(config)?;
        sqlx::query(
            r#"
            INSERT INTO app_config (
                id, config_json, updated_at
            )
            VALUES (?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                config_json = excluded.config_json,
                updated_at = excluded.updated_at
            "#,
        )
        .bind(1_i64)
        .bind(config_json)
        .bind(unix_timestamp())
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
