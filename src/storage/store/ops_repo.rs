impl SqliteStore {
    pub async fn mark_security_event_handled(&self, id: i64, handled: bool) -> Result<bool> {
        let handled_at = if handled {
            Some(unix_timestamp())
        } else {
            None
        };
        let result = sqlx::query(
            r#"
            UPDATE security_events
            SET handled = ?, handled_at = ?
            WHERE id = ?
            "#,
        )
        .bind(if handled { 1 } else { 0 })
        .bind(handled_at)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }
}
