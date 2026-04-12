impl SqliteStore {
    pub async fn import_safeline_blocked_ips_sync_result(
        &self,
        synced_records: &[BlockedIpEntry],
        failed: usize,
    ) -> Result<SafeLineBlocklistSyncResult> {
        let mut tx = self.pool.begin().await?;
        let mut synced = 0usize;
        let mut skipped = 0usize;
        let mut last_cursor = None;

        for record in synced_records {
            let fingerprint = fingerprint_blocked_ip(record);
            let result = sqlx::query(
                r#"
                INSERT OR IGNORE INTO safeline_blocked_ip_sync_dedup (
                    fingerprint, ip, expires_at, synced_at
                )
                VALUES (?, ?, ?, ?)
                "#,
            )
            .bind(&fingerprint)
            .bind(&record.ip)
            .bind(record.expires_at)
            .bind(unix_timestamp())
            .execute(&mut *tx)
            .await?;

            if result.rows_affected() == 0 {
                skipped += 1;
            } else {
                synced += 1;
                last_cursor = Some(last_cursor.map_or(record.expires_at, |current: i64| {
                    current.max(record.expires_at)
                }));
            }
        }

        let now = unix_timestamp();
        sqlx::query(
            r#"
            INSERT INTO safeline_sync_state (
                resource, last_cursor, last_success_at, last_imported_count, last_skipped_count, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(resource) DO UPDATE SET
                last_cursor = excluded.last_cursor,
                last_success_at = excluded.last_success_at,
                last_imported_count = excluded.last_imported_count,
                last_skipped_count = excluded.last_skipped_count,
                updated_at = excluded.updated_at
            "#,
        )
        .bind("blocked_ips_push")
        .bind(last_cursor)
        .bind(now)
        .bind(synced as i64)
        .bind((skipped + failed) as i64)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(SafeLineBlocklistSyncResult {
            synced,
            skipped,
            failed,
            last_cursor,
        })
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn import_safeline_blocked_ips_pull(
        &self,
        records: &[BlockedIpRecord],
    ) -> Result<SafeLineBlocklistPullResult> {
        let mut tx = self.pool.begin().await?;
        let mut imported = 0usize;
        let mut skipped = 0usize;
        let mut last_cursor = None;

        for record in records {
            let fingerprint = fingerprint_blocked_ip_record(record);
            let dedup = sqlx::query(
                r#"
                INSERT OR IGNORE INTO safeline_blocked_ip_pull_dedup (
                    fingerprint, ip, expires_at, synced_at
                )
                VALUES (?, ?, ?, ?)
                "#,
            )
            .bind(&fingerprint)
            .bind(&record.ip)
            .bind(record.expires_at)
            .bind(unix_timestamp())
            .execute(&mut *tx)
            .await?;

            if dedup.rows_affected() == 0 {
                skipped += 1;
                continue;
            }

            sqlx::query(
                r#"
                INSERT INTO blocked_ips (
                    provider, provider_remote_id, ip, reason, blocked_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&record.provider)
            .bind(&record.provider_remote_id)
            .bind(&record.ip)
            .bind(&record.reason)
            .bind(record.blocked_at)
            .bind(record.expires_at)
            .execute(&mut *tx)
            .await?;

            imported += 1;
            last_cursor = Some(last_cursor.map_or(record.expires_at, |current: i64| {
                current.max(record.expires_at)
            }));
        }

        let now = unix_timestamp();
        sqlx::query(
            r#"
            INSERT INTO safeline_sync_state (
                resource, last_cursor, last_success_at, last_imported_count, last_skipped_count, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(resource) DO UPDATE SET
                last_cursor = excluded.last_cursor,
                last_success_at = excluded.last_success_at,
                last_imported_count = excluded.last_imported_count,
                last_skipped_count = excluded.last_skipped_count,
                updated_at = excluded.updated_at
            "#,
        )
        .bind("blocked_ips_pull")
        .bind(last_cursor)
        .bind(now)
        .bind(imported as i64)
        .bind(skipped as i64)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(SafeLineBlocklistPullResult {
            imported,
            skipped,
            last_cursor,
        })
    }

}
