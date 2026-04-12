impl SqliteStore {
    pub async fn new(path: String, auto_migrate: bool) -> Result<Self> {
        let db_path = PathBuf::from(path);
        ensure_parent_dir(&db_path).await?;
        let existed_before = tokio::fs::try_exists(&db_path).await.unwrap_or(false);

        info!(
            "Opening SQLite database: path={}, existed_before={}, auto_migrate={}, journal_mode=WAL, synchronous=NORMAL",
            db_path.display(),
            existed_before,
            auto_migrate
        );

        let pool = match open_pool(&db_path, auto_migrate).await {
            Ok(pool) => {
                info!("SQLite database is ready: {}", db_path.display());
                pool
            }
            Err(err) if is_sqlite_corruption_error(&err) => {
                warn!(
                    "SQLite database at {} is corrupted, backing it up and recreating a fresh database",
                    db_path.display()
                );
                let backup_path = backup_corrupted_db(&db_path).await?;
                warn!(
                    "Moved corrupted SQLite database to backup: {}",
                    backup_path.display()
                );
                let pool = open_pool(&db_path, auto_migrate).await?;
                info!(
                    "Recreated SQLite database after recovery: {}",
                    db_path.display()
                );
                pool
            }
            Err(err) => {
                log_sqlite_open_error(&db_path, &err);
                return Err(err);
            }
        };

        if existed_before {
            match create_backup_snapshot(&pool, &db_path, BackupKind::Startup).await {
                Ok(backup_path) => {
                    info!("Created SQLite startup backup: {}", backup_path.display())
                }
                Err(err) => warn!(
                    "Failed to create SQLite startup backup for {}: {}",
                    db_path.display(),
                    err
                ),
            }
        }

        let (sender, receiver) = mpsc::channel(STORAGE_QUEUE_CAPACITY);
        tokio::spawn(run_writer(pool.clone(), receiver));

        Ok(Self {
            pool,
            db_path,
            sender,
        })
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn create_backup(&self) -> Result<PathBuf> {
        create_backup_snapshot(&self.pool, &self.db_path, BackupKind::Manual).await
    }

    pub fn enqueue_security_event(&self, event: SecurityEventRecord) {
        if let Err(err) = self.sender.try_send(StorageCommand::SecurityEvent(event)) {
            warn!(
                "Failed to enqueue security event for SQLite storage: {}",
                err
            );
        }
    }

    pub fn enqueue_blocked_ip(&self, record: BlockedIpRecord) {
        if let Err(err) = self.sender.try_send(StorageCommand::BlockedIp(record)) {
            warn!("Failed to enqueue blocked IP for SQLite storage: {}", err);
        }
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn import_safeline_security_events(
        &self,
        events: &[SecurityEventRecord],
    ) -> Result<SafeLineImportResult> {
        let mut tx = self.pool.begin().await?;
        let mut imported = 0usize;
        let mut skipped = 0usize;
        let mut last_cursor = None;

        for event in events {
            let fingerprint = fingerprint_security_event(event);
            let dedup_result = sqlx::query(
                r#"
                INSERT OR IGNORE INTO safeline_event_dedup (
                    fingerprint, created_at, imported_at
                )
                VALUES (?, ?, ?)
                "#,
            )
            .bind(&fingerprint)
            .bind(event.created_at)
            .bind(unix_timestamp())
            .execute(&mut *tx)
            .await?;

            if dedup_result.rows_affected() == 0 {
                skipped += 1;
                continue;
            }

            sqlx::query(
                r#"
                INSERT INTO security_events (
                    layer, provider, provider_event_id, provider_site_id, provider_site_name,
                    provider_site_domain, action, reason, details_json, source_ip, dest_ip,
                    source_port, dest_port, protocol, http_method, uri,
                    http_version, created_at, handled, handled_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&event.layer)
            .bind(&event.provider)
            .bind(&event.provider_event_id)
            .bind(&event.provider_site_id)
            .bind(&event.provider_site_name)
            .bind(&event.provider_site_domain)
            .bind(&event.action)
            .bind(&event.reason)
            .bind(&event.details_json)
            .bind(&event.source_ip)
            .bind(&event.dest_ip)
            .bind(event.source_port)
            .bind(event.dest_port)
            .bind(&event.protocol)
            .bind(&event.http_method)
            .bind(&event.uri)
            .bind(&event.http_version)
            .bind(event.created_at)
            .bind(if event.handled { 1 } else { 0 })
            .bind(event.handled_at)
            .execute(&mut *tx)
            .await?;

            imported += 1;
            last_cursor = Some(last_cursor.map_or(event.created_at, |current: i64| {
                current.max(event.created_at)
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
        .bind("events")
        .bind(last_cursor)
        .bind(now)
        .bind(imported as i64)
        .bind(skipped as i64)
        .bind(now)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(SafeLineImportResult {
            imported,
            skipped,
            last_cursor,
        })
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn metrics_summary(&self) -> Result<StorageMetricsSummary> {
        let security_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_events")
            .fetch_one(&self.pool)
            .await?;
        let blocked_ips: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocked_ips")
            .fetch_one(&self.pool)
            .await?;
        let latest_event_at: Option<i64> =
            sqlx::query_scalar("SELECT MAX(created_at) FROM security_events")
                .fetch_one(&self.pool)
                .await?;
        let rules: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rules")
            .fetch_one(&self.pool)
            .await?;
        let latest_rule_update_at: Option<i64> =
            sqlx::query_scalar("SELECT MAX(updated_at) FROM rules")
                .fetch_one(&self.pool)
                .await?;

        Ok(StorageMetricsSummary {
            security_events: security_events.max(0) as u64,
            blocked_ips: blocked_ips.max(0) as u64,
            latest_event_at,
            rules: rules.max(0) as u64,
            latest_rule_update_at,
        })
    }

}
