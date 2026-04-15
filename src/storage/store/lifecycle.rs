impl SqliteStore {
    pub async fn new(path: String, auto_migrate: bool) -> Result<Self> {
        Self::new_with_queue_capacity(
            path,
            auto_migrate,
            crate::config::default_sqlite_queue_capacity(),
        )
        .await
    }

    pub async fn new_with_queue_capacity(
        path: String,
        auto_migrate: bool,
        queue_capacity: usize,
    ) -> Result<Self> {
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

        let queue_capacity = queue_capacity.max(1);
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let (realtime_tx, _) = tokio::sync::broadcast::channel(256);
        let cached_security_events: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM security_events")
                .fetch_one(&pool)
                .await?;
        let cached_blocked_ips: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocked_ips")
            .fetch_one(&pool)
            .await?;
        let cached_latest_event_at: Option<i64> =
            sqlx::query_scalar("SELECT MAX(created_at) FROM security_events")
                .fetch_one(&pool)
                .await?;
        let metrics_cache = Arc::new(StorageMetricsCache::new(
            cached_security_events.max(0) as u64,
            cached_blocked_ips.max(0) as u64,
            cached_latest_event_at,
        ));
        let pending_writes = Arc::new(AtomicU64::new(0));
        let pending_write_notify = Arc::new(Notify::new());
        let writer_handle = Arc::new(Mutex::new(Some(tokio::spawn(run_writer(
            pool.clone(),
            receiver,
            realtime_tx.clone(),
            Arc::clone(&metrics_cache),
            Arc::clone(&pending_writes),
            Arc::clone(&pending_write_notify),
        )))));
        let dropped_security_events = Arc::new(AtomicU64::new(0));
        let dropped_blocked_ips = Arc::new(AtomicU64::new(0));

        Ok(Self {
            pool,
            db_path,
            sender,
            queue_capacity,
            pending_writes,
            pending_write_notify,
            writer_handle,
            dropped_security_events,
            dropped_blocked_ips,
            metrics_cache,
            realtime_tx,
        })
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn create_backup(&self) -> Result<PathBuf> {
        self.flush().await?;
        create_backup_snapshot(&self.pool, &self.db_path, BackupKind::Manual).await
    }

    pub fn enqueue_security_event(&self, event: SecurityEventRecord) {
        let queue_depth = self.pending_writes.load(Ordering::Relaxed);
        let mut event = event;
        if queue_depth >= (self.queue_capacity as u64).saturating_mul(3) / 4 {
            if matches!(event.action.as_str(), "log" | "alert") {
                self.dropped_security_events.fetch_add(1, Ordering::Relaxed);
                warn!(
                    "Dropping low-priority security event under SQLite write pressure: action={}, queue_depth={}",
                    event.action, queue_depth
                );
                return;
            }
            crate::storage::apply_write_pressure_detail_slimming(&mut event);
        }
        self.pending_writes.fetch_add(1, Ordering::Relaxed);
        match self
            .sender
            .try_send(StorageCommand::SecurityEvent(event.clone()))
        {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(StorageCommand::SecurityEvent(event)))
            | Err(mpsc::error::TrySendError::Closed(StorageCommand::SecurityEvent(event))) => {
                warn!(
                    "SQLite security event queue is unavailable, falling back to direct persistence"
                );
                let pool = self.pool.clone();
                let realtime_tx = self.realtime_tx.clone();
                let metrics_cache = Arc::clone(&self.metrics_cache);
                let pending_writes = Arc::clone(&self.pending_writes);
                let pending_write_notify = Arc::clone(&self.pending_write_notify);
                tokio::spawn(async move {
                    match persist_security_event(&pool, event, Some(metrics_cache.as_ref())).await {
                        Ok(persisted) => {
                            let _ = realtime_tx.send(
                                crate::storage::StorageRealtimeEvent::SecurityEvent(persisted),
                            );
                        }
                        Err(err) => {
                            warn!("SQLite direct security event persistence failed: {}", err);
                        }
                    }
                    finish_pending_write(&pending_writes, &pending_write_notify);
                });
            }
            Err(_) => {
                self.dropped_security_events.fetch_add(1, Ordering::Relaxed);
                finish_pending_write(&self.pending_writes, &self.pending_write_notify);
                warn!("Failed to enqueue security event for SQLite storage");
            }
        }
    }

    pub fn enqueue_blocked_ip(&self, record: BlockedIpRecord) {
        self.pending_writes.fetch_add(1, Ordering::Relaxed);
        match self
            .sender
            .try_send(StorageCommand::BlockedIp(record.clone()))
        {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(StorageCommand::BlockedIp(record)))
            | Err(mpsc::error::TrySendError::Closed(StorageCommand::BlockedIp(record))) => {
                warn!("SQLite blocked IP queue is unavailable, falling back to direct persistence");
                let pool = self.pool.clone();
                let realtime_tx = self.realtime_tx.clone();
                let metrics_cache = Arc::clone(&self.metrics_cache);
                let pending_writes = Arc::clone(&self.pending_writes);
                let pending_write_notify = Arc::clone(&self.pending_write_notify);
                tokio::spawn(async move {
                    match persist_blocked_ip(&pool, record, Some(metrics_cache.as_ref())).await {
                        Ok(persisted) => {
                            let _ = realtime_tx.send(
                                crate::storage::StorageRealtimeEvent::BlockedIpUpsert(persisted),
                            );
                        }
                        Err(err) => {
                            warn!("SQLite direct blocked IP persistence failed: {}", err);
                        }
                    }
                    finish_pending_write(&pending_writes, &pending_write_notify);
                });
            }
            Err(_) => {
                self.dropped_blocked_ips.fetch_add(1, Ordering::Relaxed);
                finish_pending_write(&self.pending_writes, &self.pending_write_notify);
                warn!("Failed to enqueue blocked IP for SQLite storage");
            }
        }
    }

    pub async fn flush(&self) -> Result<()> {
        let (ack_tx, ack_rx) = oneshot::channel();
        self.sender
            .send(StorageCommand::Flush { ack: ack_tx })
            .await
            .map_err(|_| anyhow::anyhow!("SQLite writer is unavailable during flush"))?;
        ack_rx
            .await
            .map_err(|_| anyhow::anyhow!("SQLite writer flush acknowledgement failed"))?;
        wait_for_pending_writes(&self.pending_writes, &self.pending_write_notify).await;
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        self.flush().await?;
        let (ack_tx, ack_rx) = oneshot::channel();
        self.sender
            .send(StorageCommand::Shutdown { ack: ack_tx })
            .await
            .map_err(|_| anyhow::anyhow!("SQLite writer is unavailable during shutdown"))?;
        ack_rx
            .await
            .map_err(|_| anyhow::anyhow!("SQLite writer shutdown acknowledgement failed"))?;
        if let Some(handle) = self.writer_handle.lock().await.take() {
            handle
                .await
                .map_err(|err| anyhow::anyhow!("SQLite writer task join failed: {}", err))?;
        }
        Ok(())
    }

    pub fn subscribe_realtime(
        &self,
    ) -> tokio::sync::broadcast::Receiver<crate::storage::StorageRealtimeEvent> {
        self.realtime_tx.subscribe()
    }

    pub fn emit_blocked_ip_deleted(&self, id: i64) {
        let _ = self
            .realtime_tx
            .send(crate::storage::StorageRealtimeEvent::BlockedIpDeleted(id));
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
        if imported > 0 {
            self.metrics_cache
                .security_events
                .fetch_add(imported as u64, Ordering::Relaxed);
        }
        if let Some(last_cursor) = last_cursor {
            self.metrics_cache.update_latest_event_at(last_cursor);
        }

        Ok(SafeLineImportResult {
            imported,
            skipped,
            last_cursor,
        })
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn metrics_summary(&self) -> Result<StorageMetricsSummary> {
        let queue_depth = self.pending_writes.load(Ordering::Relaxed);
        let rules: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM rules")
            .fetch_one(&self.pool)
            .await?;
        let latest_rule_update_at: Option<i64> =
            sqlx::query_scalar("SELECT MAX(updated_at) FROM rules")
                .fetch_one(&self.pool)
                .await?;

        Ok(StorageMetricsSummary {
            security_events: self.metrics_cache.security_events(),
            blocked_ips: self.metrics_cache.blocked_ips(),
            latest_event_at: self.metrics_cache.latest_event_at(),
            rules: rules.max(0) as u64,
            latest_rule_update_at,
            queue_capacity: self.queue_capacity as u64,
            queue_depth,
            dropped_security_events: self.dropped_security_events.load(Ordering::Relaxed),
            dropped_blocked_ips: self.dropped_blocked_ips.load(Ordering::Relaxed),
        })
    }
}
