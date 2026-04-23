use crate::locks::mutex_lock;

impl SqliteStore {
    pub fn queue_depth(&self) -> u64 {
        self.pending_writes.load(Ordering::Relaxed)
    }

    pub fn queue_capacity(&self) -> u64 {
        self.queue_capacity as u64
    }

    pub fn queue_usage_percent(&self) -> u64 {
        let capacity = self.queue_capacity();
        if capacity == 0 {
            0
        } else {
            self.queue_depth().saturating_mul(100) / capacity
        }
    }

    pub async fn new(path: String, auto_migrate: bool) -> Result<Self> {
        Self::new_with_runtime_options(
            path,
            auto_migrate,
            crate::config::default_sqlite_queue_capacity(),
            0,
        )
        .await
    }

    pub async fn new_with_queue_capacity(
        path: String,
        auto_migrate: bool,
        queue_capacity: usize,
    ) -> Result<Self> {
        Self::new_with_runtime_options(path, auto_migrate, queue_capacity, 0).await
    }

    pub async fn new_with_runtime_options(
        path: String,
        auto_migrate: bool,
        queue_capacity: usize,
        pool_size: usize,
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

        let pool_size = pool_size.clamp(1, 32) as u32;
        let pool = match open_pool(&db_path, auto_migrate, pool_size).await {
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
                let pool = open_pool(&db_path, auto_migrate, pool_size).await?;
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
        let aggregated_security_events =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let aggregated_security_event_candidates =
            Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

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
            aggregated_security_events,
            aggregated_security_event_candidates,
        })
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn create_backup(&self) -> Result<PathBuf> {
        self.flush().await?;
        create_backup_snapshot(&self.pool, &self.db_path, BackupKind::Manual).await
    }

    pub fn enqueue_security_event(&self, event: SecurityEventRecord) {
        let queue_depth = self.queue_depth();
        let queue_capacity = self.queue_capacity();
        let mut event = event;
        let elevated_pressure = queue_depth >= queue_capacity.saturating_mul(3) / 4;
        let critical_pressure = queue_depth >= queue_capacity.saturating_mul(9) / 10;
        if elevated_pressure {
            if should_drop_security_event_under_pressure(&event, critical_pressure) {
                self.aggregate_security_event(event, queue_depth, "queue_pressure");
                return;
            }
            crate::storage::apply_write_pressure_detail_slimming(&mut event);
        }
        self.pending_writes.fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(StorageCommand::SecurityEvent(event.clone())) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(StorageCommand::SecurityEvent(event))) => {
                finish_pending_write(&self.pending_writes, &self.pending_write_notify);
                if should_aggregate_security_event(&event) {
                    self.aggregate_security_event(event, queue_depth, "queue_full");
                } else {
                    self.dropped_security_events.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "Dropping security event because SQLite queue is full: queue_depth={}, queue_capacity={}",
                        queue_depth, queue_capacity
                    );
                }
            }
            Err(mpsc::error::TrySendError::Closed(StorageCommand::SecurityEvent(event))) => {
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

    pub fn enqueue_security_event_aggregated(
        &self,
        event: SecurityEventRecord,
        trigger: &'static str,
    ) {
        self.aggregate_security_event(event, self.queue_depth(), trigger);
    }

    pub fn enqueue_blocked_ip(&self, record: BlockedIpRecord) {
        let queue_depth = self.queue_depth();
        let queue_capacity = self.queue_capacity();
        self.pending_writes.fetch_add(1, Ordering::Relaxed);
        match self.sender.try_send(StorageCommand::BlockedIp(record.clone())) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(StorageCommand::BlockedIp(record))) => {
                warn!(
                    "SQLite queue is full for blocked IP persistence, falling back to direct persistence: queue_depth={}, queue_capacity={}",
                    queue_depth, queue_capacity
                );
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
            Err(mpsc::error::TrySendError::Closed(StorageCommand::BlockedIp(record))) => {
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
                warn!(
                    "Failed to enqueue blocked IP for SQLite storage: queue_depth={}, queue_capacity={}",
                    queue_depth, queue_capacity
                );
                finish_pending_write(&self.pending_writes, &self.pending_write_notify);
            }
        }
    }

    pub async fn flush(&self) -> Result<()> {
        self.flush_aggregated_security_events().await?;
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

    pub async fn flush_aggregated_security_events(&self) -> Result<u64> {
        let drained = {
            let mut guard =
                mutex_lock(&self.aggregated_security_events, "aggregated_security_events");
            guard.drain().map(|(_, bucket)| bucket).collect::<Vec<_>>()
        };
        mutex_lock(
            &self.aggregated_security_event_candidates,
            "aggregated_security_event_candidates",
        )
        .clear();
        let flushed = drained.len() as u64;
        for bucket in drained {
            let event = aggregated_bucket_to_event(bucket);
            persist_security_event(&self.pool, event, Some(self.metrics_cache.as_ref())).await?;
        }
        Ok(flushed)
    }

    pub fn aggregation_insight_summary(&self) -> StorageAggregationInsightSummary {
        let guard = mutex_lock(&self.aggregated_security_events, "aggregated_security_events");
        let active_bucket_count = guard.len() as u64;
        let active_event_count = guard.values().map(|bucket| bucket.count).sum::<u64>();
        let mut hotspot_sources = guard
            .values()
            .filter(|bucket| !bucket.long_tail)
            .map(|bucket| StorageAggregationHotspot {
                source_ip: bucket.source_ip.clone(),
                action: bucket.action.clone(),
                route: bucket.uri.clone(),
                count: bucket.count,
                time_window_start: bucket.time_window_start,
                time_window_end: bucket.time_window_end,
            })
            .collect::<Vec<_>>();
        hotspot_sources.sort_by(|left, right| {
            right
                .count
                .cmp(&left.count)
                .then_with(|| right.time_window_end.cmp(&left.time_window_end))
                .then_with(|| left.source_ip.cmp(&right.source_ip))
        });
        hotspot_sources.truncate(5);

        let long_tail_bucket_count = guard.values().filter(|bucket| bucket.long_tail).count() as u64;
        let long_tail_event_count = guard
            .values()
            .filter(|bucket| bucket.long_tail)
            .map(|bucket| bucket.count)
            .sum::<u64>();

        StorageAggregationInsightSummary {
            active_bucket_count,
            active_event_count,
            hotspot_sources,
            long_tail_bucket_count,
            long_tail_event_count,
        }
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

    fn aggregate_security_event(
        &self,
        event: SecurityEventRecord,
        queue_depth: u64,
        trigger: &'static str,
    ) {
        let max_bucket_count = aggregated_security_bucket_limit(self.queue_capacity);
        let direct_key = aggregated_security_event_key(&event);
        let candidate_hits = {
            let mut guard = mutex_lock(
                &self.aggregated_security_event_candidates,
                "aggregated_security_event_candidates",
            );
            let hits = guard.entry(direct_key.clone()).or_insert(0);
            *hits = hits.saturating_add(1);
            *hits
        };
        let mut guard = mutex_lock(&self.aggregated_security_events, "aggregated_security_events");
        let bucket_key = resolve_aggregated_security_event_key(
            &event,
            &direct_key,
            candidate_hits,
            &mut guard,
            max_bucket_count,
        );
        let long_tail = is_long_tail_aggregation_key(&bucket_key);
        let entry = guard.entry(bucket_key).or_insert_with(|| AggregatedSecurityEventBucket {
            layer: event.layer.clone(),
            action: event.action.clone(),
            reason: event.reason.clone(),
            source_ip: if long_tail {
                "*".to_string()
            } else {
                event.source_ip.clone()
            },
            dest_ip: event.dest_ip.clone(),
            protocol: event.protocol.clone(),
            http_method: event.http_method.clone(),
            uri: event.uri.clone(),
            http_version: event.http_version.clone(),
            count: 0,
            long_tail,
            time_window_start: aggregated_security_event_window_start(event.created_at),
            time_window_end: aggregated_security_event_window_end(event.created_at),
            first_created_at: event.created_at,
            last_created_at: event.created_at,
        });
        entry.count = entry.count.saturating_add(1);
        entry.first_created_at = entry.first_created_at.min(event.created_at);
        entry.last_created_at = entry.last_created_at.max(event.created_at);
        entry.time_window_start =
            entry.time_window_start.min(aggregated_security_event_window_start(event.created_at));
        entry.time_window_end =
            entry.time_window_end.max(aggregated_security_event_window_end(event.created_at));
        log::info!(
            "Aggregating repeated security event under storage pressure: action={}, trigger={}, queue_depth={}, aggregate_count={}, long_tail={}",
            entry.action,
            trigger,
            queue_depth,
            entry.count,
            entry.long_tail
        );
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
        let queue_depth = self.queue_depth();
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
            queue_capacity: self.queue_capacity(),
            queue_depth,
            dropped_security_events: self.dropped_security_events.load(Ordering::Relaxed),
            dropped_blocked_ips: self.dropped_blocked_ips.load(Ordering::Relaxed),
        })
    }
}

fn should_drop_security_event_under_pressure(
    event: &SecurityEventRecord,
    critical_pressure: bool,
) -> bool {
    if matches!(event.action.as_str(), "log" | "alert") {
        return true;
    }

    critical_pressure && matches!(event.action.as_str(), "respond" | "allow" | "block" | "drop")
}

fn should_aggregate_security_event(event: &SecurityEventRecord) -> bool {
    matches!(
        event.action.as_str(),
        "log" | "alert" | "respond" | "allow" | "block" | "drop"
    )
}

fn aggregated_security_event_key(event: &SecurityEventRecord) -> String {
    format!(
        "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        event.layer,
        event.action,
        event.reason,
        event.source_ip,
        event.dest_ip,
        event.protocol,
        event.http_method.as_deref().unwrap_or("*"),
        normalized_aggregation_route(event.uri.as_deref()),
        aggregated_security_event_window_start(event.created_at),
    )
}

fn aggregated_long_tail_security_event_key(event: &SecurityEventRecord) -> String {
    format!(
        "lt\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
        event.layer,
        event.action,
        event.reason,
        event.dest_ip,
        event.protocol,
        event.http_method.as_deref().unwrap_or("*"),
        normalized_aggregation_route(event.uri.as_deref()),
        aggregated_security_event_window_start(event.created_at),
    )
}

fn resolve_aggregated_security_event_key(
    event: &SecurityEventRecord,
    direct_key: &str,
    candidate_hits: u64,
    guard: &mut std::collections::HashMap<String, AggregatedSecurityEventBucket>,
    max_bucket_count: usize,
) -> String {
    if guard.contains_key(direct_key) {
        return direct_key.to_string();
    }
    if guard.len() < max_bucket_count {
        return direct_key.to_string();
    }
    if candidate_hits >= hotspot_promotion_threshold() {
        if let Some(coldest_key) = find_coldest_hotspot_bucket_key(guard) {
            guard.remove(&coldest_key);
            return direct_key.to_string();
        }
    }
    aggregated_long_tail_security_event_key(event)
}

fn is_long_tail_aggregation_key(key: &str) -> bool {
    key.starts_with("lt\u{1f}")
}

fn aggregated_security_bucket_limit(queue_capacity: usize) -> usize {
    queue_capacity.clamp(1, 2048).div_ceil(4).clamp(32, 256)
}

fn hotspot_promotion_threshold() -> u64 {
    4
}

fn find_coldest_hotspot_bucket_key(
    guard: &std::collections::HashMap<String, AggregatedSecurityEventBucket>,
) -> Option<String> {
    guard
        .iter()
        .filter(|(_, bucket)| !bucket.long_tail)
        .min_by_key(|(_, bucket)| {
            (
                bucket.count,
                bucket.last_created_at,
                bucket.first_created_at,
            )
        })
        .map(|(key, _)| key.clone())
}

fn aggregated_bucket_to_event(bucket: AggregatedSecurityEventBucket) -> SecurityEventRecord {
    let mut event = SecurityEventRecord::now(
        bucket.layer,
        "summary",
        format!("aggregated {} repeated security events", bucket.count),
        bucket.source_ip,
        bucket.dest_ip,
        0,
        0,
        bucket.protocol,
    );
    event.http_method = bucket.http_method;
    event.uri = bucket.uri.clone();
    event.http_version = bucket.http_version;
    event.created_at = bucket.last_created_at;
    event.details_json = Some(
        serde_json::json!({
            "storage_pressure": {
                "mode": "aggregated",
                "action": bucket.action,
                "original_reason": bucket.reason,
                "count": bucket.count,
                "source_scope": if bucket.long_tail { "long_tail" } else { "hotspot" },
                "route": bucket.uri,
                "time_window_start": bucket.time_window_start,
                "time_window_end": bucket.time_window_end,
                "first_created_at": bucket.first_created_at,
                "last_created_at": bucket.last_created_at,
            }
        })
        .to_string(),
    );
    event
}

fn aggregated_security_event_window_start(created_at: i64) -> i64 {
    created_at.div_euclid(crate::storage::AGGREGATED_SECURITY_EVENT_WINDOW_SECS)
        * crate::storage::AGGREGATED_SECURITY_EVENT_WINDOW_SECS
}

fn aggregated_security_event_window_end(created_at: i64) -> i64 {
    aggregated_security_event_window_start(created_at)
        + crate::storage::AGGREGATED_SECURITY_EVENT_WINDOW_SECS
}

fn normalized_aggregation_route(uri: Option<&str>) -> &str {
    uri.and_then(|value| value.split('?').next())
        .filter(|value| !value.is_empty())
        .unwrap_or("*")
}
