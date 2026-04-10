use crate::config::{Config, Rule, RuleAction, RuleLayer, Severity};
use anyhow::Result;
use log::{debug, warn};
use sha2::{Digest, Sha256};
use serde_json;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;
#[cfg(any(feature = "api", test))]
use sqlx::{QueryBuilder, Sqlite};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

const STORAGE_QUEUE_CAPACITY: usize = 1024;

#[derive(Clone)]
pub struct SqliteStore {
    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pool: SqlitePool,
    sender: mpsc::Sender<StorageCommand>,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, Default)]
pub struct StorageMetricsSummary {
    pub security_events: u64,
    pub blocked_ips: u64,
    pub latest_event_at: Option<i64>,
    pub rules: u64,
    pub latest_rule_update_at: Option<i64>,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone, Default)]
pub struct SecurityEventQuery {
    pub limit: u32,
    pub offset: u32,
    pub layer: Option<String>,
    pub provider: Option<String>,
    pub provider_site_id: Option<String>,
    pub source_ip: Option<String>,
    pub action: Option<String>,
    pub blocked_only: bool,
    pub handled_only: Option<bool>,
    pub created_from: Option<i64>,
    pub created_to: Option<i64>,
    pub sort_by: EventSortField,
    pub sort_direction: SortDirection,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone, Default)]
pub struct BlockedIpQuery {
    pub limit: u32,
    pub offset: u32,
    pub provider: Option<String>,
    pub ip: Option<String>,
    pub active_only: bool,
    pub blocked_from: Option<i64>,
    pub blocked_to: Option<i64>,
    pub sort_by: BlockedIpSortField,
    pub sort_direction: SortDirection,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone, Copy, Default)]
pub enum SortDirection {
    Asc,
    #[default]
    Desc,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone, Copy, Default)]
pub enum EventSortField {
    #[default]
    CreatedAt,
    SourceIp,
    DestPort,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone, Copy, Default)]
pub enum BlockedIpSortField {
    #[default]
    BlockedAt,
    ExpiresAt,
    Ip,
}

#[cfg(any(feature = "api", test))]
#[derive(Debug, Clone)]
pub struct PagedResult<T> {
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
    pub items: Vec<T>,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SecurityEventEntry {
    pub id: i64,
    pub layer: String,
    pub provider: Option<String>,
    pub provider_site_id: Option<String>,
    pub provider_site_name: Option<String>,
    pub provider_site_domain: Option<String>,
    pub action: String,
    pub reason: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: i64,
    pub dest_port: i64,
    pub protocol: String,
    pub http_method: Option<String>,
    pub uri: Option<String>,
    pub http_version: Option<String>,
    pub created_at: i64,
    pub handled: bool,
    pub handled_at: Option<i64>,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BlockedIpEntry {
    pub id: i64,
    pub provider: Option<String>,
    pub provider_remote_id: Option<String>,
    pub ip: String,
    pub reason: String,
    pub blocked_at: i64,
    pub expires_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SafeLineSiteMappingEntry {
    pub id: i64,
    pub safeline_site_id: String,
    pub safeline_site_name: String,
    pub safeline_site_domain: String,
    pub local_alias: String,
    pub enabled: bool,
    pub is_primary: bool,
    pub notes: String,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SafeLineSyncStateEntry {
    pub resource: String,
    pub last_cursor: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_imported_count: i64,
    pub last_skipped_count: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineDeleteResult {
    pub success: usize,
    pub failed: usize,
    pub last_cursor: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineBlocklistSyncResult {
    pub synced: usize,
    pub skipped: usize,
    pub failed: usize,
    pub last_cursor: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineBlocklistPullResult {
    pub imported: usize,
    pub skipped: usize,
    pub last_cursor: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct SecurityEventRecord {
    pub layer: String,
    pub provider: Option<String>,
    pub provider_site_id: Option<String>,
    pub provider_site_name: Option<String>,
    pub provider_site_domain: Option<String>,
    pub action: String,
    pub reason: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: i64,
    pub dest_port: i64,
    pub protocol: String,
    pub http_method: Option<String>,
    pub uri: Option<String>,
    pub http_version: Option<String>,
    pub created_at: i64,
    pub handled: bool,
    pub handled_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct BlockedIpRecord {
    pub provider: Option<String>,
    pub provider_remote_id: Option<String>,
    pub ip: String,
    pub reason: String,
    pub blocked_at: i64,
    pub expires_at: i64,
}

enum StorageCommand {
    SecurityEvent(SecurityEventRecord),
    BlockedIp(BlockedIpRecord),
}

impl SqliteStore {
    pub async fn new(path: String, auto_migrate: bool) -> Result<Self> {
        let db_path = PathBuf::from(path);
        ensure_parent_dir(&db_path).await?;

        let connect_options =
            SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))?
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Normal)
                .foreign_keys(true);

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(connect_options)
            .await?;

        if auto_migrate {
            initialize_schema(&pool).await?;
        }

        let (sender, receiver) = mpsc::channel(STORAGE_QUEUE_CAPACITY);
        tokio::spawn(run_writer(pool.clone(), receiver));

        Ok(Self { pool, sender })
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
                    layer, provider, provider_site_id, provider_site_name, provider_site_domain,
                    action, reason, source_ip, dest_ip, source_port, dest_port,
                    protocol, http_method, uri, http_version, created_at, handled, handled_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&event.layer)
            .bind(&event.provider)
            .bind(&event.provider_site_id)
            .bind(&event.provider_site_name)
            .bind(&event.provider_site_domain)
            .bind(&event.action)
            .bind(&event.reason)
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
            last_cursor = Some(
                last_cursor.map_or(event.created_at, |current: i64| current.max(event.created_at)),
            );
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

    pub async fn seed_rules(&self, rules: &[Rule]) -> Result<usize> {
        let mut inserted = 0usize;

        for rule in rules {
            let result = sqlx::query(
                r#"
                INSERT OR IGNORE INTO rules (
                    id, name, enabled, layer, pattern, action, severity, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&rule.id)
            .bind(&rule.name)
            .bind(rule.enabled)
            .bind(rule.layer.as_str())
            .bind(&rule.pattern)
            .bind(rule.action.as_str())
            .bind(rule.severity.as_str())
            .bind(unix_timestamp())
            .execute(&self.pool)
            .await?;

            inserted += result.rows_affected() as usize;
        }

        Ok(inserted)
    }

    pub async fn load_rules(&self) -> Result<Vec<Rule>> {
        let rows = sqlx::query_as::<_, StoredRuleRow>(
            r#"
            SELECT id, name, enabled, layer, pattern, action, severity
            FROM rules
            ORDER BY id ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(TryInto::try_into).collect()
    }

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

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn list_safeline_site_mappings(&self) -> Result<Vec<SafeLineSiteMappingEntry>> {
        let rows = sqlx::query_as::<_, SafeLineSiteMappingEntry>(
            r#"
            SELECT id, safeline_site_id, safeline_site_name, safeline_site_domain,
                   local_alias, enabled, is_primary, notes, updated_at
            FROM safeline_site_mappings
            ORDER BY is_primary DESC, updated_at DESC, id DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn replace_safeline_site_mappings(
        &self,
        mappings: &[SafeLineSiteMappingUpsert],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        sqlx::query("DELETE FROM safeline_site_mappings")
            .execute(&mut *tx)
            .await?;

        for mapping in mappings {
            sqlx::query(
                r#"
                INSERT INTO safeline_site_mappings (
                    safeline_site_id, safeline_site_name, safeline_site_domain,
                    local_alias, enabled, is_primary, notes, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                "#,
            )
            .bind(&mapping.safeline_site_id)
            .bind(&mapping.safeline_site_name)
            .bind(&mapping.safeline_site_domain)
            .bind(&mapping.local_alias)
            .bind(mapping.enabled)
            .bind(mapping.is_primary)
            .bind(&mapping.notes)
            .bind(unix_timestamp())
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn load_safeline_sync_state(
        &self,
        resource: &str,
    ) -> Result<Option<SafeLineSyncStateEntry>> {
        let row = sqlx::query_as::<_, SafeLineSyncStateEntry>(
            r#"
            SELECT resource, last_cursor, last_success_at, last_imported_count, last_skipped_count, updated_at
            FROM safeline_sync_state
            WHERE resource = ?
            "#,
        )
        .bind(resource)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn upsert_safeline_sync_state(
        &self,
        resource: &str,
        last_cursor: Option<i64>,
        imported: usize,
        skipped: usize,
    ) -> Result<()> {
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
        .bind(resource)
        .bind(last_cursor)
        .bind(now)
        .bind(imported as i64)
        .bind(skipped as i64)
        .bind(now)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
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
                last_cursor = Some(last_cursor.map_or(record.expires_at, |current: i64| current.max(record.expires_at)));
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
            last_cursor =
                Some(last_cursor.map_or(record.expires_at, |current: i64| current.max(record.expires_at)));
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
            SELECT id, layer, provider, provider_site_id, provider_site_name, provider_site_domain,
                   action, reason, source_ip, dest_ip, source_port, dest_port,
                   protocol, http_method, uri, http_version, created_at, handled, handled_at
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
            SELECT id, name, enabled, layer, pattern, action, severity
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
                id, name, enabled, layer, pattern, action, severity, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&rule.id)
        .bind(&rule.name)
        .bind(rule.enabled)
        .bind(rule.layer.as_str())
        .bind(&rule.pattern)
        .bind(rule.action.as_str())
        .bind(rule.severity.as_str())
        .bind(unix_timestamp())
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub async fn upsert_rule(&self, rule: &Rule) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO rules (id, name, enabled, layer, pattern, action, severity, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                enabled = excluded.enabled,
                layer = excluded.layer,
                pattern = excluded.pattern,
                action = excluded.action,
                severity = excluded.severity,
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

impl SecurityEventRecord {
    pub fn now(
        layer: impl Into<String>,
        action: impl Into<String>,
        reason: impl Into<String>,
        source_ip: impl Into<String>,
        dest_ip: impl Into<String>,
        source_port: u16,
        dest_port: u16,
        protocol: impl Into<String>,
    ) -> Self {
        Self {
            layer: layer.into(),
            provider: None,
            provider_site_id: None,
            provider_site_name: None,
            provider_site_domain: None,
            action: action.into(),
            reason: reason.into(),
            source_ip: source_ip.into(),
            dest_ip: dest_ip.into(),
            source_port: i64::from(source_port),
            dest_port: i64::from(dest_port),
            protocol: protocol.into(),
            http_method: None,
            uri: None,
            http_version: None,
            created_at: unix_timestamp(),
            handled: false,
            handled_at: None,
        }
    }
}

impl BlockedIpRecord {
    pub fn new(
        ip: impl Into<String>,
        reason: impl Into<String>,
        blocked_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            provider: None,
            provider_remote_id: None,
            ip: ip.into(),
            reason: reason.into(),
            blocked_at,
            expires_at,
        }
    }
}

async fn initialize_schema(pool: &SqlitePool) -> Result<()> {
    sqlx::raw_sql(
        r#"
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            layer TEXT NOT NULL,
            provider TEXT,
            provider_site_id TEXT,
            provider_site_name TEXT,
            provider_site_domain TEXT,
            action TEXT NOT NULL,
            reason TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            dest_ip TEXT NOT NULL,
            source_port INTEGER NOT NULL,
            dest_port INTEGER NOT NULL,
            protocol TEXT NOT NULL,
            http_method TEXT,
            uri TEXT,
            http_version TEXT,
            created_at INTEGER NOT NULL,
            handled INTEGER NOT NULL DEFAULT 0,
            handled_at INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_security_events_created_at
            ON security_events(created_at);
        CREATE INDEX IF NOT EXISTS idx_security_events_source_ip
            ON security_events(source_ip);

        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT,
            provider_remote_id TEXT,
            ip TEXT NOT NULL,
            reason TEXT NOT NULL,
            blocked_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip
            ON blocked_ips(ip);
        CREATE INDEX IF NOT EXISTS idx_blocked_ips_expires_at
            ON blocked_ips(expires_at);
        CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            layer TEXT NOT NULL,
            pattern TEXT NOT NULL,
            action TEXT NOT NULL,
            severity TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_rules_updated_at
            ON rules(updated_at);

        CREATE TABLE IF NOT EXISTS app_config (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            config_json TEXT NOT NULL,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS safeline_site_mappings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            safeline_site_id TEXT NOT NULL UNIQUE,
            safeline_site_name TEXT NOT NULL,
            safeline_site_domain TEXT NOT NULL,
            local_alias TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            is_primary INTEGER NOT NULL DEFAULT 0,
            notes TEXT NOT NULL DEFAULT '',
            updated_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_safeline_site_mappings_updated_at
            ON safeline_site_mappings(updated_at);

        CREATE TABLE IF NOT EXISTS safeline_event_dedup (
            fingerprint TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL,
            imported_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_safeline_event_dedup_created_at
            ON safeline_event_dedup(created_at);

        CREATE TABLE IF NOT EXISTS safeline_sync_state (
            resource TEXT PRIMARY KEY,
            last_cursor INTEGER,
            last_success_at INTEGER,
            last_imported_count INTEGER NOT NULL DEFAULT 0,
            last_skipped_count INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS safeline_blocked_ip_sync_dedup (
            fingerprint TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            synced_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS safeline_blocked_ip_pull_dedup (
            fingerprint TEXT PRIMARY KEY,
            ip TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            synced_at INTEGER NOT NULL
        );
        "#,
    )
    .execute(pool)
    .await?;

    if let Err(err) =
        sqlx::query("ALTER TABLE security_events ADD COLUMN handled INTEGER NOT NULL DEFAULT 0")
            .execute(pool)
            .await
    {
        if !err.to_string().contains("duplicate column name") {
            return Err(err.into());
        }
    }
    if let Err(err) = sqlx::query("ALTER TABLE security_events ADD COLUMN handled_at INTEGER")
        .execute(pool)
        .await
    {
        if !err.to_string().contains("duplicate column name") {
            return Err(err.into());
        }
    }
    for statement in [
        "ALTER TABLE security_events ADD COLUMN provider TEXT",
        "ALTER TABLE security_events ADD COLUMN provider_site_id TEXT",
        "ALTER TABLE security_events ADD COLUMN provider_site_name TEXT",
        "ALTER TABLE security_events ADD COLUMN provider_site_domain TEXT",
    ] {
        if let Err(err) = sqlx::query(statement).execute(pool).await {
            if !err.to_string().contains("duplicate column name") {
                return Err(err.into());
            }
        }
    }
    for statement in [
        "ALTER TABLE blocked_ips ADD COLUMN provider TEXT",
        "ALTER TABLE blocked_ips ADD COLUMN provider_remote_id TEXT",
    ] {
        if let Err(err) = sqlx::query(statement).execute(pool).await {
            if !err.to_string().contains("duplicate column name") {
                return Err(err.into());
            }
        }
    }
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_security_events_provider_site_id ON security_events(provider_site_id)",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE INDEX IF NOT EXISTS idx_blocked_ips_provider ON blocked_ips(provider)")
        .execute(pool)
        .await?;

    Ok(())
}

#[derive(Debug, Clone)]
pub struct SafeLineSiteMappingUpsert {
    pub safeline_site_id: String,
    pub safeline_site_name: String,
    pub safeline_site_domain: String,
    pub local_alias: String,
    pub enabled: bool,
    pub is_primary: bool,
    pub notes: String,
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineImportResult {
    pub imported: usize,
    pub skipped: usize,
    pub last_cursor: Option<i64>,
}

fn fingerprint_security_event(event: &SecurityEventRecord) -> String {
    let mut hasher = Sha256::new();
    hasher.update(event.layer.as_bytes());
    hasher.update([0]);
    hasher.update(event.provider.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(event.provider_site_id.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(event.action.as_bytes());
    hasher.update([0]);
    hasher.update(event.reason.as_bytes());
    hasher.update([0]);
    hasher.update(event.source_ip.as_bytes());
    hasher.update([0]);
    hasher.update(event.dest_ip.as_bytes());
    hasher.update([0]);
    hasher.update(event.source_port.to_le_bytes());
    hasher.update(event.dest_port.to_le_bytes());
    hasher.update([0]);
    hasher.update(event.protocol.as_bytes());
    hasher.update([0]);
    hasher.update(event.http_method.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(event.uri.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(event.http_version.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(event.created_at.to_le_bytes());
    format!("{:x}", hasher.finalize())
}

fn fingerprint_blocked_ip(record: &BlockedIpEntry) -> String {
    let mut hasher = Sha256::new();
    hasher.update(record.provider.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(
        record
            .provider_remote_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(record.ip.as_bytes());
    hasher.update([0]);
    hasher.update(record.reason.as_bytes());
    hasher.update([0]);
    hasher.update(record.blocked_at.to_le_bytes());
    hasher.update(record.expires_at.to_le_bytes());
    format!("{:x}", hasher.finalize())
}

fn fingerprint_blocked_ip_record(record: &BlockedIpRecord) -> String {
    let mut hasher = Sha256::new();
    hasher.update(record.provider.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(
        record
            .provider_remote_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(record.ip.as_bytes());
    hasher.update([0]);
    hasher.update(record.reason.as_bytes());
    hasher.update([0]);
    hasher.update(record.blocked_at.to_le_bytes());
    hasher.update(record.expires_at.to_le_bytes());
    format!("{:x}", hasher.finalize())
}

async fn run_writer(pool: SqlitePool, mut receiver: mpsc::Receiver<StorageCommand>) {
    while let Some(command) = receiver.recv().await {
        let result = match command {
            StorageCommand::SecurityEvent(event) => {
                sqlx::query(
                    r#"
                    INSERT INTO security_events (
                        layer, provider, provider_site_id, provider_site_name, provider_site_domain,
                        action, reason, source_ip, dest_ip, source_port, dest_port,
                        protocol, http_method, uri, http_version, created_at, handled, handled_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(event.layer)
                .bind(event.provider)
                .bind(event.provider_site_id)
                .bind(event.provider_site_name)
                .bind(event.provider_site_domain)
                .bind(event.action)
                .bind(event.reason)
                .bind(event.source_ip)
                .bind(event.dest_ip)
                .bind(event.source_port)
                .bind(event.dest_port)
                .bind(event.protocol)
                .bind(event.http_method)
                .bind(event.uri)
                .bind(event.http_version)
                .bind(event.created_at)
                .bind(if event.handled { 1 } else { 0 })
                .bind(event.handled_at)
                .execute(&pool)
                .await
            }
            StorageCommand::BlockedIp(record) => {
                sqlx::query(
                    r#"
                    INSERT INTO blocked_ips (provider, provider_remote_id, ip, reason, blocked_at, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(record.provider)
                .bind(record.provider_remote_id)
                .bind(record.ip)
                .bind(record.reason)
                .bind(record.blocked_at)
                .bind(record.expires_at)
                .execute(&pool)
                .await
            }
        };

        if let Err(err) = result {
            warn!("SQLite writer task failed to persist record: {}", err);
        } else {
            debug!("SQLite writer task persisted a record");
        }
    }
}

async fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    Ok(())
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(any(feature = "api", test))]
fn normalized_limit(limit: u32) -> u32 {
    if limit == 0 {
        50
    } else {
        limit.min(200)
    }
}

#[cfg(any(feature = "api", test))]
fn append_security_event_filters<'a>(
    builder: &mut QueryBuilder<'a, Sqlite>,
    query: &'a SecurityEventQuery,
) {
    if let Some(layer) = query.layer.as_deref() {
        builder.push(" AND layer = ");
        builder.push_bind(layer);
    }
    if let Some(provider) = query.provider.as_deref() {
        builder.push(" AND provider = ");
        builder.push_bind(provider);
    }
    if let Some(provider_site_id) = query.provider_site_id.as_deref() {
        builder.push(" AND provider_site_id = ");
        builder.push_bind(provider_site_id);
    }
    if let Some(source_ip) = query.source_ip.as_deref() {
        builder.push(" AND source_ip = ");
        builder.push_bind(source_ip);
    }
    if query.blocked_only {
        builder.push(" AND action = ");
        builder.push_bind("block");
    } else if let Some(action) = query.action.as_deref() {
        builder.push(" AND action = ");
        builder.push_bind(action);
    }
    if let Some(handled_only) = query.handled_only {
        builder.push(" AND handled = ");
        builder.push_bind(if handled_only { 1 } else { 0 });
    }
    if let Some(created_from) = query.created_from {
        builder.push(" AND created_at >= ");
        builder.push_bind(created_from);
    }
    if let Some(created_to) = query.created_to {
        builder.push(" AND created_at <= ");
        builder.push_bind(created_to);
    }
}

#[cfg(any(feature = "api", test))]
fn append_blocked_ip_filters<'a>(
    builder: &mut QueryBuilder<'a, Sqlite>,
    query: &'a BlockedIpQuery,
) {
    if let Some(provider) = query.provider.as_deref() {
        builder.push(" AND provider = ");
        builder.push_bind(provider);
    }
    if let Some(ip) = query.ip.as_deref() {
        builder.push(" AND ip = ");
        builder.push_bind(ip);
    }
    if query.active_only {
        builder.push(" AND expires_at > ");
        builder.push_bind(unix_timestamp());
    }
    if let Some(blocked_from) = query.blocked_from {
        builder.push(" AND blocked_at >= ");
        builder.push_bind(blocked_from);
    }
    if let Some(blocked_to) = query.blocked_to {
        builder.push(" AND blocked_at <= ");
        builder.push_bind(blocked_to);
    }
}

#[cfg(any(feature = "api", test))]
fn append_event_sort<'a>(builder: &mut QueryBuilder<'a, Sqlite>, query: &SecurityEventQuery) {
    builder.push(" ORDER BY ");
    builder.push(match query.sort_by {
        EventSortField::CreatedAt => "created_at",
        EventSortField::SourceIp => "source_ip",
        EventSortField::DestPort => "dest_port",
    });
    builder.push(match query.sort_direction {
        SortDirection::Asc => " ASC",
        SortDirection::Desc => " DESC",
    });
    builder.push(", id ");
    builder.push(match query.sort_direction {
        SortDirection::Asc => "ASC",
        SortDirection::Desc => "DESC",
    });
}

#[cfg(any(feature = "api", test))]
fn append_blocked_ip_sort<'a>(builder: &mut QueryBuilder<'a, Sqlite>, query: &BlockedIpQuery) {
    builder.push(" ORDER BY ");
    builder.push(match query.sort_by {
        BlockedIpSortField::BlockedAt => "blocked_at",
        BlockedIpSortField::ExpiresAt => "expires_at",
        BlockedIpSortField::Ip => "ip",
    });
    builder.push(match query.sort_direction {
        SortDirection::Asc => " ASC",
        SortDirection::Desc => " DESC",
    });
    builder.push(", id ");
    builder.push(match query.sort_direction {
        SortDirection::Asc => "ASC",
        SortDirection::Desc => "DESC",
    });
}

#[derive(sqlx::FromRow)]
struct StoredRuleRow {
    id: String,
    name: String,
    enabled: bool,
    layer: String,
    pattern: String,
    action: String,
    severity: String,
}

#[derive(sqlx::FromRow)]
struct StoredAppConfigRow {
    config_json: String,
}

impl TryFrom<StoredRuleRow> for Rule {
    type Error = anyhow::Error;

    fn try_from(value: StoredRuleRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            name: value.name,
            enabled: value.enabled,
            layer: parse_rule_layer(&value.layer)?,
            pattern: value.pattern,
            action: parse_rule_action(&value.action)?,
            severity: parse_severity(&value.severity)?,
        })
    }
}

impl TryFrom<StoredAppConfigRow> for Config {
    type Error = anyhow::Error;

    fn try_from(value: StoredAppConfigRow) -> Result<Self, Self::Error> {
        Ok(serde_json::from_str(&value.config_json)?)
    }
}

fn parse_rule_layer(value: &str) -> Result<RuleLayer> {
    RuleLayer::parse(value).map_err(anyhow::Error::msg)
}

fn parse_rule_action(value: &str) -> Result<RuleAction> {
    RuleAction::parse(value).map_err(anyhow::Error::msg)
}

fn parse_severity(value: &str) -> Result<Severity> {
    Severity::parse(value).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RuleAction, RuleLayer, Severity};

    fn unique_test_db_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("{}_{}_{}.db", env!("CARGO_PKG_NAME"), name, nanos))
            .display()
            .to_string()
    }

    #[tokio::test]
    async fn test_sqlite_store_initializes_schema() {
        let path = unique_test_db_path("schema");
        let _store = SqliteStore::new(path.clone(), true).await.unwrap();

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&format!("sqlite://{}", path))
            .await
            .unwrap();

        let security_events_exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'security_events'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let blocked_ips_exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'blocked_ips'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let rules_exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'rules'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let app_config_exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'app_config'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        let safeline_site_mappings_exists: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'safeline_site_mappings'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        assert_eq!(security_events_exists, 1);
        assert_eq!(blocked_ips_exists, 1);
        assert_eq!(rules_exists, 1);
        assert_eq!(app_config_exists, 1);
        assert_eq!(safeline_site_mappings_exists, 1);
    }

    #[tokio::test]
    async fn test_sqlite_store_persists_records() {
        let path = unique_test_db_path("records");
        let store = SqliteStore::new(path.clone(), true).await.unwrap();

        store.enqueue_security_event(SecurityEventRecord {
            layer: "L7".to_string(),
            provider: None,
            provider_site_id: None,
            provider_site_name: None,
            provider_site_domain: None,
            action: "block".to_string(),
            reason: "test event".to_string(),
            source_ip: "127.0.0.1".to_string(),
            dest_ip: "127.0.0.1".to_string(),
            source_port: 12345,
            dest_port: 8080,
            protocol: "TCP".to_string(),
            http_method: Some("GET".to_string()),
            uri: Some("/".to_string()),
            http_version: Some("HTTP/1.1".to_string()),
            created_at: unix_timestamp(),
            handled: false,
            handled_at: None,
        });
        store.enqueue_blocked_ip(BlockedIpRecord::new(
            "127.0.0.1",
            "rate limit exceeded",
            unix_timestamp(),
            unix_timestamp() + 30,
        ));

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(&format!("sqlite://{}", path))
            .await
            .unwrap();

        let security_events_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_events")
            .fetch_one(&pool)
            .await
            .unwrap();
        let blocked_ips_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocked_ips")
            .fetch_one(&pool)
            .await
            .unwrap();

        assert_eq!(security_events_count, 1);
        assert_eq!(blocked_ips_count, 1);

        let summary = store.metrics_summary().await.unwrap();
        assert_eq!(summary.security_events, 1);
        assert_eq!(summary.blocked_ips, 1);
        assert!(summary.latest_event_at.is_some());
        assert_eq!(summary.rules, 0);
        assert!(summary.latest_rule_update_at.is_none());
    }

    #[tokio::test]
    async fn test_sqlite_store_seeds_and_loads_rules() {
        let path = unique_test_db_path("rules");
        let store = SqliteStore::new(path, true).await.unwrap();
        let rules = vec![
            Rule {
                id: "rule-1".to_string(),
                name: "Block SQLi".to_string(),
                enabled: true,
                layer: RuleLayer::L7,
                pattern: "(?i)union\\s+select".to_string(),
                action: RuleAction::Block,
                severity: Severity::High,
            },
            Rule {
                id: "rule-2".to_string(),
                name: "Alert Port Scan".to_string(),
                enabled: true,
                layer: RuleLayer::L4,
                pattern: "scan".to_string(),
                action: RuleAction::Alert,
                severity: Severity::Medium,
            },
        ];

        let inserted = store.seed_rules(&rules).await.unwrap();
        assert_eq!(inserted, 2);

        let inserted_again = store.seed_rules(&rules).await.unwrap();
        assert_eq!(inserted_again, 0);

        let loaded_rules = store.load_rules().await.unwrap();
        assert_eq!(loaded_rules.len(), 2);
        assert_eq!(loaded_rules[0].id, "rule-1");
        assert_eq!(loaded_rules[1].id, "rule-2");
        assert_eq!(
            store.load_rule("rule-1").await.unwrap().unwrap().name,
            "Block SQLi"
        );

        let updated_rule = Rule {
            id: "rule-1".to_string(),
            name: "Block Updated SQLi".to_string(),
            enabled: false,
            layer: RuleLayer::L7,
            pattern: "(?i)select".to_string(),
            action: RuleAction::Alert,
            severity: Severity::Critical,
        };
        store.upsert_rule(&updated_rule).await.unwrap();
        let fetched_updated = store.load_rule("rule-1").await.unwrap().unwrap();
        assert_eq!(fetched_updated.name, "Block Updated SQLi");
        assert!(!fetched_updated.enabled);
        assert_eq!(fetched_updated.action, RuleAction::Alert);
        assert_eq!(fetched_updated.severity, Severity::Critical);

        let inserted_new = store
            .insert_rule(&Rule {
                id: "rule-3".to_string(),
                name: "New Rule".to_string(),
                enabled: true,
                layer: RuleLayer::L4,
                pattern: "syn".to_string(),
                action: RuleAction::Block,
                severity: Severity::Low,
            })
            .await
            .unwrap();
        assert!(inserted_new);
        let inserted_duplicate = store.insert_rule(&updated_rule).await.unwrap();
        assert!(!inserted_duplicate);

        let deleted = store.delete_rule("rule-2").await.unwrap();
        assert!(deleted);
        let deleted_missing = store.delete_rule("missing").await.unwrap();
        assert!(!deleted_missing);

        let latest_version = store.latest_rules_version().await.unwrap();
        assert!(latest_version > 0);

        let summary = store.metrics_summary().await.unwrap();
        assert_eq!(summary.rules, 2);
        assert!(summary.latest_rule_update_at.is_some());
    }

    #[tokio::test]
    async fn test_sqlite_store_seeds_and_updates_app_config() {
        let path = unique_test_db_path("app_config");
        let store = SqliteStore::new(path, true).await.unwrap();
        let initial = Config {
            api_enabled: true,
            sqlite_enabled: true,
            sqlite_path: "data/custom.db".to_string(),
            max_concurrent_tasks: 321,
            ..Config::default()
        };

        let inserted = store.seed_app_config(&initial).await.unwrap();
        assert!(inserted);

        let loaded = store.load_app_config().await.unwrap().unwrap();
        assert!(loaded.api_enabled);
        assert_eq!(loaded.sqlite_path, "data/custom.db");

        let inserted_again = store.seed_app_config(&Config::default()).await.unwrap();
        assert!(!inserted_again);

        let updated = Config {
            api_enabled: false,
            max_concurrent_tasks: 654,
            ..initial.clone()
        };
        store.upsert_app_config(&updated).await.unwrap();

        let loaded_updated = store.load_app_config().await.unwrap().unwrap();
        assert!(!loaded_updated.api_enabled);
        assert_eq!(loaded_updated.max_concurrent_tasks, 654);
    }

    #[tokio::test]
    async fn test_sqlite_store_queries_events_and_blocked_ips() {
        let path = unique_test_db_path("queries");
        let store = SqliteStore::new(path, true).await.unwrap();
        let now = unix_timestamp();

        store.enqueue_security_event(SecurityEventRecord {
            layer: "L7".to_string(),
            provider: None,
            provider_site_id: None,
            provider_site_name: None,
            provider_site_domain: None,
            action: "block".to_string(),
            reason: "sql injection".to_string(),
            source_ip: "10.0.0.1".to_string(),
            dest_ip: "10.0.0.2".to_string(),
            source_port: 50000,
            dest_port: 8080,
            protocol: "TCP".to_string(),
            http_method: Some("GET".to_string()),
            uri: Some("/login".to_string()),
            http_version: Some("HTTP/1.1".to_string()),
            created_at: now - 10,
            handled: false,
            handled_at: None,
        });
        store.enqueue_security_event(SecurityEventRecord {
            layer: "L4".to_string(),
            provider: None,
            provider_site_id: None,
            provider_site_name: None,
            provider_site_domain: None,
            action: "alert".to_string(),
            reason: "port scan".to_string(),
            source_ip: "10.0.0.3".to_string(),
            dest_ip: "10.0.0.2".to_string(),
            source_port: 40000,
            dest_port: 22,
            protocol: "TCP".to_string(),
            http_method: None,
            uri: None,
            http_version: None,
            created_at: now - 5,
            handled: false,
            handled_at: None,
        });
        store.enqueue_blocked_ip(BlockedIpRecord::new(
            "10.0.0.1",
            "rate limit exceeded",
            now - 15,
            now + 60,
        ));
        store.enqueue_blocked_ip(BlockedIpRecord::new(
            "10.0.0.4",
            "expired block",
            now - 120,
            now - 60,
        ));

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let l7_events = store
            .list_security_events(&SecurityEventQuery {
                layer: Some("L7".to_string()),
                ..SecurityEventQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(l7_events.total, 1);
        assert_eq!(l7_events.items[0].reason, "sql injection");

        let blocked_only_events = store
            .list_security_events(&SecurityEventQuery {
                blocked_only: true,
                ..SecurityEventQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(blocked_only_events.total, 1);
        assert_eq!(blocked_only_events.items[0].action, "block");

        let recent_events = store
            .list_security_events(&SecurityEventQuery {
                created_from: Some(now - 7),
                sort_by: EventSortField::CreatedAt,
                sort_direction: SortDirection::Asc,
                ..SecurityEventQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(recent_events.total, 1);
        assert_eq!(recent_events.items[0].reason, "port scan");

        let source_sorted_events = store
            .list_security_events(&SecurityEventQuery {
                sort_by: EventSortField::SourceIp,
                sort_direction: SortDirection::Asc,
                ..SecurityEventQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(source_sorted_events.total, 2);
        assert_eq!(source_sorted_events.items[0].source_ip, "10.0.0.1");

        let port_sorted_events = store
            .list_security_events(&SecurityEventQuery {
                sort_by: EventSortField::DestPort,
                sort_direction: SortDirection::Asc,
                ..SecurityEventQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(port_sorted_events.total, 2);
        assert_eq!(port_sorted_events.items[0].dest_port, 22);

        let active_blocks = store
            .list_blocked_ips(&BlockedIpQuery {
                active_only: true,
                ..BlockedIpQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(active_blocks.total, 1);
        assert_eq!(active_blocks.items[0].ip, "10.0.0.1");

        let sorted_blocks = store
            .list_blocked_ips(&BlockedIpQuery {
                sort_by: BlockedIpSortField::Ip,
                sort_direction: SortDirection::Asc,
                ..BlockedIpQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(sorted_blocks.total, 2);
        assert_eq!(sorted_blocks.items[0].ip, "10.0.0.1");

        let expires_sorted_blocks = store
            .list_blocked_ips(&BlockedIpQuery {
                sort_by: BlockedIpSortField::ExpiresAt,
                sort_direction: SortDirection::Asc,
                ..BlockedIpQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(expires_sorted_blocks.total, 2);
        assert_eq!(expires_sorted_blocks.items[0].ip, "10.0.0.4");

        let paged_blocks = store
            .list_blocked_ips(&BlockedIpQuery {
                limit: 1,
                offset: 1,
                ..BlockedIpQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(paged_blocks.limit, 1);
        assert_eq!(paged_blocks.offset, 1);
        assert_eq!(paged_blocks.items.len(), 1);
    }

    #[tokio::test]
    async fn test_sqlite_store_replaces_safeline_site_mappings() {
        let path = unique_test_db_path("safeline_site_mappings");
        let store = SqliteStore::new(path, true).await.unwrap();

        store
            .replace_safeline_site_mappings(&[
                SafeLineSiteMappingUpsert {
                    safeline_site_id: "site-1".to_string(),
                    safeline_site_name: "portal".to_string(),
                    safeline_site_domain: "portal.example.com".to_string(),
                    local_alias: "主站".to_string(),
                    enabled: true,
                    is_primary: true,
                    notes: "prod".to_string(),
                },
                SafeLineSiteMappingUpsert {
                    safeline_site_id: "site-2".to_string(),
                    safeline_site_name: "admin".to_string(),
                    safeline_site_domain: "admin.example.com".to_string(),
                    local_alias: "后台".to_string(),
                    enabled: false,
                    is_primary: false,
                    notes: String::new(),
                },
            ])
            .await
            .unwrap();

        let mappings = store.list_safeline_site_mappings().await.unwrap();
        assert_eq!(mappings.len(), 2);
        assert_eq!(mappings[0].safeline_site_id, "site-1");
        assert!(mappings[0].is_primary);

        store
            .replace_safeline_site_mappings(&[SafeLineSiteMappingUpsert {
                safeline_site_id: "site-3".to_string(),
                safeline_site_name: "api".to_string(),
                safeline_site_domain: "api.example.com".to_string(),
                local_alias: "接口".to_string(),
                enabled: true,
                is_primary: false,
                notes: "new".to_string(),
            }])
            .await
            .unwrap();

        let replaced = store.list_safeline_site_mappings().await.unwrap();
        assert_eq!(replaced.len(), 1);
        assert_eq!(replaced[0].safeline_site_id, "site-3");
    }

    #[tokio::test]
    async fn test_sqlite_store_deduplicates_safeline_events() {
        let path = unique_test_db_path("safeline_event_dedup");
        let store = SqliteStore::new(path, true).await.unwrap();
        let event = SecurityEventRecord {
            layer: "safeline".to_string(),
            provider: Some("safeline".to_string()),
            provider_site_id: Some("site-1".to_string()),
            provider_site_name: Some("主站".to_string()),
            provider_site_domain: Some("portal.example.com".to_string()),
            action: "block".to_string(),
            reason: "safeline:sqli".to_string(),
            source_ip: "203.0.113.10".to_string(),
            dest_ip: "10.0.0.10".to_string(),
            source_port: 44321,
            dest_port: 443,
            protocol: "HTTP".to_string(),
            http_method: Some("POST".to_string()),
            uri: Some("/login".to_string()),
            http_version: Some("HTTP/1.1".to_string()),
            created_at: unix_timestamp(),
            handled: false,
            handled_at: None,
        };

        let first = store
            .import_safeline_security_events(std::slice::from_ref(&event))
            .await
            .unwrap();
        assert_eq!(first.imported, 1);
        assert_eq!(first.skipped, 0);

        let second = store
            .import_safeline_security_events(std::slice::from_ref(&event))
            .await
            .unwrap();
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped, 1);

        let events = store
            .list_security_events(&SecurityEventQuery::default())
            .await
            .unwrap();
        assert_eq!(events.total, 1);

        let state = store.load_safeline_sync_state("events").await.unwrap().unwrap();
        assert_eq!(state.last_imported_count, 0);
        assert_eq!(state.last_skipped_count, 1);
    }

    #[tokio::test]
    async fn test_sqlite_store_deduplicates_safeline_blocked_ip_pull() {
        let path = unique_test_db_path("safeline_blocked_ip_pull_dedup");
        let store = SqliteStore::new(path, true).await.unwrap();
        let record = BlockedIpRecord {
            provider: Some("safeline".to_string()),
            provider_remote_id: Some("remote-1".to_string()),
            ip: "203.0.113.10".to_string(),
            reason: "safeline:test".to_string(),
            blocked_at: unix_timestamp(),
            expires_at: unix_timestamp() + 600,
        };

        let first = store
            .import_safeline_blocked_ips_pull(std::slice::from_ref(&record))
            .await
            .unwrap();
        assert_eq!(first.imported, 1);
        assert_eq!(first.skipped, 0);

        let second = store
            .import_safeline_blocked_ips_pull(std::slice::from_ref(&record))
            .await
            .unwrap();
        assert_eq!(second.imported, 0);
        assert_eq!(second.skipped, 1);

        let blocked = store
            .list_blocked_ips(&BlockedIpQuery {
                provider: Some("safeline".to_string()),
                ..BlockedIpQuery::default()
            })
            .await
            .unwrap();
        assert_eq!(blocked.total, 1);

        let state = store
            .load_safeline_sync_state("blocked_ips_pull")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.last_imported_count, 0);
        assert_eq!(state.last_skipped_count, 1);
    }

    #[tokio::test]
    async fn test_sqlite_store_blocked_ip_pull_dedup_is_isolated_from_push_dedup() {
        let path = unique_test_db_path("safeline_blocked_ip_pull_isolated");
        let store = SqliteStore::new(path, true).await.unwrap();
        let now = unix_timestamp();
        let pushed = BlockedIpEntry {
            id: 1,
            provider: Some("safeline".to_string()),
            provider_remote_id: Some("remote-1".to_string()),
            ip: "203.0.113.20".to_string(),
            reason: "safeline:test".to_string(),
            blocked_at: now,
            expires_at: now + 1200,
        };
        let pulled = BlockedIpRecord {
            provider: pushed.provider.clone(),
            provider_remote_id: pushed.provider_remote_id.clone(),
            ip: pushed.ip.clone(),
            reason: pushed.reason.clone(),
            blocked_at: pushed.blocked_at,
            expires_at: pushed.expires_at,
        };

        let push_result = store
            .import_safeline_blocked_ips_sync_result(&[pushed], 0)
            .await
            .unwrap();
        assert_eq!(push_result.synced, 1);

        let pull_result = store
            .import_safeline_blocked_ips_pull(&[pulled])
            .await
            .unwrap();
        assert_eq!(pull_result.imported, 1);
        assert_eq!(pull_result.skipped, 0);
    }
}
