use crate::config::{Rule, RuleAction, RuleLayer, Severity};
use anyhow::Result;
use log::{debug, warn};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
#[cfg(any(feature = "api", test))]
use sqlx::{QueryBuilder, Sqlite};
use sqlx::SqlitePool;
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
    pub source_ip: Option<String>,
    pub action: Option<String>,
    pub blocked_only: bool,
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
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BlockedIpEntry {
    pub id: i64,
    pub ip: String,
    pub reason: String,
    pub blocked_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct SecurityEventRecord {
    pub layer: String,
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
}

#[derive(Debug, Clone)]
pub struct BlockedIpRecord {
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
            SELECT id, layer, action, reason, source_ip, dest_ip, source_port, dest_port,
                   protocol, http_method, uri, http_version, created_at
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
            "SELECT id, ip, reason, blocked_at, expires_at FROM blocked_ips WHERE 1=1",
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
            created_at INTEGER NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_security_events_created_at
            ON security_events(created_at);
        CREATE INDEX IF NOT EXISTS idx_security_events_source_ip
            ON security_events(source_ip);

        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

async fn run_writer(pool: SqlitePool, mut receiver: mpsc::Receiver<StorageCommand>) {
    while let Some(command) = receiver.recv().await {
        let result = match command {
            StorageCommand::SecurityEvent(event) => {
                sqlx::query(
                    r#"
                    INSERT INTO security_events (
                        layer, action, reason, source_ip, dest_ip, source_port, dest_port,
                        protocol, http_method, uri, http_version, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    "#,
                )
                .bind(event.layer)
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
                .execute(&pool)
                .await
            }
            StorageCommand::BlockedIp(record) => {
                sqlx::query(
                    r#"
                    INSERT INTO blocked_ips (ip, reason, blocked_at, expires_at)
                    VALUES (?, ?, ?, ?)
                    "#,
                )
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

        assert_eq!(security_events_exists, 1);
        assert_eq!(blocked_ips_exists, 1);
        assert_eq!(rules_exists, 1);
    }

    #[tokio::test]
    async fn test_sqlite_store_persists_records() {
        let path = unique_test_db_path("records");
        let store = SqliteStore::new(path.clone(), true).await.unwrap();

        store.enqueue_security_event(SecurityEventRecord {
            layer: "L7".to_string(),
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
    async fn test_sqlite_store_queries_events_and_blocked_ips() {
        let path = unique_test_db_path("queries");
        let store = SqliteStore::new(path, true).await.unwrap();
        let now = unix_timestamp();

        store.enqueue_security_event(SecurityEventRecord {
            layer: "L7".to_string(),
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
        });
        store.enqueue_security_event(SecurityEventRecord {
            layer: "L4".to_string(),
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
}
