use super::{
    schema::initialize_schema, BlockedIpEntry, BlockedIpRecord, SecurityEventRecord, StorageCommand,
};
use anyhow::{Context, Result};
use log::{debug, warn};
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Notify};

use super::{
    SqliteOpenErrorKind, SQLITE_CORRUPT_BACKUP_RETENTION, SQLITE_STARTUP_BACKUP_RETENTION,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BackupKind {
    Startup,
    Manual,
    Corrupt,
}

pub(super) async fn open_pool(db_path: &Path, auto_migrate: bool) -> Result<SqlitePool> {
    let connect_options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            // FULL reduces the risk of losing committed records when the process or host crashes.
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(connect_options)
        .await?;
    validate_database(&pool).await?;
    if auto_migrate {
        initialize_schema(&pool).await?;
    }
    Ok(pool)
}

pub(super) fn classify_sqlite_error(error: &anyhow::Error) -> SqliteOpenErrorKind {
    if is_sqlite_corruption_error(error) {
        return SqliteOpenErrorKind::Corruption;
    }
    let message = error.to_string().to_ascii_lowercase();
    if let Some(io_error) = error.downcast_ref::<std::io::Error>() {
        return match io_error.kind() {
            std::io::ErrorKind::PermissionDenied => SqliteOpenErrorKind::PermissionDenied,
            std::io::ErrorKind::NotFound => SqliteOpenErrorKind::PathUnavailable,
            _ => SqliteOpenErrorKind::Other,
        };
    }
    if message.contains("permission denied") || message.contains("readonly") {
        return SqliteOpenErrorKind::PermissionDenied;
    }
    if message.contains("no such file")
        || message.contains("unable to open database file")
        || message.contains("cannot open")
    {
        return SqliteOpenErrorKind::PathUnavailable;
    }
    if message.contains("disk is full") || message.contains("database or disk is full") {
        return SqliteOpenErrorKind::DiskFull;
    }
    SqliteOpenErrorKind::Other
}

async fn validate_database(pool: &SqlitePool) -> Result<()> {
    let integrity_check: String = sqlx::query_scalar("PRAGMA integrity_check(1)")
        .fetch_one(pool)
        .await?;
    if integrity_check.eq_ignore_ascii_case("ok") {
        Ok(())
    } else {
        anyhow::bail!("sqlite integrity check failed: {integrity_check}");
    }
}

pub(super) fn is_sqlite_corruption_error(error: &anyhow::Error) -> bool {
    let Some(sqlx_error) = error.downcast_ref::<sqlx::Error>() else {
        return error
            .to_string()
            .to_ascii_lowercase()
            .contains("integrity check failed");
    };
    if let Some(database_error) = sqlx_error.as_database_error() {
        let message = database_error.message().to_ascii_lowercase();
        if message.contains("database disk image is malformed")
            || message.contains("malformed")
            || message.contains("file is not a database")
        {
            return true;
        }
        if database_error
            .code()
            .is_some_and(|code| code == "11" || code == "26")
        {
            return true;
        }
    }
    let message = sqlx_error.to_string().to_ascii_lowercase();
    message.contains("database disk image is malformed")
        || message.contains("database corrupt")
        || message.contains("file is not a database")
        || message.contains("malformed")
        || message.contains("integrity check failed")
}

pub(super) fn log_sqlite_open_error(path: &Path, error: &anyhow::Error) {
    let kind = classify_sqlite_error(error);
    warn!(
        "Failed to open SQLite database: path={}, kind={:?}, error={}",
        path.display(),
        kind,
        error
    );
}

pub(super) async fn backup_corrupted_db(path: &Path) -> Result<PathBuf> {
    if !tokio::fs::try_exists(path).await? {
        return Ok(corrupted_backup_path(path, &timestamp_suffix()));
    }
    ensure_backup_dir(path).await?;
    let backup_path = backup_file_path(path, BackupKind::Corrupt, &timestamp_suffix());
    tokio::fs::rename(path, &backup_path)
        .await
        .with_context(|| {
            format!(
                "failed to move corrupted SQLite database {} to {}",
                path.display(),
                backup_path.display()
            )
        })?;
    for suffix in ["-wal", "-shm"] {
        let sidecar = PathBuf::from(format!("{}{}", path.display(), suffix));
        if tokio::fs::try_exists(&sidecar).await? {
            let backup_sidecar = PathBuf::from(format!("{}{}", backup_path.display(), suffix));
            tokio::fs::rename(&sidecar, &backup_sidecar)
                .await
                .with_context(|| {
                    format!(
                        "failed to move corrupted SQLite sidecar {} to {}",
                        sidecar.display(),
                        backup_sidecar.display()
                    )
                })?;
        }
    }
    prune_backups(path, BackupKind::Corrupt, SQLITE_CORRUPT_BACKUP_RETENTION).await?;
    Ok(backup_path)
}

pub(super) async fn create_backup_snapshot(
    pool: &SqlitePool,
    db_path: &Path,
    kind: BackupKind,
) -> Result<PathBuf> {
    ensure_backup_dir(db_path).await?;
    let backup_path = backup_file_path(db_path, kind, &timestamp_suffix());
    checkpoint_wal(pool).await?;
    let escaped_backup_path = backup_path.to_string_lossy().replace('\'', "''");
    sqlx::query(&format!("VACUUM INTO '{}'", escaped_backup_path))
        .execute(pool)
        .await
        .with_context(|| {
            format!(
                "failed to create SQLite backup snapshot from {} to {}",
                db_path.display(),
                backup_path.display()
            )
        })?;
    if kind == BackupKind::Startup {
        prune_backups(
            db_path,
            BackupKind::Startup,
            SQLITE_STARTUP_BACKUP_RETENTION,
        )
        .await?;
    }
    Ok(backup_path)
}

async fn checkpoint_wal(pool: &SqlitePool) -> Result<()> {
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(pool)
        .await?;
    Ok(())
}

async fn ensure_backup_dir(path: &Path) -> Result<()> {
    tokio::fs::create_dir_all(backup_dir(path)).await?;
    Ok(())
}

pub(super) fn backup_dir(path: &Path) -> PathBuf {
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join("backups")
}

fn backup_file_path(path: &Path, kind: BackupKind, timestamp: &str) -> PathBuf {
    let stem = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("sqlite");
    let ext = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| format!(".{ext}"))
        .unwrap_or_default();
    backup_dir(path).join(format!(
        "{stem}.{}.{}{ext}",
        backup_kind_label(kind),
        timestamp
    ))
}

fn backup_kind_label(kind: BackupKind) -> &'static str {
    match kind {
        BackupKind::Startup => "startup.",
        BackupKind::Manual => "manual.",
        BackupKind::Corrupt => "corrupt.",
    }
}

async fn prune_backups(path: &Path, kind: BackupKind, retain: usize) -> Result<()> {
    let dir = backup_dir(path);
    if !tokio::fs::try_exists(&dir).await? {
        return Ok(());
    }
    let stem = path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("sqlite");
    let ext = path
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| format!(".{value}"))
        .unwrap_or_default();
    let prefix = format!("{stem}.{}", backup_kind_label(kind));
    let mut entries = tokio::fs::read_dir(&dir).await?;
    let mut backup_files = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        if file_name.starts_with(&prefix) && file_name.ends_with(&ext) {
            backup_files.push(entry.path());
        }
    }
    backup_files.sort();
    let remove_count = backup_files.len().saturating_sub(retain);
    for backup_path in backup_files.into_iter().take(remove_count) {
        tokio::fs::remove_file(&backup_path)
            .await
            .with_context(|| {
                format!(
                    "failed to remove old SQLite backup {}",
                    backup_path.display()
                )
            })?;
    }
    Ok(())
}

fn corrupted_backup_path(path: &Path, timestamp: &str) -> PathBuf {
    backup_file_path(path, BackupKind::Corrupt, timestamp)
}

fn timestamp_suffix() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .to_string()
}

pub(super) fn fingerprint_security_event(event: &SecurityEventRecord) -> String {
    let mut hasher = Sha256::new();
    hasher.update(event.layer.as_bytes());
    hasher.update([0]);
    hasher.update(event.provider.as_deref().unwrap_or_default().as_bytes());
    hasher.update([0]);
    hasher.update(
        event
            .provider_event_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(
        event
            .provider_site_id
            .as_deref()
            .unwrap_or_default()
            .as_bytes(),
    );
    hasher.update([0]);
    hasher.update(event.action.as_bytes());
    hasher.update([0]);
    hasher.update(event.reason.as_bytes());
    hasher.update([0]);
    hasher.update(event.details_json.as_deref().unwrap_or_default().as_bytes());
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

pub(super) fn serialize_string_vec(values: &[String]) -> Result<String> {
    Ok(serde_json::to_string(values)?)
}

pub(super) fn fingerprint_blocked_ip(record: &BlockedIpEntry) -> String {
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

pub(super) fn fingerprint_blocked_ip_record(record: &BlockedIpRecord) -> String {
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

pub(super) async fn run_writer(
    pool: SqlitePool,
    mut receiver: mpsc::Receiver<StorageCommand>,
    realtime_tx: tokio::sync::broadcast::Sender<crate::storage::StorageRealtimeEvent>,
    pending_writes: Arc<AtomicU64>,
    pending_write_notify: Arc<Notify>,
) {
    while let Some(command) = receiver.recv().await {
        let result = match command {
            StorageCommand::SecurityEvent(event) => persist_security_event(&pool, event)
                .await
                .map(crate::storage::StorageRealtimeEvent::SecurityEvent),
            StorageCommand::BlockedIp(record) => persist_blocked_ip(&pool, record)
                .await
                .map(crate::storage::StorageRealtimeEvent::BlockedIpUpsert),
            StorageCommand::Flush { ack } => {
                if let Err(err) = checkpoint_wal(&pool).await {
                    warn!("SQLite writer flush checkpoint failed: {}", err);
                }
                let _ = ack.send(());
                continue;
            }
            StorageCommand::Shutdown { ack } => {
                if let Err(err) = checkpoint_wal(&pool).await {
                    warn!("SQLite writer shutdown checkpoint failed: {}", err);
                }
                let _ = ack.send(());
                break;
            }
        };
        match result {
            Ok(event) => {
                let _ = realtime_tx.send(event);
                debug!("SQLite writer task persisted a record");
            }
            Err(err) => {
                warn!("SQLite writer task failed to persist record: {}", err);
            }
        }
        finish_pending_write(&pending_writes, &pending_write_notify);
    }
}

pub(super) async fn persist_security_event(
    pool: &SqlitePool,
    event: SecurityEventRecord,
) -> Result<crate::storage::SecurityEventEntry> {
    let result = sqlx::query(
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
    .execute(pool)
    .await?;
    Ok(crate::storage::SecurityEventEntry {
        id: result.last_insert_rowid(),
        layer: event.layer,
        provider: event.provider,
        provider_event_id: event.provider_event_id,
        provider_site_id: event.provider_site_id,
        provider_site_name: event.provider_site_name,
        provider_site_domain: event.provider_site_domain,
        action: event.action,
        reason: event.reason,
        details_json: event.details_json,
        source_ip: event.source_ip,
        dest_ip: event.dest_ip,
        source_port: event.source_port,
        dest_port: event.dest_port,
        protocol: event.protocol,
        http_method: event.http_method,
        uri: event.uri,
        http_version: event.http_version,
        created_at: event.created_at,
        handled: event.handled,
        handled_at: event.handled_at,
    })
}

pub(super) async fn persist_blocked_ip(
    pool: &SqlitePool,
    record: BlockedIpRecord,
) -> Result<crate::storage::BlockedIpEntry> {
    let result = sqlx::query(
        r#"
        INSERT INTO blocked_ips (provider, provider_remote_id, ip, reason, blocked_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(&record.provider)
    .bind(&record.provider_remote_id)
    .bind(&record.ip)
    .bind(&record.reason)
    .bind(record.blocked_at)
    .bind(record.expires_at)
    .execute(pool)
    .await?;
    Ok(crate::storage::BlockedIpEntry {
        id: result.last_insert_rowid(),
        provider: record.provider,
        provider_remote_id: record.provider_remote_id,
        ip: record.ip,
        reason: record.reason,
        blocked_at: record.blocked_at,
        expires_at: record.expires_at,
    })
}

pub(super) fn finish_pending_write(pending_writes: &AtomicU64, pending_write_notify: &Notify) {
    let previous = pending_writes.fetch_sub(1, Ordering::Relaxed);
    if previous <= 1 {
        pending_write_notify.notify_waiters();
    }
}

pub(super) async fn wait_for_pending_writes(
    pending_writes: &AtomicU64,
    pending_write_notify: &Notify,
) {
    loop {
        let notified = pending_write_notify.notified();
        if pending_writes.load(Ordering::Relaxed) == 0 {
            break;
        }
        notified.await;
    }
}

pub(super) async fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    Ok(())
}

pub(super) fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
