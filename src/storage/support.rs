use super::{
    schema::initialize_schema, BlockedIpEntry, BlockedIpRecord, SecurityEventRecord, StorageCommand,
};
use anyhow::{Context, Result};
use log::{debug, warn};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Notify};

const MAX_EVENT_DETAILS_BYTES: usize = 4 * 1024;

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
    mut event: SecurityEventRecord,
) -> Result<crate::storage::SecurityEventEntry> {
    sanitize_security_event_record(&mut event);
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
    let persisted = crate::storage::SecurityEventEntry {
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
    };
    persist_behavior_intelligence(pool, &persisted).await?;
    Ok(persisted)
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

pub(crate) fn apply_write_pressure_detail_slimming(event: &mut SecurityEventRecord) {
    if let Some(details_json) = event.details_json.as_mut() {
        if let Ok(mut value) = serde_json::from_str::<Value>(details_json) {
            if let Some(object) = value.as_object_mut() {
                object.insert(
                    "storage_pressure".to_string(),
                    serde_json::json!({
                        "mode": "slimmed",
                        "reason": "sqlite_queue_pressure",
                    }),
                );
            }
            *details_json = truncate_json_value(&value, MAX_EVENT_DETAILS_BYTES / 2);
        } else if details_json.len() > MAX_EVENT_DETAILS_BYTES / 2 {
            details_json.truncate(MAX_EVENT_DETAILS_BYTES / 2);
            details_json.push_str("...");
        }
    }
}

fn sanitize_security_event_record(event: &mut SecurityEventRecord) {
    let Some(details_json) = event.details_json.as_ref() else {
        return;
    };
    let Ok(mut value) = serde_json::from_str::<Value>(details_json) else {
        if details_json.len() > MAX_EVENT_DETAILS_BYTES {
            event.details_json = Some(format!("{{\"truncated\":true,\"raw\":\"{}...\"}}", &details_json[..MAX_EVENT_DETAILS_BYTES.min(details_json.len())]));
        }
        return;
    };
    sanitize_json_value(&mut value);
    event.details_json = Some(truncate_json_value(&value, MAX_EVENT_DETAILS_BYTES));
}

fn sanitize_json_value(value: &mut Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };

    if let Some(client_identity) = object.get_mut("client_identity").and_then(Value::as_object_mut)
    {
        client_identity.remove("configured_real_ip_header_value");
        if let Some(headers) = client_identity.get_mut("headers").and_then(Value::as_array_mut) {
            headers.retain(|entry| {
                entry
                    .as_array()
                    .and_then(|pair| pair.first())
                    .and_then(Value::as_str)
                    .is_some()
            });
        }
    }

    if let Some(server) = object.get_mut("server").and_then(Value::as_object_mut) {
        server.remove("request_id");
    }
}

fn truncate_json_value(value: &Value, max_bytes: usize) -> String {
    let serialized = serde_json::to_string(value).unwrap_or_else(|_| "{}".to_string());
    if serialized.len() <= max_bytes {
        return serialized;
    }

    let mut object = match value {
        Value::Object(map) => map.clone(),
        _ => {
            return serde_json::json!({
                "truncated": true,
                "summary": serialized.chars().take(max_bytes).collect::<String>(),
            })
            .to_string()
        }
    };
    object.insert("truncated".to_string(), Value::Bool(true));
    object.insert(
        "summary".to_string(),
        Value::String(serialized.chars().take(max_bytes.min(512)).collect()),
    );
    serde_json::to_string(&Value::Object(object)).unwrap_or_else(|_| "{\"truncated\":true}".to_string())
}

#[derive(Debug)]
struct ParsedSecurityContext {
    identity: String,
    identity_kind: String,
    source_ip: String,
    site_domain: Option<String>,
    user_agent: Option<String>,
    behavior: Option<ParsedBehaviorPayload>,
}

#[derive(Debug)]
struct ParsedBehaviorPayload {
    action: Option<String>,
    score: i64,
    dominant_route: Option<String>,
    focused_document_route: Option<String>,
    focused_api_route: Option<String>,
    distinct_routes: i64,
    repeated_ratio: i64,
    document_repeated_ratio: i64,
    api_repeated_ratio: i64,
    document_requests: i64,
    api_requests: i64,
    non_document_requests: i64,
    interval_jitter_ms: Option<i64>,
    challenge_count_window: i64,
    session_span_secs: i64,
    flags_json: String,
}

async fn persist_behavior_intelligence(
    pool: &SqlitePool,
    event: &crate::storage::SecurityEventEntry,
) -> Result<()> {
    let Some(context) = parse_security_context(event) else {
        return Ok(());
    };

    upsert_fingerprint_profile(pool, event, &context).await?;
    if let Some(behavior) = context.behavior.as_ref() {
        upsert_behavior_session(pool, event, &context, behavior).await?;
        insert_behavior_event(pool, event, &context, behavior).await?;
    }
    Ok(())
}

fn parse_security_context(
    event: &crate::storage::SecurityEventEntry,
) -> Option<ParsedSecurityContext> {
    let details = event
        .details_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<Value>(raw).ok());
    let identity = details
        .as_ref()
        .and_then(parse_behavior_identity)
        .or_else(|| {
            (event.provider.as_deref() == Some("browser_fingerprint"))
                .then(|| {
                    event
                        .provider_event_id
                        .as_deref()
                        .map(|value| format!("fp:{value}"))
                })
                .flatten()
        })?;
    let identity_kind = identity_kind(&identity).to_string();
    let source_ip = details
        .as_ref()
        .and_then(parse_client_identity_source_ip)
        .unwrap_or_else(|| event.source_ip.clone());
    let site_domain = event
        .provider_site_domain
        .clone()
        .or_else(|| details.as_ref().and_then(parse_client_identity_host));
    let user_agent = details.as_ref().and_then(parse_client_identity_user_agent);
    let behavior = details.as_ref().and_then(parse_behavior_payload);

    Some(ParsedSecurityContext {
        identity,
        identity_kind,
        source_ip,
        site_domain,
        user_agent,
        behavior,
    })
}

fn parse_behavior_identity(details: &Value) -> Option<String> {
    details
        .get("l7_behavior")
        .and_then(|value| value.get("identity"))
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_client_identity_source_ip(details: &Value) -> Option<String> {
    details
        .get("client_identity")
        .and_then(|value| value.get("resolved_client_ip"))
        .or_else(|| {
            details
                .get("client_identity")
                .and_then(|value| value.get("source_ip"))
        })
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_client_identity_host(details: &Value) -> Option<String> {
    parse_client_identity_header(details, "host")
}

fn parse_client_identity_user_agent(details: &Value) -> Option<String> {
    parse_client_identity_header(details, "user-agent")
}

fn parse_client_identity_header(details: &Value, name: &str) -> Option<String> {
    details
        .get("client_identity")
        .and_then(|value| value.get("headers"))
        .and_then(|value| value.as_array())
        .and_then(|headers| {
            headers.iter().find_map(|entry| {
                let pair = entry.as_array()?;
                let key = pair.first()?.as_str()?.trim();
                let value = pair.get(1)?.as_str()?.trim();
                (key.eq_ignore_ascii_case(name) && !value.is_empty()).then(|| value.to_string())
            })
        })
}

fn parse_behavior_payload(details: &Value) -> Option<ParsedBehaviorPayload> {
    let behavior = details.get("l7_behavior")?;
    let identity = behavior
        .get("identity")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim();
    if identity.is_empty() {
        return None;
    }
    Some(ParsedBehaviorPayload {
        action: parse_optional_text(behavior.get("action")),
        score: parse_i64_field(behavior.get("score")),
        dominant_route: parse_optional_text(behavior.get("dominant_route")),
        focused_document_route: parse_optional_text(behavior.get("focused_document_route")),
        focused_api_route: parse_optional_text(behavior.get("focused_api_route")),
        distinct_routes: parse_i64_field(behavior.get("distinct_routes")),
        repeated_ratio: parse_i64_field(behavior.get("repeated_ratio")),
        document_repeated_ratio: parse_i64_field(behavior.get("document_repeated_ratio")),
        api_repeated_ratio: parse_i64_field(behavior.get("api_repeated_ratio")),
        document_requests: parse_i64_field(behavior.get("document_requests")),
        api_requests: parse_i64_field(behavior.get("api_requests")),
        non_document_requests: parse_i64_field(behavior.get("non_document_requests")),
        interval_jitter_ms: parse_optional_i64(behavior.get("interval_jitter_ms")),
        challenge_count_window: parse_i64_field(behavior.get("challenge_count_window")),
        session_span_secs: parse_i64_field(behavior.get("session_span_secs")),
        flags_json: parse_flags_json(behavior.get("flags")),
    })
}

fn parse_optional_text(value: Option<&Value>) -> Option<String> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn parse_i64_field(value: Option<&Value>) -> i64 {
    parse_optional_i64(value).unwrap_or_default()
}

fn parse_optional_i64(value: Option<&Value>) -> Option<i64> {
    match value {
        Some(Value::Number(number)) => number.as_i64(),
        Some(Value::String(raw)) => raw.trim().parse::<i64>().ok(),
        _ => None,
    }
}

fn parse_flags_json(value: Option<&Value>) -> String {
    if let Some(raw) = value.and_then(Value::as_str) {
        let items = raw
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect::<Vec<_>>();
        return serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string());
    }
    "[]".to_string()
}

fn identity_kind(identity: &str) -> &'static str {
    if identity.starts_with("fp:") {
        "fingerprint"
    } else if identity.starts_with("pfp:") {
        "passive_fingerprint"
    } else if identity.starts_with("cookie:") {
        "cookie"
    } else if identity.starts_with("ipua:") {
        "ipua"
    } else {
        "other"
    }
}

fn session_key(identity: &str, site_domain: Option<&str>) -> String {
    format!("{}|{}", identity, site_domain.unwrap_or("*"))
}

async fn upsert_fingerprint_profile(
    pool: &SqlitePool,
    event: &crate::storage::SecurityEventEntry,
    context: &ParsedSecurityContext,
) -> Result<()> {
    let is_behavior_event = context.behavior.is_some();
    let is_challenge = context
        .behavior
        .as_ref()
        .and_then(|value| value.action.as_deref())
        .map(|value| value == "challenge")
        .unwrap_or(false);
    let is_block = context
        .behavior
        .as_ref()
        .and_then(|value| value.action.as_deref())
        .map(|value| value == "block")
        .unwrap_or(false);
    let latest_score = context.behavior.as_ref().map(|value| value.score);
    let max_score = latest_score.unwrap_or_default();
    let latest_action = context
        .behavior
        .as_ref()
        .and_then(|value| value.action.clone());

    sqlx::query(
        r#"
        INSERT INTO fingerprint_profiles (
            identity, identity_kind, source_ip, first_seen_at, last_seen_at,
            first_site_domain, last_site_domain, first_user_agent, last_user_agent,
            total_security_events, total_behavior_events, total_challenges, total_blocks,
            latest_score, max_score, latest_action, reputation_score, notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, 0, '')
        ON CONFLICT(identity) DO UPDATE SET
            source_ip = excluded.source_ip,
            last_seen_at = excluded.last_seen_at,
            last_site_domain = COALESCE(excluded.last_site_domain, fingerprint_profiles.last_site_domain),
            last_user_agent = COALESCE(excluded.last_user_agent, fingerprint_profiles.last_user_agent),
            total_security_events = fingerprint_profiles.total_security_events + 1,
            total_behavior_events = fingerprint_profiles.total_behavior_events + excluded.total_behavior_events,
            total_challenges = fingerprint_profiles.total_challenges + excluded.total_challenges,
            total_blocks = fingerprint_profiles.total_blocks + excluded.total_blocks,
            latest_score = COALESCE(excluded.latest_score, fingerprint_profiles.latest_score),
            max_score = MAX(fingerprint_profiles.max_score, excluded.max_score),
            latest_action = COALESCE(excluded.latest_action, fingerprint_profiles.latest_action)
        "#,
    )
    .bind(&context.identity)
    .bind(&context.identity_kind)
    .bind(&context.source_ip)
    .bind(event.created_at)
    .bind(event.created_at)
    .bind(&context.site_domain)
    .bind(&context.site_domain)
    .bind(&context.user_agent)
    .bind(&context.user_agent)
    .bind(if is_behavior_event { 1 } else { 0 })
    .bind(if is_challenge { 1 } else { 0 })
    .bind(if is_block { 1 } else { 0 })
    .bind(latest_score)
    .bind(max_score)
    .bind(&latest_action)
    .execute(pool)
    .await?;
    Ok(())
}

async fn upsert_behavior_session(
    pool: &SqlitePool,
    event: &crate::storage::SecurityEventEntry,
    context: &ParsedSecurityContext,
    behavior: &ParsedBehaviorPayload,
) -> Result<()> {
    let key = session_key(&context.identity, context.site_domain.as_deref());
    let is_challenge = behavior.action.as_deref() == Some("challenge");
    let is_block = behavior.action.as_deref() == Some("block");
    sqlx::query(
        r#"
        INSERT INTO behavior_sessions (
            session_key, identity, source_ip, site_domain, opened_at, last_seen_at,
            event_count, challenge_count, block_count, latest_action, latest_uri, latest_reason,
            dominant_route, focused_document_route, focused_api_route, distinct_routes,
            repeated_ratio, document_repeated_ratio, api_repeated_ratio, document_requests,
            api_requests, non_document_requests, interval_jitter_ms, session_span_secs, flags_json
        )
        VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_key) DO UPDATE SET
            source_ip = excluded.source_ip,
            last_seen_at = excluded.last_seen_at,
            event_count = behavior_sessions.event_count + 1,
            challenge_count = behavior_sessions.challenge_count + excluded.challenge_count,
            block_count = behavior_sessions.block_count + excluded.block_count,
            latest_action = COALESCE(excluded.latest_action, behavior_sessions.latest_action),
            latest_uri = COALESCE(excluded.latest_uri, behavior_sessions.latest_uri),
            latest_reason = excluded.latest_reason,
            dominant_route = COALESCE(excluded.dominant_route, behavior_sessions.dominant_route),
            focused_document_route = COALESCE(excluded.focused_document_route, behavior_sessions.focused_document_route),
            focused_api_route = COALESCE(excluded.focused_api_route, behavior_sessions.focused_api_route),
            distinct_routes = MAX(behavior_sessions.distinct_routes, excluded.distinct_routes),
            repeated_ratio = MAX(behavior_sessions.repeated_ratio, excluded.repeated_ratio),
            document_repeated_ratio = MAX(behavior_sessions.document_repeated_ratio, excluded.document_repeated_ratio),
            api_repeated_ratio = MAX(behavior_sessions.api_repeated_ratio, excluded.api_repeated_ratio),
            document_requests = MAX(behavior_sessions.document_requests, excluded.document_requests),
            api_requests = MAX(behavior_sessions.api_requests, excluded.api_requests),
            non_document_requests = MAX(behavior_sessions.non_document_requests, excluded.non_document_requests),
            interval_jitter_ms = COALESCE(excluded.interval_jitter_ms, behavior_sessions.interval_jitter_ms),
            session_span_secs = MAX(behavior_sessions.session_span_secs, excluded.session_span_secs),
            flags_json = excluded.flags_json
        "#,
    )
    .bind(&key)
    .bind(&context.identity)
    .bind(&context.source_ip)
    .bind(&context.site_domain)
    .bind(event.created_at)
    .bind(event.created_at)
    .bind(if is_challenge { 1 } else { 0 })
    .bind(if is_block { 1 } else { 0 })
    .bind(&behavior.action)
    .bind(&event.uri)
    .bind(&event.reason)
    .bind(&behavior.dominant_route)
    .bind(&behavior.focused_document_route)
    .bind(&behavior.focused_api_route)
    .bind(behavior.distinct_routes)
    .bind(behavior.repeated_ratio)
    .bind(behavior.document_repeated_ratio)
    .bind(behavior.api_repeated_ratio)
    .bind(behavior.document_requests)
    .bind(behavior.api_requests)
    .bind(behavior.non_document_requests)
    .bind(behavior.interval_jitter_ms)
    .bind(behavior.session_span_secs)
    .bind(&behavior.flags_json)
    .execute(pool)
    .await?;
    Ok(())
}

async fn insert_behavior_event(
    pool: &SqlitePool,
    event: &crate::storage::SecurityEventEntry,
    context: &ParsedSecurityContext,
    behavior: &ParsedBehaviorPayload,
) -> Result<()> {
    let key = session_key(&context.identity, context.site_domain.as_deref());
    sqlx::query(
        r#"
        INSERT INTO behavior_events (
            security_event_id, identity, session_key, source_ip, site_domain, http_method,
            uri, action, reason, score, dominant_route, focused_document_route,
            focused_api_route, distinct_routes, repeated_ratio, document_repeated_ratio,
            api_repeated_ratio, document_requests, api_requests, non_document_requests,
            interval_jitter_ms, challenge_count_window, session_span_secs, flags_json, created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        "#,
    )
    .bind(event.id)
    .bind(&context.identity)
    .bind(&key)
    .bind(&context.source_ip)
    .bind(&context.site_domain)
    .bind(&event.http_method)
    .bind(&event.uri)
    .bind(&behavior.action)
    .bind(&event.reason)
    .bind(behavior.score)
    .bind(&behavior.dominant_route)
    .bind(&behavior.focused_document_route)
    .bind(&behavior.focused_api_route)
    .bind(behavior.distinct_routes)
    .bind(behavior.repeated_ratio)
    .bind(behavior.document_repeated_ratio)
    .bind(behavior.api_repeated_ratio)
    .bind(behavior.document_requests)
    .bind(behavior.api_requests)
    .bind(behavior.non_document_requests)
    .bind(behavior.interval_jitter_ms)
    .bind(behavior.challenge_count_window)
    .bind(behavior.session_span_secs)
    .bind(&behavior.flags_json)
    .bind(event.created_at)
    .execute(pool)
    .await?;
    Ok(())
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
