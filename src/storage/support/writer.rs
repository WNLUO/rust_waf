use super::super::{
    BlockedIpRecord, SecurityEventRecord, StorageCommand, StorageMetricsCache, StorageRealtimeEvent,
};
use super::backup::checkpoint_wal;
use super::behavior::persist_behavior_intelligence;
use anyhow::Result;
use log::{debug, warn};
use serde_json::Value;
use sqlx::SqlitePool;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Notify};

const MAX_EVENT_DETAILS_BYTES: usize = 4 * 1024;

pub(crate) async fn run_writer(
    pool: SqlitePool,
    mut receiver: mpsc::Receiver<StorageCommand>,
    realtime_tx: tokio::sync::broadcast::Sender<StorageRealtimeEvent>,
    metrics_cache: Arc<StorageMetricsCache>,
    pending_writes: Arc<AtomicU64>,
    pending_write_notify: Arc<Notify>,
) {
    let writer_delay = writer_delay_from_env();
    while let Some(command) = receiver.recv().await {
        let result = match command {
            StorageCommand::SecurityEvent(event) => {
                persist_security_event(&pool, event, Some(metrics_cache.as_ref()))
                    .await
                    .map(StorageRealtimeEvent::SecurityEvent)
            }
            StorageCommand::BlockedIp(record) => {
                persist_blocked_ip(&pool, record, Some(metrics_cache.as_ref()))
                    .await
                    .map(StorageRealtimeEvent::BlockedIpUpsert)
            }
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
        if !writer_delay.is_zero() {
            tokio::time::sleep(writer_delay).await;
        }
        finish_pending_write(&pending_writes, &pending_write_notify);
    }
}

fn writer_delay_from_env() -> Duration {
    env::var("WAF_SQLITE_WRITER_DELAY_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|delay_ms| *delay_ms > 0)
        .map(Duration::from_millis)
        .unwrap_or_default()
}

pub(crate) async fn persist_security_event(
    pool: &SqlitePool,
    mut event: SecurityEventRecord,
    metrics_cache: Option<&StorageMetricsCache>,
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
    if let Some(metrics_cache) = metrics_cache {
        metrics_cache.increment_security_events();
        metrics_cache.update_latest_event_at(persisted.created_at);
    }
    Ok(persisted)
}

pub(crate) async fn persist_blocked_ip(
    pool: &SqlitePool,
    record: BlockedIpRecord,
    metrics_cache: Option<&StorageMetricsCache>,
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
    let persisted = crate::storage::BlockedIpEntry {
        id: result.last_insert_rowid(),
        provider: record.provider,
        provider_remote_id: record.provider_remote_id,
        ip: record.ip,
        reason: record.reason,
        blocked_at: record.blocked_at,
        expires_at: record.expires_at,
    };
    if let Some(metrics_cache) = metrics_cache {
        metrics_cache.increment_blocked_ips();
    }
    Ok(persisted)
}

pub(crate) fn finish_pending_write(pending_writes: &AtomicU64, pending_write_notify: &Notify) {
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
            event.details_json = Some(format!(
                "{{\"truncated\":true,\"raw\":\"{}...\"}}",
                &details_json[..MAX_EVENT_DETAILS_BYTES.min(details_json.len())]
            ));
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

    if let Some(client_identity) = object
        .get_mut("client_identity")
        .and_then(Value::as_object_mut)
    {
        client_identity.remove("configured_real_ip_header_value");
        if let Some(headers) = client_identity
            .get_mut("headers")
            .and_then(Value::as_array_mut)
        {
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
    serde_json::to_string(&Value::Object(object))
        .unwrap_or_else(|_| "{\"truncated\":true}".to_string())
}

pub(crate) async fn wait_for_pending_writes(
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
