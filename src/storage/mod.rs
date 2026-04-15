mod models;
mod query;
mod schema;
mod store;
mod support;
mod upserts;

pub use self::models::*;
#[cfg(any(feature = "api", test))]
pub use self::query::*;
pub(crate) use self::support::apply_write_pressure_detail_slimming;
use self::support::*;
pub use self::upserts::*;

use crate::config::{Config, Rule};
use anyhow::Result;
use log::{info, warn};
use serde_json;
use sqlx::SqlitePool;
#[cfg(any(feature = "api", test))]
use sqlx::{QueryBuilder, Sqlite};
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, Notify};
use tokio::task::JoinHandle;

use self::models::{serialize_rule_response_template, StoredAppConfigRow, StoredRuleRow};
#[cfg(any(feature = "api", test))]
use self::query::{
    append_blocked_ip_cleanup_filters, append_blocked_ip_filters, append_blocked_ip_sort,
    append_event_sort, append_security_event_filters, normalized_limit,
};

const SQLITE_STARTUP_BACKUP_RETENTION: usize = 5;
const SQLITE_CORRUPT_BACKUP_RETENTION: usize = 5;
const STORAGE_OPTION_NONE_SENTINEL: i64 = -1;

#[derive(Debug, Default)]
struct StorageMetricsCache {
    security_events: AtomicU64,
    blocked_ips: AtomicU64,
    latest_event_at: AtomicI64,
}

impl StorageMetricsCache {
    fn new(security_events: u64, blocked_ips: u64, latest_event_at: Option<i64>) -> Self {
        Self {
            security_events: AtomicU64::new(security_events),
            blocked_ips: AtomicU64::new(blocked_ips),
            latest_event_at: AtomicI64::new(
                latest_event_at.unwrap_or(STORAGE_OPTION_NONE_SENTINEL),
            ),
        }
    }

    fn security_events(&self) -> u64 {
        self.security_events.load(Ordering::Relaxed)
    }

    fn blocked_ips(&self) -> u64 {
        self.blocked_ips.load(Ordering::Relaxed)
    }

    fn latest_event_at(&self) -> Option<i64> {
        match self.latest_event_at.load(Ordering::Relaxed) {
            STORAGE_OPTION_NONE_SENTINEL => None,
            value => Some(value),
        }
    }

    fn increment_security_events(&self) {
        self.security_events.fetch_add(1, Ordering::Relaxed);
    }

    fn decrement_security_events_by(&self, count: u64) {
        self.security_events.fetch_sub(count, Ordering::Relaxed);
    }

    fn update_latest_event_at(&self, created_at: i64) {
        let mut current = self.latest_event_at.load(Ordering::Relaxed);
        loop {
            if current != STORAGE_OPTION_NONE_SENTINEL && current >= created_at {
                break;
            }
            match self.latest_event_at.compare_exchange(
                current,
                created_at,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    fn increment_blocked_ips(&self) {
        self.blocked_ips.fetch_add(1, Ordering::Relaxed);
    }

    fn decrement_blocked_ips_by(&self, count: u64) {
        self.blocked_ips.fetch_sub(count, Ordering::Relaxed);
    }
}

#[derive(Clone)]
pub struct SqliteStore {
    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pool: SqlitePool,
    db_path: PathBuf,
    sender: mpsc::Sender<StorageCommand>,
    queue_capacity: usize,
    pending_writes: Arc<AtomicU64>,
    pending_write_notify: Arc<Notify>,
    writer_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
    dropped_security_events: Arc<AtomicU64>,
    dropped_blocked_ips: Arc<AtomicU64>,
    metrics_cache: Arc<StorageMetricsCache>,
    realtime_tx: broadcast::Sender<StorageRealtimeEvent>,
}

#[allow(clippy::large_enum_variant)]
enum StorageCommand {
    SecurityEvent(SecurityEventRecord),
    BlockedIp(BlockedIpRecord),
    Flush { ack: oneshot::Sender<()> },
    Shutdown { ack: oneshot::Sender<()> },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum StorageRealtimeEvent {
    SecurityEvent(SecurityEventEntry),
    BlockedIpUpsert(BlockedIpEntry),
    BlockedIpDeleted(i64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SqliteOpenErrorKind {
    Corruption,
    PermissionDenied,
    PathUnavailable,
    DiskFull,
    Other,
}

#[cfg(test)]
mod tests;
