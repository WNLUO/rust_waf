mod models;
mod query;
mod schema;
mod store;
mod support;
mod upserts;

pub use self::models::*;
#[cfg(any(feature = "api", test))]
pub use self::query::*;
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
use std::sync::atomic::{AtomicU64, Ordering};
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
