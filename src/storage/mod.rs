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
use tokio::sync::mpsc;

use self::models::{serialize_rule_response_template, StoredAppConfigRow, StoredRuleRow};
#[cfg(any(feature = "api", test))]
use self::query::{
    append_blocked_ip_filters, append_blocked_ip_sort, append_event_sort,
    append_security_event_filters, normalized_limit,
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
    dropped_security_events: Arc<AtomicU64>,
    dropped_blocked_ips: Arc<AtomicU64>,
}

enum StorageCommand {
    SecurityEvent(SecurityEventRecord),
    BlockedIp(BlockedIpRecord),
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
