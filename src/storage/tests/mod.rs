use super::*;
use crate::config::RuntimeProfile;
use crate::config::{RuleAction, RuleLayer, Severity};
use sqlx::sqlite::SqlitePoolOptions;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

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

mod certificates_and_sites;
mod events_and_blocked;
mod queue_pressure;
mod records_and_metrics;
mod rules_and_config;
mod safeline_sync;
mod schema_and_backups;
