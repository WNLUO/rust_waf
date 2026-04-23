use super::super::{schema::initialize_schema, SqliteOpenErrorKind};
use anyhow::Result;
use log::warn;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;
use std::path::Path;
use std::str::FromStr;

pub(crate) async fn open_pool(
    db_path: &Path,
    auto_migrate: bool,
    pool_size: u32,
) -> Result<SqlitePool> {
    let connect_options =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", db_path.display()))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            // FULL reduces the risk of losing committed records when the process or host crashes.
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true);
    let pool_size = pool_size.max(1).min(32);
    let pool = SqlitePoolOptions::new()
        .max_connections(pool_size)
        .connect_with(connect_options)
        .await?;
    validate_database(&pool).await?;
    if auto_migrate {
        initialize_schema(&pool).await?;
    }
    Ok(pool)
}

pub(crate) fn classify_sqlite_error(error: &anyhow::Error) -> SqliteOpenErrorKind {
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

pub(crate) fn is_sqlite_corruption_error(error: &anyhow::Error) -> bool {
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

pub(crate) fn log_sqlite_open_error(path: &Path, error: &anyhow::Error) {
    let kind = classify_sqlite_error(error);
    warn!(
        "Failed to open SQLite database: path={}, kind={:?}, error={}",
        path.display(),
        kind,
        error
    );
}

pub(crate) async fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await?;
        }
    }
    Ok(())
}
