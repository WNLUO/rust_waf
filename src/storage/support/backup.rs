use super::super::{SQLITE_CORRUPT_BACKUP_RETENTION, SQLITE_STARTUP_BACKUP_RETENTION};
use anyhow::{Context, Result};
use sqlx::SqlitePool;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BackupKind {
    Startup,
    Manual,
    Corrupt,
}

pub(crate) async fn backup_corrupted_db(path: &Path) -> Result<PathBuf> {
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

pub(crate) async fn create_backup_snapshot(
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

pub(crate) async fn checkpoint_wal(pool: &SqlitePool) -> Result<()> {
    sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
        .execute(pool)
        .await?;
    Ok(())
}

async fn ensure_backup_dir(path: &Path) -> Result<()> {
    tokio::fs::create_dir_all(backup_dir(path)).await?;
    Ok(())
}

pub(crate) fn backup_dir(path: &Path) -> PathBuf {
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
