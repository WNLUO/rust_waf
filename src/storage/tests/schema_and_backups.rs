use super::*;

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
    let app_config_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'app_config'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let safeline_site_mappings_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'safeline_site_mappings'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let safeline_cached_sites_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'safeline_cached_sites'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let local_certificates_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'local_certificates'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let local_sites_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'local_sites'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let site_sync_links_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'site_sync_links'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let local_certificate_secrets_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'local_certificate_secrets'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let fingerprint_profiles_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'fingerprint_profiles'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let behavior_sessions_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'behavior_sessions'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let behavior_events_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'behavior_events'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let ai_audit_reports_exists: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'ai_audit_reports'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(security_events_exists, 1);
    assert_eq!(blocked_ips_exists, 1);
    assert_eq!(rules_exists, 1);
    assert_eq!(app_config_exists, 1);
    assert_eq!(safeline_site_mappings_exists, 1);
    assert_eq!(safeline_cached_sites_exists, 1);
    assert_eq!(local_certificates_exists, 1);
    assert_eq!(local_sites_exists, 1);
    assert_eq!(site_sync_links_exists, 1);
    assert_eq!(local_certificate_secrets_exists, 1);
    assert_eq!(fingerprint_profiles_exists, 1);
    assert_eq!(behavior_sessions_exists, 1);
    assert_eq!(behavior_events_exists, 1);
    assert_eq!(ai_audit_reports_exists, 1);
}

#[tokio::test]
async fn test_sqlite_store_recovers_from_corrupted_database() {
    let path = unique_test_db_path("corrupted_recovery");
    tokio::fs::write(&path, b"this-is-not-a-valid-sqlite-database")
        .await
        .unwrap();

    let _store = SqliteStore::new(path.clone(), true).await.unwrap();

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite://{}", path))
        .await
        .unwrap();

    let integrity_check: String = sqlx::query_scalar("PRAGMA integrity_check(1)")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(integrity_check, "ok");

    let file_name = Path::new(&path)
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap();
    let backup_prefix = format!("{file_name}.corrupt.");
    let backup_exists = backup_dir(Path::new(&path))
        .read_dir()
        .unwrap()
        .filter_map(|entry| entry.ok())
        .any(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&backup_prefix) && name.ends_with(".db"))
        });
    assert!(backup_exists, "expected corrupted database backup to exist");
}

#[tokio::test]
async fn test_sqlite_store_creates_startup_backup_for_existing_database() {
    let path = unique_test_db_path("startup_backup");
    let _store = SqliteStore::new(path.clone(), true).await.unwrap();

    let _reopened = SqliteStore::new(path.clone(), true).await.unwrap();

    let file_name = Path::new(&path)
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap();
    let backup_prefix = format!("{file_name}.startup.");
    let backup_exists = backup_dir(Path::new(&path))
        .read_dir()
        .unwrap()
        .filter_map(|entry| entry.ok())
        .any(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(&backup_prefix) && name.ends_with(".db"))
        });
    assert!(backup_exists, "expected startup database backup to exist");
}

#[tokio::test]
async fn test_sqlite_store_manual_backup_creates_snapshot() {
    let path = unique_test_db_path("manual_backup");
    let store = SqliteStore::new(path, true).await.unwrap();

    let backup_path = store.create_backup().await.unwrap();

    assert!(backup_path.exists(), "expected manual backup file to exist");
}
