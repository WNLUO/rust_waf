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

#[tokio::test]
async fn test_sqlite_store_persists_records() {
    let path = unique_test_db_path("records");
    let store = SqliteStore::new(path.clone(), true).await.unwrap();

    store.enqueue_security_event(SecurityEventRecord {
        layer: "L7".to_string(),
        provider: None,
        provider_event_id: Some("evt-query-1".to_string()),
        provider_site_id: None,
        provider_site_name: None,
        provider_site_domain: None,
        action: "block".to_string(),
        reason: "test event".to_string(),
        details_json: None,
        source_ip: "127.0.0.1".to_string(),
        dest_ip: "127.0.0.1".to_string(),
        source_port: 12345,
        dest_port: 8080,
        protocol: "TCP".to_string(),
        http_method: Some("GET".to_string()),
        uri: Some("/".to_string()),
        http_version: Some("HTTP/1.1".to_string()),
        created_at: unix_timestamp(),
        handled: false,
        handled_at: None,
    });
    store.enqueue_blocked_ip(BlockedIpRecord::new(
        "127.0.0.1",
        "rate limit exceeded",
        unix_timestamp(),
        unix_timestamp() + 30,
    ));

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite://{}", path))
        .await
        .unwrap();

    let security_events_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM security_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    let blocked_ips_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blocked_ips")
        .fetch_one(&pool)
        .await
        .unwrap();

    assert_eq!(security_events_count, 1);
    assert_eq!(blocked_ips_count, 1);

    let summary = store.metrics_summary().await.unwrap();
    assert_eq!(summary.security_events, 1);
    assert_eq!(summary.blocked_ips, 1);
    assert!(summary.latest_event_at.is_some());
    assert_eq!(summary.rules, 0);
    assert!(summary.latest_rule_update_at.is_none());
    assert_eq!(summary.queue_capacity, 1024);
    assert_eq!(summary.dropped_security_events, 0);
    assert_eq!(summary.dropped_blocked_ips, 0);
}

#[tokio::test]
async fn test_sqlite_store_persists_ai_audit_reports_and_feedback() {
    let path = unique_test_db_path("ai_audit_reports");
    let store = SqliteStore::new(path, true).await.unwrap();

    let report_id = store
        .create_ai_audit_report(
            123,
            "xiaomi_mimo",
            false,
            "medium",
            "headline",
            r#"{"report_id":null,"generated_at":123,"provider_used":"xiaomi_mimo","fallback_used":false,"execution_notes":[],"risk_level":"medium","headline":"headline","executive_summary":[],"findings":[],"recommendations":[],"summary":{"generated_at":123,"window_seconds":300,"sampled_events":0,"total_events":0,"active_rules":0,"current":{"adaptive_system_pressure":"normal","adaptive_reasons":[],"l4_overload_level":"normal","auto_tuning_controller_state":"stable","auto_tuning_last_adjust_reason":null,"auto_tuning_last_adjust_diff":[],"identity_pressure_percent":0.0,"l7_friction_pressure_percent":0.0,"slow_attack_pressure_percent":0.0},"counters":{"proxied_requests":0,"blocked_packets":0,"blocked_l4":0,"blocked_l7":0,"l7_cc_challenges":0,"l7_cc_blocks":0,"l7_cc_delays":0,"l7_behavior_challenges":0,"l7_behavior_blocks":0,"l7_behavior_delays":0,"trusted_proxy_permit_drops":0,"trusted_proxy_l4_degrade_actions":0,"slow_attack_hits":0,"average_proxy_latency_micros":0},"identity_states":[],"primary_signals":[],"labels":[],"top_source_ips":[],"top_routes":[],"top_hosts":[],"recent_events":[]}}"#,
        )
        .await
        .unwrap();

    let reports = store
        .list_ai_audit_reports(&AiAuditReportQuery {
            limit: 10,
            offset: 0,
            feedback_status: None,
        })
        .await
        .unwrap();

    assert_eq!(reports.total, 1);
    assert_eq!(reports.items[0].id, report_id);
    assert_eq!(reports.items[0].provider_used, "xiaomi_mimo");

    let updated = store
        .update_ai_audit_report_feedback(report_id, Some("confirmed"), Some("looks good"))
        .await
        .unwrap();
    assert!(updated);

    let reports = store
        .list_ai_audit_reports(&AiAuditReportQuery {
            limit: 10,
            offset: 0,
            feedback_status: Some("confirmed".to_string()),
        })
        .await
        .unwrap();
    assert_eq!(reports.total, 1);
    assert_eq!(
        reports.items[0].feedback_status.as_deref(),
        Some("confirmed")
    );
    assert_eq!(
        reports.items[0].feedback_notes.as_deref(),
        Some("looks good")
    );
}

#[tokio::test]
async fn test_sqlite_store_metrics_cache_tracks_deletes() {
    let path = unique_test_db_path("metrics_cache_deletes");
    let store = SqliteStore::new(path, true).await.unwrap();
    let now = unix_timestamp();

    store.enqueue_security_event(SecurityEventRecord {
        layer: "L7".to_string(),
        provider: None,
        provider_event_id: None,
        provider_site_id: None,
        provider_site_name: None,
        provider_site_domain: None,
        action: "block".to_string(),
        reason: "newer event".to_string(),
        details_json: None,
        source_ip: "127.0.0.1".to_string(),
        dest_ip: "127.0.0.1".to_string(),
        source_port: 12345,
        dest_port: 8080,
        protocol: "TCP".to_string(),
        http_method: Some("GET".to_string()),
        uri: Some("/new".to_string()),
        http_version: Some("HTTP/1.1".to_string()),
        created_at: now,
        handled: false,
        handled_at: None,
    });
    store.enqueue_security_event(SecurityEventRecord {
        layer: "L7".to_string(),
        provider: None,
        provider_event_id: None,
        provider_site_id: None,
        provider_site_name: None,
        provider_site_domain: None,
        action: "alert".to_string(),
        reason: "older event".to_string(),
        details_json: None,
        source_ip: "127.0.0.2".to_string(),
        dest_ip: "127.0.0.1".to_string(),
        source_port: 12346,
        dest_port: 8080,
        protocol: "TCP".to_string(),
        http_method: Some("GET".to_string()),
        uri: Some("/old".to_string()),
        http_version: Some("HTTP/1.1".to_string()),
        created_at: now - 10,
        handled: false,
        handled_at: None,
    });
    store.enqueue_blocked_ip(BlockedIpRecord::new(
        "198.51.100.1",
        "test block 1",
        now,
        now + 60,
    ));
    store.enqueue_blocked_ip(BlockedIpRecord::new(
        "198.51.100.2",
        "test block 2",
        now,
        now - 1,
    ));
    store.flush().await.unwrap();

    let summary = store.metrics_summary().await.unwrap();
    assert_eq!(summary.security_events, 2);
    assert_eq!(summary.blocked_ips, 2);
    assert_eq!(summary.latest_event_at, Some(now));

    let blocked = store
        .list_blocked_ips(&BlockedIpQuery::default())
        .await
        .unwrap();
    let active_block = blocked
        .items
        .iter()
        .find(|item| item.ip == "198.51.100.1")
        .unwrap();
    assert!(store.delete_blocked_ip(active_block.id).await.unwrap());

    let cleaned = store
        .cleanup_expired_blocked_ips(&BlockedIpCleanupQuery {
            source_scope: BlockedIpSourceScope::All,
            provider: None,
            blocked_from: None,
            blocked_to: None,
            expires_before: now,
        })
        .await
        .unwrap();
    assert_eq!(cleaned.len(), 1);

    let purged = store.purge_old_security_events(now - 5).await.unwrap();
    assert_eq!(purged, 1);

    let summary = store.metrics_summary().await.unwrap();
    assert_eq!(summary.security_events, 1);
    assert_eq!(summary.blocked_ips, 0);
    assert_eq!(summary.latest_event_at, Some(now));
}

#[tokio::test]
async fn test_sqlite_store_persists_fingerprint_profiles_and_behavior_history() {
    let path = unique_test_db_path("behavior_history");
    let store = SqliteStore::new(path.clone(), true).await.unwrap();

    store.enqueue_security_event(SecurityEventRecord {
        layer: "L7".to_string(),
        provider: None,
        provider_event_id: None,
        provider_site_id: None,
        provider_site_name: None,
        provider_site_domain: Some("example.com".to_string()),
        action: "respond".to_string(),
        reason: "l7 behavior guard challenged suspicious session: score=60".to_string(),
        details_json: Some(
            r#"{
              "client_identity": {
                "resolved_client_ip": "203.0.113.10",
                "headers": [
                  ["host", "example.com"],
                  ["user-agent", "MobileSafari"]
                ]
              },
              "l7_behavior": {
                "action": "challenge",
                "identity": "fp:test-fingerprint",
                "score": "60",
                "dominant_route": "/api/search",
                "focused_document_route": "/",
                "focused_api_route": "/api/search",
                "distinct_routes": "3",
                "repeated_ratio": "80",
                "document_repeated_ratio": "100",
                "api_repeated_ratio": "100",
                "document_requests": "1",
                "api_requests": "4",
                "non_document_requests": "8",
                "challenge_count_window": "1",
                "session_span_secs": "12",
                "flags": "focused_api_burst,single_query_endpoint"
              }
            }"#
            .to_string(),
        ),
        source_ip: "203.0.113.10".to_string(),
        dest_ip: "192.0.2.10".to_string(),
        source_port: 42310,
        dest_port: 443,
        protocol: "TCP".to_string(),
        http_method: Some("GET".to_string()),
        uri: Some("/api/search?q=test".to_string()),
        http_version: Some("HTTP/2.0".to_string()),
        created_at: unix_timestamp(),
        handled: false,
        handled_at: None,
    });

    store.flush().await.unwrap();

    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect(&format!("sqlite://{}", path))
        .await
        .unwrap();

    let profile_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM fingerprint_profiles")
        .fetch_one(&pool)
        .await
        .unwrap();
    let behavior_session_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM behavior_sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    let behavior_event_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM behavior_events")
        .fetch_one(&pool)
        .await
        .unwrap();
    let latest_profile: (String, String, i64, i64, i64) = sqlx::query_as(
        "SELECT identity, identity_kind, total_security_events, total_behavior_events, total_challenges FROM fingerprint_profiles LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let latest_session: (String, String, i64, i64, i64) = sqlx::query_as(
        "SELECT identity, focused_api_route, api_requests, api_repeated_ratio, challenge_count FROM behavior_sessions LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();

    assert_eq!(profile_count, 1);
    assert_eq!(behavior_session_count, 1);
    assert_eq!(behavior_event_count, 1);
    assert_eq!(latest_profile.0, "fp:test-fingerprint");
    assert_eq!(latest_profile.1, "fingerprint");
    assert_eq!(latest_profile.2, 1);
    assert_eq!(latest_profile.3, 1);
    assert_eq!(latest_profile.4, 1);
    assert_eq!(latest_session.0, "fp:test-fingerprint");
    assert_eq!(latest_session.1, "/api/search");
    assert_eq!(latest_session.2, 4);
    assert_eq!(latest_session.3, 100);
    assert_eq!(latest_session.4, 1);
}

#[tokio::test]
async fn test_sqlite_store_drops_low_priority_writes_under_queue_pressure() {
    let path = unique_test_db_path("queue_drops");
    let store = SqliteStore::new_with_queue_capacity(path, true, 1)
        .await
        .unwrap();

    for idx in 0..5_000 {
        store.enqueue_security_event(SecurityEventRecord {
            layer: "L7".to_string(),
            provider: None,
            provider_event_id: Some(format!("evt-drop-{idx}")),
            provider_site_id: None,
            provider_site_name: None,
            provider_site_domain: None,
            action: if idx % 2 == 0 {
                "respond".to_string()
            } else {
                "block".to_string()
            },
            reason: "queue pressure".to_string(),
            details_json: None,
            source_ip: "127.0.0.1".to_string(),
            dest_ip: "127.0.0.1".to_string(),
            source_port: 12345,
            dest_port: 8080,
            protocol: "TCP".to_string(),
            http_method: Some("GET".to_string()),
            uri: Some("/drop".to_string()),
            http_version: Some("HTTP/1.1".to_string()),
            created_at: unix_timestamp() + idx as i64,
            handled: false,
            handled_at: None,
        });
    }

    for idx in 0..5_000 {
        store.enqueue_blocked_ip(BlockedIpRecord::new(
            format!("198.51.100.{}", idx % 255),
            "queue pressure".to_string(),
            unix_timestamp(),
            unix_timestamp() + 60,
        ));
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    store.flush().await.unwrap();
    let summary = store.metrics_summary().await.unwrap();
    assert_eq!(summary.queue_capacity, 1);
    assert!(summary.dropped_security_events > 0);
    assert_eq!(summary.dropped_blocked_ips, 0);
    assert_eq!(summary.queue_depth, 0);
    assert!(summary.security_events > 0);
    assert!(summary.blocked_ips > 0);

    let aggregated = store
        .list_security_events(&SecurityEventQuery {
            action: Some("summary".to_string()),
            limit: 10,
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert!(aggregated.total > 0);
}

#[tokio::test]
async fn test_sqlite_store_aggregates_low_priority_events_by_route_and_time_window() {
    let path = unique_test_db_path("aggregated_route_window");
    let store = SqliteStore::new_with_queue_capacity(path, true, 1)
        .await
        .unwrap();
    let now = unix_timestamp().div_euclid(10) * 10;

    for created_at in [now, now + 1, now + 2] {
        store.enqueue_security_event(SecurityEventRecord {
            layer: "L7".to_string(),
            provider: None,
            provider_event_id: None,
            provider_site_id: None,
            provider_site_name: None,
            provider_site_domain: None,
            action: "alert".to_string(),
            reason: "burst on login".to_string(),
            details_json: None,
            source_ip: "203.0.113.20".to_string(),
            dest_ip: "10.0.0.2".to_string(),
            source_port: 40000,
            dest_port: 443,
            protocol: "TCP".to_string(),
            http_method: Some("POST".to_string()),
            uri: Some("/login?from=bot".to_string()),
            http_version: Some("HTTP/1.1".to_string()),
            created_at,
            handled: false,
            handled_at: None,
        });
    }

    for created_at in [now + 6, now + 7] {
        store.enqueue_security_event(SecurityEventRecord {
            layer: "L7".to_string(),
            provider: None,
            provider_event_id: None,
            provider_site_id: None,
            provider_site_name: None,
            provider_site_domain: None,
            action: "alert".to_string(),
            reason: "burst on login".to_string(),
            details_json: None,
            source_ip: "203.0.113.20".to_string(),
            dest_ip: "10.0.0.2".to_string(),
            source_port: 40000,
            dest_port: 443,
            protocol: "TCP".to_string(),
            http_method: Some("POST".to_string()),
            uri: Some("/login?from=bot".to_string()),
            http_version: Some("HTTP/1.1".to_string()),
            created_at,
            handled: false,
            handled_at: None,
        });
    }

    store.flush().await.unwrap();

    let aggregated = store
        .list_security_events(&SecurityEventQuery {
            action: Some("summary".to_string()),
            limit: 10,
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();

    assert_eq!(aggregated.total, 2);
    assert!(aggregated
        .items
        .iter()
        .all(|item| item.http_method.as_deref() == Some("POST")));
    assert!(aggregated
        .items
        .iter()
        .all(|item| item.uri.as_deref() == Some("/login?from=bot")));

    let details = aggregated
        .items
        .iter()
        .map(|item| serde_json::from_str::<serde_json::Value>(item.details_json.as_deref().unwrap()).unwrap())
        .collect::<Vec<_>>();
    assert!(details.iter().any(|value| {
        value["storage_pressure"]["count"].as_u64() == Some(3)
            && value["storage_pressure"]["route"].as_str() == Some("/login?from=bot")
    }));
    assert!(details.iter().any(|value| value["storage_pressure"]["count"].as_u64() == Some(2)));
}

#[tokio::test]
async fn test_sqlite_store_preserves_hotspots_and_merges_long_tail_sources() {
    let path = unique_test_db_path("aggregated_hotspots");
    let store = SqliteStore::new_with_queue_capacity(path, true, 1)
        .await
        .unwrap();
    let now = unix_timestamp().div_euclid(10) * 10;

    for idx in 0..40 {
        store.enqueue_security_event(SecurityEventRecord {
            layer: "L7".to_string(),
            provider: None,
            provider_event_id: None,
            provider_site_id: None,
            provider_site_name: None,
            provider_site_domain: None,
            action: "alert".to_string(),
            reason: "wide scan".to_string(),
            details_json: None,
            source_ip: format!("198.51.100.{idx}"),
            dest_ip: "10.0.0.2".to_string(),
            source_port: 40000,
            dest_port: 443,
            protocol: "TCP".to_string(),
            http_method: Some("GET".to_string()),
            uri: Some("/probe".to_string()),
            http_version: Some("HTTP/1.1".to_string()),
            created_at: now,
            handled: false,
            handled_at: None,
        });
    }

    for _ in 0..8 {
        store.enqueue_security_event(SecurityEventRecord {
            layer: "L7".to_string(),
            provider: None,
            provider_event_id: None,
            provider_site_id: None,
            provider_site_name: None,
            provider_site_domain: None,
            action: "alert".to_string(),
            reason: "wide scan".to_string(),
            details_json: None,
            source_ip: "203.0.113.99".to_string(),
            dest_ip: "10.0.0.2".to_string(),
            source_port: 40000,
            dest_port: 443,
            protocol: "TCP".to_string(),
            http_method: Some("GET".to_string()),
            uri: Some("/probe".to_string()),
            http_version: Some("HTTP/1.1".to_string()),
            created_at: now,
            handled: false,
            handled_at: None,
        });
    }

    store.flush().await.unwrap();

    let aggregated = store
        .list_security_events(&SecurityEventQuery {
            action: Some("summary".to_string()),
            limit: 100,
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();

    assert!(aggregated.total >= 2);
    assert!(aggregated
        .items
        .iter()
        .any(|item| item.source_ip == "203.0.113.99"));
    assert!(aggregated.items.iter().any(|item| item.source_ip == "*"));

    let details = aggregated
        .items
        .iter()
        .map(|item| {
            (
                item.source_ip.clone(),
                serde_json::from_str::<serde_json::Value>(item.details_json.as_deref().unwrap())
                    .unwrap(),
            )
        })
        .collect::<Vec<_>>();

    assert!(details.iter().any(|(source_ip, value)| {
        source_ip == "*"
            && value["storage_pressure"]["source_scope"].as_str() == Some("long_tail")
    }));
    assert!(details.iter().any(|(source_ip, value)| {
        source_ip == "203.0.113.99"
            && value["storage_pressure"]["source_scope"].as_str() == Some("hotspot")
            && value["storage_pressure"]["count"].as_u64().unwrap_or_default() >= 1
    }));
}

#[tokio::test]
async fn test_sqlite_store_seeds_and_loads_rules() {
    let path = unique_test_db_path("rules");
    let store = SqliteStore::new(path, true).await.unwrap();
    let rules = vec![
        Rule {
            id: "rule-1".to_string(),
            name: "Block SQLi".to_string(),
            enabled: true,
            layer: RuleLayer::L7,
            pattern: "(?i)union\\s+select".to_string(),
            action: RuleAction::Block,
            severity: Severity::High,
            plugin_template_id: None,
            response_template: None,
        },
        Rule {
            id: "rule-2".to_string(),
            name: "Alert Port Scan".to_string(),
            enabled: true,
            layer: RuleLayer::L4,
            pattern: "scan".to_string(),
            action: RuleAction::Alert,
            severity: Severity::Medium,
            plugin_template_id: None,
            response_template: None,
        },
    ];

    let inserted = store.seed_rules(&rules).await.unwrap();
    assert_eq!(inserted, 2);

    let inserted_again = store.seed_rules(&rules).await.unwrap();
    assert_eq!(inserted_again, 0);

    let loaded_rules = store.load_rules().await.unwrap();
    assert_eq!(loaded_rules.len(), 2);
    assert_eq!(loaded_rules[0].id, "rule-1");
    assert_eq!(loaded_rules[1].id, "rule-2");
    assert_eq!(
        store.load_rule("rule-1").await.unwrap().unwrap().name,
        "Block SQLi"
    );

    let updated_rule = Rule {
        id: "rule-1".to_string(),
        name: "Block Updated SQLi".to_string(),
        enabled: false,
        layer: RuleLayer::L7,
        pattern: "(?i)select".to_string(),
        action: RuleAction::Alert,
        severity: Severity::Critical,
        plugin_template_id: None,
        response_template: None,
    };
    store.upsert_rule(&updated_rule).await.unwrap();
    let fetched_updated = store.load_rule("rule-1").await.unwrap().unwrap();
    assert_eq!(fetched_updated.name, "Block Updated SQLi");
    assert!(!fetched_updated.enabled);
    assert_eq!(fetched_updated.action, RuleAction::Alert);
    assert_eq!(fetched_updated.severity, Severity::Critical);

    let inserted_new = store
        .insert_rule(&Rule {
            id: "rule-3".to_string(),
            name: "New Rule".to_string(),
            enabled: true,
            layer: RuleLayer::L4,
            pattern: "syn".to_string(),
            action: RuleAction::Block,
            severity: Severity::Low,
            plugin_template_id: None,
            response_template: None,
        })
        .await
        .unwrap();
    assert!(inserted_new);
    let inserted_duplicate = store.insert_rule(&updated_rule).await.unwrap();
    assert!(!inserted_duplicate);

    let deleted = store.delete_rule("rule-2").await.unwrap();
    assert!(deleted);
    let deleted_missing = store.delete_rule("missing").await.unwrap();
    assert!(!deleted_missing);

    let latest_version = store.latest_rules_version().await.unwrap();
    assert!(latest_version > 0);

    let summary = store.metrics_summary().await.unwrap();
    assert_eq!(summary.rules, 2);
    assert!(summary.latest_rule_update_at.is_some());
}

#[tokio::test]
async fn test_sqlite_store_seeds_and_updates_app_config() {
    let path = unique_test_db_path("app_config");
    let store = SqliteStore::new(path, true).await.unwrap();
    let initial = Config {
        runtime_profile: RuntimeProfile::Standard,
        api_enabled: true,
        sqlite_enabled: true,
        sqlite_path: "data/custom.db".to_string(),
        max_concurrent_tasks: 321,
        ..Config::default()
    };

    let inserted = store.seed_app_config(&initial).await.unwrap();
    assert!(inserted);

    let loaded = store.load_app_config().await.unwrap().unwrap();
    assert!(loaded.api_enabled);
    assert_eq!(loaded.sqlite_path, "data/custom.db");

    let inserted_again = store.seed_app_config(&Config::default()).await.unwrap();
    assert!(!inserted_again);

    let updated = Config {
        api_enabled: false,
        max_concurrent_tasks: 654,
        ..initial.clone()
    };
    store.upsert_app_config(&updated).await.unwrap();

    let loaded_updated = store.load_app_config().await.unwrap().unwrap();
    assert!(!loaded_updated.api_enabled);
    assert_eq!(loaded_updated.max_concurrent_tasks, 654);
}

#[tokio::test]
async fn test_sqlite_store_loads_legacy_app_config_with_default_safeline() {
    let path = unique_test_db_path("legacy_app_config");
    let store = SqliteStore::new(path, true).await.unwrap();

    sqlx::query(
        r#"
            INSERT INTO app_config (id, config_json, updated_at)
            VALUES (?, ?, ?)
            "#,
    )
    .bind(1_i64)
    .bind(r#"{"interface":"eth0","listen_addrs":["0.0.0.0:8080"],"runtime_profile":"minimal","api_enabled":false,"api_bind":"127.0.0.1:3740","bloom_enabled":false,"l4_bloom_false_positive_verification":false,"l7_bloom_false_positive_verification":false,"maintenance_interval_secs":60,"l4_config":{"ddos_protection_enabled":true,"advanced_ddos_enabled":false,"connection_rate_limit":64,"syn_flood_threshold":32,"max_tracked_ips":512,"max_blocked_ips":128,"state_ttl_secs":180,"bloom_filter_scale":1.0},"l7_config":{"http_inspection_enabled":true,"max_request_size":4096,"http2_config":{"enabled":false,"max_concurrent_streams":50,"max_frame_size":16384,"enable_priorities":true,"initial_window_size":65535},"bloom_filter_scale":1.0},"http3_config":{"enabled":false,"listen_addr":"0.0.0.0:8443","max_concurrent_streams":50,"idle_timeout_secs":60,"mtu":1200,"max_frame_size":65536,"enable_connection_migration":false,"qpack_table_size":2048,"certificate_path":null,"private_key_path":null,"enable_tls13":true},"rules":[],"metrics_enabled":true,"sqlite_enabled":true,"sqlite_path":"data/waf.db","sqlite_auto_migrate":true,"sqlite_rules_enabled":false,"max_concurrent_tasks":128}"#)
    .bind(unix_timestamp())
    .execute(&store.pool)
    .await
    .unwrap();

    let loaded = store.load_app_config().await.unwrap().unwrap();
    assert!(loaded.integrations.safeline.enabled);
    assert_eq!(
        loaded.integrations.safeline.auth_probe_path,
        "/api/open/system/key"
    );
    assert_eq!(loaded.console_settings.gateway_name, "玄枢防护网关");
}

#[tokio::test]
async fn test_sqlite_store_queries_events_and_blocked_ips() {
    let path = unique_test_db_path("queries");
    let store = SqliteStore::new(path, true).await.unwrap();
    let now = unix_timestamp();

    store.enqueue_security_event(SecurityEventRecord {
        layer: "L7".to_string(),
        provider: None,
        provider_event_id: Some("evt-query-1".to_string()),
        provider_site_id: None,
        provider_site_name: None,
        provider_site_domain: None,
        action: "block".to_string(),
        reason: "sql injection".to_string(),
        details_json: Some(
            serde_json::json!({
                "client_identity": {
                    "identity_state": "trusted_cdn_forwarded",
                    "forward_header_valid": true
                },
                "inspection_runtime": {
                    "rule_inspection_mode": "lightweight"
                }
            })
            .to_string(),
        ),
        source_ip: "10.0.0.1".to_string(),
        dest_ip: "10.0.0.2".to_string(),
        source_port: 50000,
        dest_port: 8080,
        protocol: "TCP".to_string(),
        http_method: Some("GET".to_string()),
        uri: Some("/login".to_string()),
        http_version: Some("HTTP/1.1".to_string()),
        created_at: now - 10,
        handled: false,
        handled_at: None,
    });
    store.enqueue_security_event(SecurityEventRecord {
        layer: "L4".to_string(),
        provider: None,
        provider_event_id: None,
        provider_site_id: None,
        provider_site_name: None,
        provider_site_domain: None,
        action: "alert".to_string(),
        reason: "slow attack detected".to_string(),
        details_json: None,
        source_ip: "10.0.0.3".to_string(),
        dest_ip: "10.0.0.2".to_string(),
        source_port: 40000,
        dest_port: 22,
        protocol: "TCP".to_string(),
        http_method: None,
        uri: None,
        http_version: None,
        created_at: now - 5,
        handled: false,
        handled_at: None,
    });
    store.enqueue_blocked_ip(BlockedIpRecord::new(
        "10.0.0.1",
        "rate limit exceeded",
        now - 15,
        now + 60,
    ));
    store.enqueue_blocked_ip(BlockedIpRecord::new(
        "10.0.0.4",
        "expired block",
        now - 120,
        now - 60,
    ));

    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let l7_events = store
        .list_security_events(&SecurityEventQuery {
            layer: Some("L7".to_string()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(l7_events.total, 1);
    assert_eq!(l7_events.items[0].reason, "sql injection");
    assert_eq!(
        l7_events.items[0].provider_event_id.as_deref(),
        Some("evt-query-1")
    );

    let blocked_only_events = store
        .list_security_events(&SecurityEventQuery {
            blocked_only: true,
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(blocked_only_events.total, 1);
    assert_eq!(blocked_only_events.items[0].action, "block");

    let recent_events = store
        .list_security_events(&SecurityEventQuery {
            created_from: Some(now - 7),
            sort_by: EventSortField::CreatedAt,
            sort_direction: SortDirection::Asc,
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(recent_events.total, 1);
    assert_eq!(recent_events.items[0].reason, "slow attack detected");

    let source_sorted_events = store
        .list_security_events(&SecurityEventQuery {
            sort_by: EventSortField::SourceIp,
            sort_direction: SortDirection::Asc,
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(source_sorted_events.total, 2);
    assert_eq!(source_sorted_events.items[0].source_ip, "10.0.0.1");

    let port_sorted_events = store
        .list_security_events(&SecurityEventQuery {
            sort_by: EventSortField::DestPort,
            sort_direction: SortDirection::Asc,
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(port_sorted_events.total, 2);
    assert_eq!(port_sorted_events.items[0].dest_port, 22);

    let identity_filtered_events = store
        .list_security_events(&SecurityEventQuery {
            identity_state: Some("trusted_cdn_forwarded".to_string()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(identity_filtered_events.total, 1);
    assert_eq!(identity_filtered_events.items[0].reason, "sql injection");

    let signal_filtered_events = store
        .list_security_events(&SecurityEventQuery {
            primary_signal: Some("slow_attack".to_string()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(signal_filtered_events.total, 1);
    assert_eq!(
        signal_filtered_events.items[0].reason,
        "slow attack detected"
    );

    let labeled_events = store
        .list_security_events(&SecurityEventQuery {
            labels: vec![
                "identity:trusted_cdn_forwarded".to_string(),
                "l7_rules:lightweight".to_string(),
            ],
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(labeled_events.total, 1);
    assert_eq!(labeled_events.items[0].reason, "sql injection");

    let active_blocks = store
        .list_blocked_ips(&BlockedIpQuery {
            active_only: true,
            ..BlockedIpQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(active_blocks.total, 1);
    assert_eq!(active_blocks.items[0].ip, "10.0.0.1");

    let sorted_blocks = store
        .list_blocked_ips(&BlockedIpQuery {
            sort_by: BlockedIpSortField::Ip,
            sort_direction: SortDirection::Asc,
            ..BlockedIpQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(sorted_blocks.total, 2);
    assert_eq!(sorted_blocks.items[0].ip, "10.0.0.1");

    let expires_sorted_blocks = store
        .list_blocked_ips(&BlockedIpQuery {
            sort_by: BlockedIpSortField::ExpiresAt,
            sort_direction: SortDirection::Asc,
            ..BlockedIpQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(expires_sorted_blocks.total, 2);
    assert_eq!(expires_sorted_blocks.items[0].ip, "10.0.0.4");

    let paged_blocks = store
        .list_blocked_ips(&BlockedIpQuery {
            limit: 1,
            offset: 1,
            ..BlockedIpQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(paged_blocks.limit, 1);
    assert_eq!(paged_blocks.offset, 1);
    assert_eq!(paged_blocks.items.len(), 1);

    let keyword_blocks = store
        .list_blocked_ips(&BlockedIpQuery {
            keyword: Some("rate limit".to_string()),
            ..BlockedIpQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(keyword_blocks.total, 1);
    assert_eq!(keyword_blocks.items[0].ip, "10.0.0.1");
}

#[tokio::test]
async fn test_sqlite_store_replaces_safeline_site_mappings() {
    let path = unique_test_db_path("safeline_site_mappings");
    let store = SqliteStore::new(path, true).await.unwrap();

    store
        .replace_safeline_site_mappings(&[
            SafeLineSiteMappingUpsert {
                safeline_site_id: "site-1".to_string(),
                safeline_site_name: "portal".to_string(),
                safeline_site_domain: "portal.example.com".to_string(),
                local_alias: "主站".to_string(),
                enabled: true,
                is_primary: true,
                notes: "prod".to_string(),
            },
            SafeLineSiteMappingUpsert {
                safeline_site_id: "site-2".to_string(),
                safeline_site_name: "admin".to_string(),
                safeline_site_domain: "admin.example.com".to_string(),
                local_alias: "后台".to_string(),
                enabled: false,
                is_primary: false,
                notes: String::new(),
            },
        ])
        .await
        .unwrap();

    let mappings = store.list_safeline_site_mappings().await.unwrap();
    assert_eq!(mappings.len(), 2);
    assert_eq!(mappings[0].safeline_site_id, "site-1");
    assert!(mappings[0].is_primary);

    store
        .replace_safeline_site_mappings(&[SafeLineSiteMappingUpsert {
            safeline_site_id: "site-3".to_string(),
            safeline_site_name: "api".to_string(),
            safeline_site_domain: "api.example.com".to_string(),
            local_alias: "接口".to_string(),
            enabled: true,
            is_primary: false,
            notes: "new".to_string(),
        }])
        .await
        .unwrap();

    let replaced = store.list_safeline_site_mappings().await.unwrap();
    assert_eq!(replaced.len(), 1);
    assert_eq!(replaced[0].safeline_site_id, "site-3");
}

#[tokio::test]
async fn test_sqlite_store_replaces_safeline_cached_sites() {
    let path = unique_test_db_path("safeline_cached_sites");
    let store = SqliteStore::new(path, true).await.unwrap();

    let cached_at = store
        .replace_safeline_cached_sites(&[
            SafeLineCachedSiteUpsert {
                remote_site_id: "site-1".to_string(),
                name: "portal".to_string(),
                domain: "portal.example.com".to_string(),
                status: "online".to_string(),
                enabled: Some(true),
                server_names: vec!["portal.example.com".to_string()],
                ports: vec!["80".to_string()],
                ssl_ports: vec!["443".to_string()],
                upstreams: vec!["http://127.0.0.1:8080".to_string()],
                ssl_enabled: true,
                cert_id: Some(10),
                cert_type: Some(2),
                cert_filename: Some("portal.crt".to_string()),
                key_filename: Some("portal.key".to_string()),
                health_check: Some(true),
                raw_json: "{\"id\":\"site-1\"}".to_string(),
            },
            SafeLineCachedSiteUpsert {
                remote_site_id: "site-2".to_string(),
                name: "admin".to_string(),
                domain: "admin.example.com".to_string(),
                status: "offline".to_string(),
                enabled: Some(false),
                server_names: vec!["admin.example.com".to_string()],
                ports: vec!["8080".to_string()],
                ssl_ports: vec![],
                upstreams: vec!["http://127.0.0.1:8081".to_string()],
                ssl_enabled: false,
                cert_id: None,
                cert_type: None,
                cert_filename: None,
                key_filename: None,
                health_check: Some(false),
                raw_json: "{\"id\":\"site-2\"}".to_string(),
            },
        ])
        .await
        .unwrap();

    assert!(cached_at.is_some());
    let cached = store.list_safeline_cached_sites().await.unwrap();
    assert_eq!(cached.len(), 2);
    assert_eq!(cached[0].updated_at, cached[1].updated_at);

    let replaced_at = store
        .replace_safeline_cached_sites(&[SafeLineCachedSiteUpsert {
            remote_site_id: "site-3".to_string(),
            name: "api".to_string(),
            domain: "api.example.com".to_string(),
            status: "online".to_string(),
            enabled: Some(true),
            server_names: vec!["api.example.com".to_string()],
            ports: vec!["80".to_string()],
            ssl_ports: vec!["443".to_string()],
            upstreams: vec!["http://127.0.0.1:8082".to_string()],
            ssl_enabled: true,
            cert_id: None,
            cert_type: None,
            cert_filename: None,
            key_filename: None,
            health_check: None,
            raw_json: "{\"id\":\"site-3\"}".to_string(),
        }])
        .await
        .unwrap();

    assert!(replaced_at.is_some());
    let replaced = store.list_safeline_cached_sites().await.unwrap();
    assert_eq!(replaced.len(), 1);
    assert_eq!(replaced[0].remote_site_id, "site-3");

    let cleared_at = store.replace_safeline_cached_sites(&[]).await.unwrap();
    assert_eq!(cleared_at, None);
    assert!(store.list_safeline_cached_sites().await.unwrap().is_empty());
}

#[tokio::test]
async fn test_sqlite_store_manages_local_certificates() {
    let path = unique_test_db_path("local_certificates");
    let store = SqliteStore::new(path, true).await.unwrap();

    let certificate_id = store
        .insert_local_certificate(&LocalCertificateUpsert {
            name: "prod wildcard".to_string(),
            domains: vec!["example.com".to_string(), "*.example.com".to_string()],
            issuer: "Let's Encrypt".to_string(),
            valid_from: Some(1_700_000_000),
            valid_to: Some(1_800_000_000),
            source_type: "manual".to_string(),
            provider_remote_id: Some("31".to_string()),
            provider_remote_domains: vec!["example.com".to_string(), "*.example.com".to_string()],
            last_remote_fingerprint: Some("fp31".to_string()),
            sync_status: "synced".to_string(),
            sync_message: "ok".to_string(),
            auto_sync_enabled: true,
            trusted: true,
            expired: false,
            notes: "initial import".to_string(),
            last_synced_at: Some(1_700_000_100),
        })
        .await
        .unwrap();

    let loaded = store
        .load_local_certificate(certificate_id)
        .await
        .unwrap()
        .unwrap();
    let domains: Vec<String> = serde_json::from_str(&loaded.domains_json).unwrap();
    assert_eq!(loaded.name, "prod wildcard");
    assert_eq!(domains, vec!["example.com", "*.example.com"]);
    assert_eq!(loaded.provider_remote_id.as_deref(), Some("31"));
    assert!(loaded.trusted);

    store
        .upsert_local_certificate_secret(
            certificate_id,
            "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----",
            "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----",
        )
        .await
        .unwrap();
    let secret = store
        .load_local_certificate_secret(certificate_id)
        .await
        .unwrap()
        .unwrap();
    assert!(secret.certificate_pem.contains("BEGIN CERTIFICATE"));
    assert!(secret.private_key_pem.contains("BEGIN PRIVATE KEY"));

    let updated = store
        .update_local_certificate(
            certificate_id,
            &LocalCertificateUpsert {
                name: "prod wildcard v2".to_string(),
                domains: vec!["example.com".to_string()],
                issuer: "Let's Encrypt".to_string(),
                valid_from: Some(1_700_000_000),
                valid_to: Some(1_900_000_000),
                source_type: "safeline".to_string(),
                provider_remote_id: Some("32".to_string()),
                provider_remote_domains: vec!["example.com".to_string()],
                last_remote_fingerprint: Some("fp32".to_string()),
                sync_status: "synced".to_string(),
                sync_message: "updated".to_string(),
                auto_sync_enabled: false,
                trusted: true,
                expired: false,
                notes: "rotated".to_string(),
                last_synced_at: Some(1_700_000_200),
            },
        )
        .await
        .unwrap();
    assert!(updated);

    let listed = store.list_local_certificates().await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "prod wildcard v2");
    assert_eq!(listed[0].provider_remote_id.as_deref(), Some("32"));

    store
        .upsert_local_certificate_secret(
            certificate_id,
            "-----BEGIN CERTIFICATE-----\nCERT-V2\n-----END CERTIFICATE-----",
            "-----BEGIN PRIVATE KEY-----\nKEY-V2\n-----END PRIVATE KEY-----",
        )
        .await
        .unwrap();
    let updated_secret = store
        .load_local_certificate_secret(certificate_id)
        .await
        .unwrap()
        .unwrap();
    assert!(updated_secret.certificate_pem.contains("CERT-V2"));

    let deleted = store
        .delete_local_certificate(certificate_id)
        .await
        .unwrap();
    assert!(deleted);
    assert!(store
        .load_local_certificate(certificate_id)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .load_local_certificate_secret(certificate_id)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn test_sqlite_store_manages_local_sites_and_sync_links() {
    let path = unique_test_db_path("local_sites");
    let store = SqliteStore::new(path, true).await.unwrap();

    let certificate_id = store
        .insert_local_certificate(&LocalCertificateUpsert {
            name: "portal cert".to_string(),
            domains: vec!["portal.example.com".to_string()],
            issuer: "Acme CA".to_string(),
            valid_from: None,
            valid_to: None,
            source_type: "manual".to_string(),
            provider_remote_id: None,
            provider_remote_domains: Vec::new(),
            last_remote_fingerprint: None,
            sync_status: "idle".to_string(),
            sync_message: String::new(),
            auto_sync_enabled: false,
            trusted: false,
            expired: false,
            notes: String::new(),
            last_synced_at: None,
        })
        .await
        .unwrap();

    let site_id = store
        .insert_local_site(&LocalSiteUpsert {
            name: "Portal".to_string(),
            primary_hostname: "portal.example.com".to_string(),
            hostnames: vec![
                "portal.example.com".to_string(),
                "www.portal.example.com".to_string(),
            ],
            listen_ports: vec!["80".to_string(), "443".to_string()],
            upstreams: vec!["http://127.0.0.1:8080".to_string()],
            safeline_intercept: None,
            enabled: true,
            tls_enabled: true,
            local_certificate_id: Some(certificate_id),
            source: "manual".to_string(),
            sync_mode: "bidirectional".to_string(),
            notes: "production".to_string(),
            last_synced_at: Some(1_700_000_300),
        })
        .await
        .unwrap();

    let loaded_site = store.load_local_site(site_id).await.unwrap().unwrap();
    let hostnames: Vec<String> = serde_json::from_str(&loaded_site.hostnames_json).unwrap();
    let listen_ports: Vec<String> = serde_json::from_str(&loaded_site.listen_ports_json).unwrap();
    assert_eq!(loaded_site.primary_hostname, "portal.example.com");
    assert_eq!(hostnames.len(), 2);
    assert_eq!(listen_ports, vec!["80", "443"]);
    assert_eq!(loaded_site.local_certificate_id, Some(certificate_id));

    let updated = store
        .update_local_site(
            site_id,
            &LocalSiteUpsert {
                name: "Portal Main".to_string(),
                primary_hostname: "portal.example.com".to_string(),
                hostnames: vec!["portal.example.com".to_string()],
                listen_ports: vec!["443".to_string()],
                upstreams: vec![
                    "http://127.0.0.1:8080".to_string(),
                    "http://127.0.0.1:8081".to_string(),
                ],
                safeline_intercept: None,
                enabled: true,
                tls_enabled: true,
                local_certificate_id: Some(certificate_id),
                source: "safeline".to_string(),
                sync_mode: "remote_to_local".to_string(),
                notes: "synced".to_string(),
                last_synced_at: Some(1_700_000_400),
            },
        )
        .await
        .unwrap();
    assert!(updated);

    store
        .upsert_site_sync_link(&SiteSyncLinkUpsert {
            local_site_id: site_id,
            provider: "safeline".to_string(),
            remote_site_id: "remote-1".to_string(),
            remote_site_name: "portal.example.com".to_string(),
            remote_cert_id: Some("31".to_string()),
            sync_mode: "remote_to_local".to_string(),
            last_local_hash: Some("local-a".to_string()),
            last_remote_hash: Some("remote-a".to_string()),
            last_error: None,
            last_synced_at: Some(1_700_000_500),
        })
        .await
        .unwrap();

    store
        .upsert_site_sync_link(&SiteSyncLinkUpsert {
            local_site_id: site_id,
            provider: "safeline".to_string(),
            remote_site_id: "remote-2".to_string(),
            remote_site_name: "portal-new.example.com".to_string(),
            remote_cert_id: Some("32".to_string()),
            sync_mode: "bidirectional".to_string(),
            last_local_hash: Some("local-b".to_string()),
            last_remote_hash: Some("remote-b".to_string()),
            last_error: Some("conflict".to_string()),
            last_synced_at: Some(1_700_000_600),
        })
        .await
        .unwrap();

    let links = store.list_site_sync_links().await.unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].remote_site_id, "remote-2");
    assert_eq!(links[0].remote_cert_id.as_deref(), Some("32"));
    assert_eq!(links[0].last_error.as_deref(), Some("conflict"));

    let deleted_link = store.delete_site_sync_link(links[0].id).await.unwrap();
    assert!(deleted_link);
    assert!(store.list_site_sync_links().await.unwrap().is_empty());

    let deleted_site = store.delete_local_site(site_id).await.unwrap();
    assert!(deleted_site);
    assert!(store.load_local_site(site_id).await.unwrap().is_none());

    let cert_after_site_delete = store
        .load_local_certificate(certificate_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(cert_after_site_delete.id, certificate_id);
}

#[tokio::test]
async fn test_sqlite_store_deduplicates_safeline_events() {
    let path = unique_test_db_path("safeline_event_dedup");
    let store = SqliteStore::new(path, true).await.unwrap();
    let event = SecurityEventRecord {
        layer: "safeline".to_string(),
        provider: Some("safeline".to_string()),
        provider_event_id: Some("event-1".to_string()),
        provider_site_id: Some("site-1".to_string()),
        provider_site_name: Some("主站".to_string()),
        provider_site_domain: Some("portal.example.com".to_string()),
        action: "block".to_string(),
        reason: "safeline:sqli".to_string(),
        details_json: None,
        source_ip: "203.0.113.10".to_string(),
        dest_ip: "10.0.0.10".to_string(),
        source_port: 44321,
        dest_port: 443,
        protocol: "HTTP".to_string(),
        http_method: Some("POST".to_string()),
        uri: Some("/login".to_string()),
        http_version: Some("HTTP/1.1".to_string()),
        created_at: unix_timestamp(),
        handled: false,
        handled_at: None,
    };

    let first = store
        .import_safeline_security_events(std::slice::from_ref(&event))
        .await
        .unwrap();
    assert_eq!(first.imported, 1);
    assert_eq!(first.skipped, 0);

    let second = store
        .import_safeline_security_events(std::slice::from_ref(&event))
        .await
        .unwrap();
    assert_eq!(second.imported, 0);
    assert_eq!(second.skipped, 1);

    let stored = store
        .list_security_events(&SecurityEventQuery::default())
        .await
        .unwrap();
    assert_eq!(stored.total, 1);
    assert_eq!(
        stored.items[0].provider_event_id.as_deref(),
        Some("event-1")
    );

    let events = store
        .list_security_events(&SecurityEventQuery::default())
        .await
        .unwrap();
    assert_eq!(events.total, 1);

    let state = store
        .load_safeline_sync_state("events")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.last_imported_count, 0);
    assert_eq!(state.last_skipped_count, 1);
}

#[tokio::test]
async fn test_sqlite_store_deduplicates_safeline_blocked_ip_pull() {
    let path = unique_test_db_path("safeline_blocked_ip_pull_dedup");
    let store = SqliteStore::new(path, true).await.unwrap();
    let record = BlockedIpRecord {
        provider: Some("safeline".to_string()),
        provider_remote_id: Some("remote-1".to_string()),
        ip: "203.0.113.10".to_string(),
        reason: "safeline:test".to_string(),
        blocked_at: unix_timestamp(),
        expires_at: unix_timestamp() + 600,
    };

    let first = store
        .import_safeline_blocked_ips_pull(std::slice::from_ref(&record))
        .await
        .unwrap();
    assert_eq!(first.imported, 1);
    assert_eq!(first.skipped, 0);

    let second = store
        .import_safeline_blocked_ips_pull(std::slice::from_ref(&record))
        .await
        .unwrap();
    assert_eq!(second.imported, 0);
    assert_eq!(second.skipped, 1);

    let blocked = store
        .list_blocked_ips(&BlockedIpQuery {
            provider: Some("safeline".to_string()),
            ..BlockedIpQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(blocked.total, 1);

    let state = store
        .load_safeline_sync_state("blocked_ips_pull")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.last_imported_count, 0);
    assert_eq!(state.last_skipped_count, 1);
}

#[tokio::test]
async fn test_sqlite_store_blocked_ip_pull_dedup_is_isolated_from_push_dedup() {
    let path = unique_test_db_path("safeline_blocked_ip_pull_isolated");
    let store = SqliteStore::new(path, true).await.unwrap();
    let now = unix_timestamp();
    let pushed = BlockedIpEntry {
        id: 1,
        provider: Some("safeline".to_string()),
        provider_remote_id: Some("remote-1".to_string()),
        ip: "203.0.113.20".to_string(),
        reason: "safeline:test".to_string(),
        blocked_at: now,
        expires_at: now + 1200,
    };
    let pulled = BlockedIpRecord {
        provider: pushed.provider.clone(),
        provider_remote_id: pushed.provider_remote_id.clone(),
        ip: pushed.ip.clone(),
        reason: pushed.reason.clone(),
        blocked_at: pushed.blocked_at,
        expires_at: pushed.expires_at,
    };

    let push_result = store
        .import_safeline_blocked_ips_sync_result(&[pushed], 0)
        .await
        .unwrap();
    assert_eq!(push_result.synced, 1);

    let pull_result = store
        .import_safeline_blocked_ips_pull(&[pulled])
        .await
        .unwrap();
    assert_eq!(pull_result.imported, 1);
    assert_eq!(pull_result.skipped, 0);
}
