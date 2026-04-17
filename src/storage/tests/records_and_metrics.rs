use super::*;

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
