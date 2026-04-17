use super::*;

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
        .map(|item| {
            serde_json::from_str::<serde_json::Value>(item.details_json.as_deref().unwrap())
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert!(details.iter().any(|value| {
        value["storage_pressure"]["count"].as_u64() == Some(3)
            && value["storage_pressure"]["route"].as_str() == Some("/login?from=bot")
    }));
    assert!(details
        .iter()
        .any(|value| value["storage_pressure"]["count"].as_u64() == Some(2)));
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

    let insight = store.aggregation_insight_summary();
    assert!(insight.active_bucket_count >= 2);
    assert!(insight.long_tail_event_count > 0);
    assert!(insight
        .hotspot_sources
        .iter()
        .any(|item| item.source_ip == "203.0.113.99"));

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
        source_ip == "*" && value["storage_pressure"]["source_scope"].as_str() == Some("long_tail")
    }));
    assert!(details.iter().any(|(source_ip, value)| {
        source_ip == "203.0.113.99"
            && value["storage_pressure"]["source_scope"].as_str() == Some("hotspot")
            && value["storage_pressure"]["count"]
                .as_u64()
                .unwrap_or_default()
                >= 1
    }));
}
