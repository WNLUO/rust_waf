use super::*;

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
