use super::super::*;

fn unique_test_db_path(name: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir()
        .join(format!("{}_{}_{}.db", env!("CARGO_PKG_NAME"), name, nanos))
        .display()
        .to_string()
}

#[tokio::test]
async fn runtime_aggregate_events_routes_http_drops_to_summary_records() {
    let config = crate::config::Config {
        sqlite_path: unique_test_db_path("runtime_aggregate_http_drop"),
        sqlite_queue_capacity: 8,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let packet = PacketInfo::from_socket_addrs(
        "198.51.100.20:42300".parse().unwrap(),
        "10.0.0.2:443".parse().unwrap(),
        Protocol::TCP,
    );
    let mut request = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "POST".to_string(),
        "/login?next=/admin".to_string(),
    );
    request.set_client_ip("198.51.100.20".to_string());
    request.add_metadata("runtime.aggregate_events".to_string(), "true".to_string());

    let result = InspectionResult::drop(InspectionLayer::L7, "runtime pressure drop");
    persist_http_inspection_event(&context, &packet, &request, &result);

    let store = context.sqlite_store.as_ref().expect("sqlite store");
    store.flush().await.unwrap();
    let events = store
        .list_security_events(&crate::storage::SecurityEventQuery {
            action: Some("summary".to_string()),
            limit: 10,
            ..crate::storage::SecurityEventQuery::default()
        })
        .await
        .unwrap();

    assert_eq!(events.total, 1);
    let event = &events.items[0];
    assert_eq!(event.layer, "L7");
    assert_eq!(event.action, "summary");
    assert_eq!(event.http_method.as_deref(), Some("POST"));
    assert_eq!(event.uri.as_deref(), Some("/login?next=/admin"));
    let details: serde_json::Value =
        serde_json::from_str(event.details_json.as_deref().unwrap()).unwrap();
    assert_eq!(
        details["storage_pressure"]["original_reason"].as_str(),
        Some("runtime pressure drop")
    );
    assert_eq!(details["storage_pressure"]["count"].as_u64(), Some(1));
}

#[tokio::test]
async fn trim_event_persistence_skips_soft_http_alerts_under_pressure() {
    let config = crate::config::Config {
        sqlite_path: unique_test_db_path("runtime_trim_alert"),
        sqlite_queue_capacity: 8,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let packet = PacketInfo::from_socket_addrs(
        "198.51.100.21:42300".parse().unwrap(),
        "10.0.0.2:443".parse().unwrap(),
        Protocol::TCP,
    );
    let mut request = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "GET".to_string(),
        "/probe".to_string(),
    );
    request.add_metadata(
        "runtime.pressure.trim_event_persistence".to_string(),
        "true".to_string(),
    );

    let result = InspectionResult::alert(InspectionLayer::L7, "trim me");
    persist_http_inspection_event(&context, &packet, &request, &result);

    let store = context.sqlite_store.as_ref().expect("sqlite store");
    store.flush().await.unwrap();
    let events = store
        .list_security_events(&crate::storage::SecurityEventQuery {
            limit: 10,
            ..crate::storage::SecurityEventQuery::default()
        })
        .await
        .unwrap();

    assert_eq!(events.total, 0);
}

#[tokio::test]
async fn trim_event_persistence_aggregates_http_drops_without_full_details() {
    let config = crate::config::Config {
        sqlite_path: unique_test_db_path("runtime_trim_drop_aggregate"),
        sqlite_queue_capacity: 8,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let packet = PacketInfo::from_socket_addrs(
        "198.51.100.22:42300".parse().unwrap(),
        "10.0.0.2:443".parse().unwrap(),
        Protocol::TCP,
    );
    let mut request = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "POST".to_string(),
        "/api/login".to_string(),
    );
    request.set_client_ip("198.51.100.22".to_string());
    request.add_metadata(
        "runtime.pressure.trim_event_persistence".to_string(),
        "true".to_string(),
    );
    request.add_metadata("early_defense.action".to_string(), "drop".to_string());
    request.add_metadata(
        "early_defense.reason".to_string(),
        "l4_high_risk_runtime_pressure".to_string(),
    );

    let result = InspectionResult::drop(InspectionLayer::L7, "early defense dropped request");
    persist_http_inspection_event(&context, &packet, &request, &result);

    let store = context.sqlite_store.as_ref().expect("sqlite store");
    store.flush().await.unwrap();
    let events = store
        .list_security_events(&crate::storage::SecurityEventQuery {
            action: Some("summary".to_string()),
            limit: 10,
            ..crate::storage::SecurityEventQuery::default()
        })
        .await
        .unwrap();

    assert_eq!(events.total, 1);
    let event = &events.items[0];
    assert_eq!(event.action, "summary");
    assert_eq!(event.uri.as_deref(), Some("/api/login"));
    let details: serde_json::Value =
        serde_json::from_str(event.details_json.as_deref().unwrap()).unwrap();
    assert_eq!(
        details["storage_pressure"]["mode"].as_str(),
        Some("aggregated")
    );
    assert_eq!(
        details["storage_pressure"]["original_reason"].as_str(),
        Some("early defense dropped request")
    );
    assert!(
        details.get("client_identity").is_none(),
        "aggregated pressure event should avoid full identity details"
    );
}
