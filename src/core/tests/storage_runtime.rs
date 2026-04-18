use super::*;

#[tokio::test]
async fn test_context_loads_and_refreshes_sqlite_rules() {
    let db_path = unique_test_db_path("rules_refresh");
    let config = Config {
        interface: "lo0".to_string(),
        listen_addrs: vec!["127.0.0.1:0".to_string()],
        tcp_upstream_addr: None,
        udp_upstream_addr: None,
        runtime_profile: RuntimeProfile::Standard,
        api_enabled: false,
        api_bind: "127.0.0.1:3740".to_string(),
        bloom_enabled: false,
        l4_bloom_false_positive_verification: false,
        l7_bloom_false_positive_verification: false,
        maintenance_interval_secs: 30,
        l4_config: L4Config::default(),
        l7_config: L7Config::default(),
        http3_config: Http3Config::default(),
        rules: vec![test_rule("seed-1", "attack")],
        metrics_enabled: true,
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        sqlite_rules_enabled: true,
        max_concurrent_tasks: 128,
        ..Config::default()
    };

    let context = WafContext::new(config).await.unwrap();
    assert_eq!(context.active_rule_count(), 1);

    let store = context.sqlite_store.as_ref().unwrap();
    store
        .seed_rules(&[test_rule("seed-2", "exploit")])
        .await
        .unwrap();

    let refreshed = context.refresh_rules_from_storage().await.unwrap();
    assert!(refreshed);
    assert_eq!(context.active_rule_count(), 2);
}

#[tokio::test]
async fn test_context_restores_active_local_blocked_ips_into_runtime_memory() {
    let db_path = unique_test_db_path("blocked_ip_restore");
    let bootstrap_store = SqliteStore::new(db_path.clone(), true).await.unwrap();
    let now = unix_timestamp();
    bootstrap_store.enqueue_blocked_ip(crate::storage::BlockedIpRecord::new(
        "203.0.113.10",
        "restore me",
        now,
        now + 120,
    ));
    bootstrap_store.enqueue_blocked_ip(crate::storage::BlockedIpRecord::new(
        "203.0.113.11",
        "already expired",
        now - 120,
        now - 1,
    ));
    bootstrap_store.flush().await.unwrap();
    bootstrap_store.shutdown().await.unwrap();

    let config = Config {
        interface: "lo0".to_string(),
        listen_addrs: vec!["127.0.0.1:0".to_string()],
        tcp_upstream_addr: None,
        udp_upstream_addr: None,
        runtime_profile: RuntimeProfile::Standard,
        api_enabled: false,
        api_bind: "127.0.0.1:3740".to_string(),
        bloom_enabled: false,
        l4_bloom_false_positive_verification: false,
        l7_bloom_false_positive_verification: false,
        maintenance_interval_secs: 30,
        l4_config: L4Config {
            connection_rate_limit: 1,
            ..L4Config::default()
        },
        l7_config: L7Config::default(),
        http3_config: Http3Config::default(),
        metrics_enabled: true,
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        sqlite_rules_enabled: true,
        max_concurrent_tasks: 128,
        ..Config::default()
    };

    let context = WafContext::new(config).await.unwrap();
    let stats = context
        .l4_inspector()
        .expect("l4 inspector should be available")
        .get_statistics();
    assert_eq!(stats.connections.blocked_connections, 1);
}
