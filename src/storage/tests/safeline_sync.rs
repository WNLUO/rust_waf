use super::*;

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
