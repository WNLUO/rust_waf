use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use waf::storage::LocalSiteUpsert;
use waf::{Config, RuntimeProfile, SqliteStore, WafContext};

fn unique_test_db_path(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let suffix = rand::random::<u64>();
    std::env::temp_dir()
        .join(format!("waf_runtime_{}_{}_{}.db", name, nanos, suffix))
        .display()
        .to_string()
}

#[tokio::test]
async fn refreshing_gateway_runtime_picks_up_new_site_routes() {
    let mut config = Config::default();
    config.runtime_profile = RuntimeProfile::Standard;
    config.sqlite_enabled = true;
    config.sqlite_path = unique_test_db_path("gateway_reload");
    config = config.normalized();

    let store = SqliteStore::new(config.sqlite_path.clone(), true)
        .await
        .unwrap();
    store.seed_app_config(&config).await.unwrap();

    let context = Arc::new(WafContext::new(config).await.unwrap());
    assert!(context
        .gateway_runtime
        .resolve_site(Some("portal.example.com"), 8080)
        .is_none());

    store
        .insert_local_site(&LocalSiteUpsert {
            name: "Portal".to_string(),
            primary_hostname: "portal.example.com".to_string(),
            hostnames: vec!["portal.example.com".to_string()],
            listen_ports: vec!["8080".to_string()],
            upstreams: vec!["127.0.0.1:9000".to_string()],
            safeline_intercept: None,
            enabled: true,
            tls_enabled: false,
            local_certificate_id: None,
            source: "manual".to_string(),
            sync_mode: "manual".to_string(),
            notes: String::new(),
            last_synced_at: None,
        })
        .await
        .unwrap();

    context
        .refresh_gateway_runtime_from_storage()
        .await
        .unwrap();

    let site = context
        .gateway_runtime
        .resolve_site(Some("portal.example.com"), 8080)
        .expect("site should be visible after runtime refresh");
    assert_eq!(site.name, "Portal");
    assert_eq!(site.upstream_endpoint.as_deref(), Some("127.0.0.1:9000"));
}
