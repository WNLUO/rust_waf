#![cfg(feature = "api")]

use axum::body::Body;
use http::{Request, StatusCode};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tower::util::ServiceExt;
use waf::api::build_test_router;
use waf::{Config, RuntimeProfile, SqliteStore, WafContext};

fn unique_test_db_path(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let suffix = rand::random::<u64>();
    std::env::temp_dir()
        .join(format!("waf_e2e_{}_{}_{}.db", name, nanos, suffix))
        .display()
        .to_string()
}

async fn seeded_context(token: &str) -> Arc<WafContext> {
    let mut config = Config::default();
    config.runtime_profile = RuntimeProfile::Standard;
    config.api_enabled = true;
    config.sqlite_enabled = true;
    config.sqlite_path = unique_test_db_path("site_hot_reload");
    config.admin_api_auth.enabled = true;
    config.admin_api_auth.bearer_token = token.to_string();
    config = config.normalized();

    let store = SqliteStore::new(config.sqlite_path.clone(), true)
        .await
        .unwrap();
    store.seed_app_config(&config).await.unwrap();
    drop(store);

    Arc::new(WafContext::new(config).await.unwrap())
}

#[tokio::test]
async fn creating_site_via_admin_api_refreshes_gateway_runtime_immediately() {
    let context = seeded_context("secret-token").await;
    let router = build_test_router(Arc::clone(&context));

    let payload = serde_json::json!({
        "name": "Portal",
        "primary_hostname": "portal.example.com",
        "hostnames": ["portal.example.com"],
        "listen_ports": ["8080"],
        "upstreams": ["127.0.0.1:9000"],
        "enabled": true,
        "tls_enabled": false,
        "local_certificate_id": null,
        "source": "manual",
        "sync_mode": "manual",
        "notes": "",
        "last_synced_at": null
    });

    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/sites/local")
                .header("authorization", "Bearer secret-token")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
    assert!(
        context
            .gateway_runtime
            .resolve_site(Some("portal.example.com"), 8080)
            .is_some(),
        "gateway runtime should pick up the new site without a restart"
    );
}
