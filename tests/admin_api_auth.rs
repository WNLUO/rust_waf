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
        .join(format!("waf_integration_{}_{}_{}.db", name, nanos, suffix))
        .display()
        .to_string()
}

async fn seeded_context(token: &str) -> Arc<WafContext> {
    let mut config = Config::default();
    config.runtime_profile = RuntimeProfile::Standard;
    config.api_enabled = true;
    config.sqlite_enabled = true;
    config.sqlite_path = unique_test_db_path("admin_auth");
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
async fn health_endpoint_remains_public() {
    let router = build_test_router(seeded_context("secret-token").await);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn protected_admin_endpoint_requires_bearer_token() {
    let router = build_test_router(seeded_context("secret-token").await);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/settings")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn protected_admin_endpoint_accepts_valid_bearer_token() {
    let router = build_test_router(seeded_context("secret-token").await);

    let response = router
        .oneshot(
            Request::builder()
                .uri("/settings")
                .header("authorization", "Bearer secret-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
