#![cfg(feature = "api")]

use axum::body::{to_bytes, Body};
use http::{Method, Request, StatusCode};
use serde_json::Value;
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
        .join(format!("waf_l4_refresh_{}_{}_{}.db", name, nanos, suffix))
        .display()
        .to_string()
}

async fn seeded_context() -> Arc<WafContext> {
    let mut config = Config::default();
    config.runtime_profile = RuntimeProfile::Standard;
    config.api_enabled = true;
    config.sqlite_enabled = true;
    config.sqlite_path = unique_test_db_path("runtime_refresh");
    config = config.normalized();

    let store = SqliteStore::new(config.sqlite_path.clone(), true)
        .await
        .unwrap();
    store.seed_app_config(&config).await.unwrap();
    drop(store);

    Arc::new(WafContext::new(config).await.unwrap())
}

#[tokio::test]
async fn updating_l4_config_refreshes_runtime_without_restart() {
    let router = build_test_router(seeded_context().await);

    let initial_stats = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/l4/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(initial_stats.status(), StatusCode::OK);
    let initial_body = to_bytes(initial_stats.into_body(), usize::MAX)
        .await
        .unwrap();
    let initial_json: Value = serde_json::from_slice(&initial_body).unwrap();
    assert_eq!(initial_json["enabled"], Value::Bool(true));
    assert!(initial_json["behavior"]["overview"]["bucket_count"].is_number());
    assert!(initial_json["behavior"]["top_buckets"].is_array());

    let update_payload = serde_json::json!({
        "ddos_protection_enabled": false,
        "advanced_ddos_enabled": false,
        "connection_rate_limit": 0,
        "syn_flood_threshold": 50,
        "max_tracked_ips": 4096,
        "max_blocked_ips": 1024,
        "state_ttl_secs": 300,
        "bloom_filter_scale": 1.0
    });

    let update_response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri("/l4/config")
                .header("content-type", "application/json")
                .body(Body::from(update_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_response.status(), StatusCode::OK);
    let update_body = to_bytes(update_response.into_body(), usize::MAX)
        .await
        .unwrap();
    let update_json: Value = serde_json::from_slice(&update_body).unwrap();
    assert_eq!(update_json["success"], Value::Bool(true));
    assert!(update_json["message"]
        .as_str()
        .unwrap_or_default()
        .contains("立即刷新"));

    let refreshed_stats = router
        .oneshot(
            Request::builder()
                .uri("/l4/stats")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refreshed_stats.status(), StatusCode::OK);
    let refreshed_body = to_bytes(refreshed_stats.into_body(), usize::MAX)
        .await
        .unwrap();
    let refreshed_json: Value = serde_json::from_slice(&refreshed_body).unwrap();
    assert_eq!(refreshed_json["enabled"], Value::Bool(false));
    assert!(refreshed_json["behavior"]["overview"]["bucket_count"].is_number());
}
