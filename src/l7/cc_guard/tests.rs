use super::counters::{cleanup_batch_for_size, cleanup_interval_for_size};
use super::*;
use crate::core::InspectionLayer;
use crate::protocol::HttpVersion;

fn request(uri: &str) -> UnifiedHttpRequest {
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), uri.to_string());
    request.set_client_ip("203.0.113.10".to_string());
    request.add_header("host".to_string(), "example.com".to_string());
    request.add_header("accept".to_string(), "text/html".to_string());
    request
}

fn unresolved_proxy_request(uri: &str) -> UnifiedHttpRequest {
    let mut request = request(uri);
    request.add_metadata("network.trusted_proxy_peer".to_string(), "true".to_string());
    request.add_metadata(
        "network.client_ip_unresolved".to_string(),
        "true".to_string(),
    );
    request.add_metadata(
        "network.identity_state".to_string(),
        "trusted_cdn_unresolved".to_string(),
    );
    request
}

fn spoofed_forward_header_request(uri: &str) -> UnifiedHttpRequest {
    let mut request = request(uri);
    request.add_metadata(
        "network.identity_state".to_string(),
        "spoofed_forward_header".to_string(),
    );
    request
}

#[tokio::test]
async fn issues_challenge_when_route_rate_crosses_threshold() {
    let config = CcDefenseConfig {
        route_challenge_threshold: 2,
        route_block_threshold: 20,
        host_challenge_threshold: 20,
        host_block_threshold: 40,
        ip_challenge_threshold: 20,
        ip_block_threshold: 40,
        ..CcDefenseConfig::default()
    };
    let guard = L7CcGuard::new(&config);

    let mut first = request("/search?q=1");
    assert!(guard.inspect_request(&mut first).await.is_none());

    let mut second = request("/search?q=2");
    let result = guard.inspect_request(&mut second).await;
    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.layer, InspectionLayer::L7);
    assert_eq!(result.action, crate::core::InspectionAction::Respond);
    assert_eq!(
        result
            .custom_response
            .as_ref()
            .expect("challenge response")
            .status_code,
        403
    );
}

#[tokio::test]
async fn page_subresources_are_not_challenged_aggressively() {
    let config = CcDefenseConfig {
        route_challenge_threshold: 2,
        route_block_threshold: 3,
        page_load_grace_secs: 5,
        ..CcDefenseConfig::default()
    };
    let guard = L7CcGuard::new(&config);

    let mut doc = request("/index.html");
    doc.add_header("sec-fetch-dest".to_string(), "document".to_string());
    assert!(guard.inspect_request(&mut doc).await.is_none());

    let mut img = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "GET".to_string(),
        "/assets/a.png".to_string(),
    );
    img.set_client_ip("203.0.113.10".to_string());
    img.add_header("host".to_string(), "example.com".to_string());
    img.add_header("sec-fetch-dest".to_string(), "image".to_string());
    img.add_header(
        "referer".to_string(),
        "https://example.com/index.html".to_string(),
    );

    assert!(guard.inspect_request(&mut img).await.is_none());
}

#[tokio::test]
async fn long_static_page_subresources_match_host_window() {
    let config = CcDefenseConfig {
        route_challenge_threshold: 2,
        route_block_threshold: 3,
        page_load_grace_secs: 5,
        ..CcDefenseConfig::default()
    };
    let guard = L7CcGuard::new(&config);

    let mut doc = request("/202604162080.html");
    doc.add_header("sec-fetch-dest".to_string(), "document".to_string());
    assert!(guard.inspect_request(&mut doc).await.is_none());

    let mut asset = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "GET".to_string(),
        "/wp-content/uploads/2026/04/rocky-9-e7b3bbe7bb9fe4b8ade5a682e4bd95e690ade5bbba-podman-e697a0e5ae88e68aa4e8bf9be7a88b-k3s-e99b86e7bea4efbc8ce5ae9ee78eb0e8beb9e7bc98.webp".to_string(),
    );
    asset.set_client_ip("203.0.113.10".to_string());
    asset.add_header("host".to_string(), "example.com".to_string());
    asset.add_header("sec-fetch-dest".to_string(), "image".to_string());
    asset.add_header(
        "referer".to_string(),
        "https://example.com/202604162080.html".to_string(),
    );

    assert!(guard.inspect_request(&mut asset).await.is_none());
    assert_eq!(
        asset
            .get_metadata("l7.cc.page_subresource")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn verified_browser_static_burst_does_not_persist_block() {
    let config = CcDefenseConfig {
        route_challenge_threshold: 2,
        route_block_threshold: 200,
        host_challenge_threshold: 2,
        host_block_threshold: 80,
        ip_challenge_threshold: 2,
        ip_block_threshold: 80,
        ..CcDefenseConfig::default()
    };
    let guard = L7CcGuard::new(&config);

    let mut first = request("/article");
    assert!(guard.inspect_request(&mut first).await.is_none());
    let mut second = request("/article");
    let challenge = guard
        .inspect_request(&mut second)
        .await
        .expect("challenge response");
    let cookie = challenge
        .custom_response
        .as_ref()
        .and_then(|response| {
            response
                .headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
                .map(|(_, value)| value.split(';').next().unwrap_or(value).to_string())
        })
        .expect("challenge should set cookie");

    for index in 0..120 {
        let mut asset = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            format!("/wp-content/uploads/2026/04/image-{index}.webp"),
        );
        asset.set_client_ip("203.0.113.10".to_string());
        asset.add_header("host".to_string(), "example.com".to_string());
        asset.add_header("sec-fetch-dest".to_string(), "image".to_string());
        asset.add_header("cookie".to_string(), cookie.clone());

        let result = guard.inspect_request(&mut asset).await;
        assert!(
            result
                .as_ref()
                .map(|result| !result.persist_blocked_ip)
                .unwrap_or(true),
            "verified static asset burst should not persist a local block at request {index}"
        );
        assert_eq!(
            asset
                .get_metadata("l7.cc.verified_static_asset")
                .map(String::as_str),
            Some("true")
        );
    }
}

#[tokio::test]
async fn api_requests_accumulate_weight_faster_than_documents() {
    let config = CcDefenseConfig {
        route_challenge_threshold: 3,
        route_block_threshold: 20,
        host_challenge_threshold: 20,
        host_block_threshold: 40,
        ip_challenge_threshold: 20,
        ip_block_threshold: 40,
        ..CcDefenseConfig::default()
    };
    let guard = L7CcGuard::new(&config);

    let mut first = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "POST".to_string(),
        "/api/search".to_string(),
    );
    first.set_client_ip("203.0.113.10".to_string());
    first.add_header("host".to_string(), "example.com".to_string());
    first.add_header("accept".to_string(), "application/json".to_string());
    assert!(guard.inspect_request(&mut first).await.is_none());
    assert_eq!(
        first
            .get_metadata("l7.cc.weight_percent")
            .map(String::as_str),
        Some("140")
    );

    let mut second = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "POST".to_string(),
        "/api/search".to_string(),
    );
    second.set_client_ip("203.0.113.10".to_string());
    second.add_header("host".to_string(), "example.com".to_string());
    second.add_header("accept".to_string(), "application/json".to_string());
    let result = guard.inspect_request(&mut second).await;
    assert!(result.is_some(), "api-like traffic should challenge sooner");
    assert_eq!(
        second
            .get_metadata("l7.cc.request_kind")
            .map(String::as_str),
        Some("api")
    );
    assert_eq!(
        second.get_metadata("l7.cc.action").map(String::as_str),
        Some("api_friction")
    );
    let response = result
        .and_then(|item| item.custom_response)
        .expect("api friction response");
    assert_eq!(response.status_code, 429);
    assert!(response
        .headers
        .iter()
        .any(|(key, value)| { key == "x-rust-waf-cc-action" && value == "api-friction" }));
}

#[tokio::test]
async fn distributed_api_requests_trigger_global_hot_path_pressure() {
    let config = CcDefenseConfig {
        route_challenge_threshold: 8,
        route_block_threshold: 16,
        host_challenge_threshold: 100,
        host_block_threshold: 200,
        ip_challenge_threshold: 100,
        ip_block_threshold: 200,
        hot_path_challenge_threshold: 500,
        hot_path_block_threshold: 1_000,
        ..CcDefenseConfig::default()
    };
    let guard = L7CcGuard::new(&config);

    for idx in 0..3 {
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "POST".to_string(),
            "/api/checkout".to_string(),
        );
        request.set_client_ip(format!("203.0.113.{}", idx + 10));
        request.add_header("host".to_string(), "example.com".to_string());
        request.add_header("accept".to_string(), "application/json".to_string());
        assert!(guard.inspect_request(&mut request).await.is_none());
        assert_eq!(
            request
                .get_metadata("l7.cc.hot_path_clients")
                .map(String::as_str),
            Some(match idx {
                0 => "1",
                1 => "2",
                _ => "3",
            })
        );
    }

    let mut fourth = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "POST".to_string(),
        "/api/checkout".to_string(),
    );
    fourth.set_client_ip("203.0.113.20".to_string());
    fourth.add_header("host".to_string(), "example.com".to_string());
    fourth.add_header("accept".to_string(), "application/json".to_string());
    let result = guard.inspect_request(&mut fourth).await;
    assert!(
        result.is_some(),
        "distributed pressure should trigger challenge"
    );
    assert_eq!(
        fourth
            .get_metadata("l7.cc.hot_path_clients")
            .map(String::as_str),
        Some("4")
    );
}

#[tokio::test]
async fn hard_multiplier_configuration_can_force_block_for_subresources() {
    let config = CcDefenseConfig {
        route_challenge_threshold: 100,
        route_block_threshold: 2,
        hard_route_block_multiplier: 1,
        page_load_grace_secs: 5,
        ..CcDefenseConfig::default()
    };
    let guard = L7CcGuard::new(&config);

    let mut doc = request("/index.html");
    doc.add_header("sec-fetch-dest".to_string(), "document".to_string());
    assert!(guard.inspect_request(&mut doc).await.is_none());

    let mut first_img = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "GET".to_string(),
        "/assets/a.png".to_string(),
    );
    first_img.set_client_ip("203.0.113.10".to_string());
    first_img.add_header("host".to_string(), "example.com".to_string());
    first_img.add_header(
        "referer".to_string(),
        "https://example.com/index.html".to_string(),
    );
    assert!(guard.inspect_request(&mut first_img).await.is_none());

    let mut second_img = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "GET".to_string(),
        "/assets/a.png".to_string(),
    );
    second_img.set_client_ip("203.0.113.10".to_string());
    second_img.add_header("host".to_string(), "example.com".to_string());
    second_img.add_header(
        "referer".to_string(),
        "https://example.com/index.html".to_string(),
    );
    let result = guard.inspect_request(&mut second_img).await;
    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.action, crate::core::InspectionAction::Drop);
    assert!(result.persist_blocked_ip);
    assert_eq!(
        second_img
            .get_metadata("l7.enforcement")
            .map(String::as_str),
        Some("drop")
    );
}

#[tokio::test]
async fn unresolved_proxy_identity_can_be_challenged_without_direct_block() {
    let config = CcDefenseConfig {
        route_challenge_threshold: 2,
        route_block_threshold: 2,
        host_challenge_threshold: 2,
        host_block_threshold: 2,
        ip_challenge_threshold: 2,
        ip_block_threshold: 2,
        delay_threshold_percent: 100,
        delay_ms: 1,
        ..CcDefenseConfig::default()
    };
    let guard = L7CcGuard::new(&config);

    let mut first = unresolved_proxy_request("/search?q=1");
    let first_result = guard.inspect_request(&mut first).await;
    assert!(first_result.is_none());

    let mut second = unresolved_proxy_request("/search?q=2");
    let second_result = guard.inspect_request(&mut second).await;
    assert!(second_result.is_some());
    let second_result = second_result.unwrap();
    assert_eq!(
        second.get_metadata("l7.cc.action").map(String::as_str),
        Some("challenge")
    );
    assert_eq!(second_result.action, crate::core::InspectionAction::Respond);
    assert_eq!(
        second
            .get_metadata("l7.cc.client_identity_unresolved")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn spoofed_forward_header_requests_are_blocked_immediately() {
    let guard = L7CcGuard::new(&CcDefenseConfig::default());
    let mut request = spoofed_forward_header_request("/search?q=1");

    let result = guard.inspect_request(&mut request).await;

    assert!(result.is_some());
    let result = result.unwrap();
    assert_eq!(result.action, crate::core::InspectionAction::Drop);
    assert_eq!(
        request.get_metadata("l7.cc.action").map(String::as_str),
        Some("block")
    );
    assert_eq!(
        request.get_metadata("l7.enforcement").map(String::as_str),
        Some("drop")
    );
    assert!(result.reason.contains("spoofed forwarded header"));
}

#[tokio::test]
async fn updating_config_preserves_existing_request_history() {
    let mut config = CcDefenseConfig {
        route_challenge_threshold: 3,
        route_block_threshold: 20,
        host_challenge_threshold: 20,
        host_block_threshold: 40,
        ip_challenge_threshold: 20,
        ip_block_threshold: 40,
        ..CcDefenseConfig::default()
    };
    let guard = L7CcGuard::new(&config);

    let mut first = request("/search?q=1");
    assert!(guard.inspect_request(&mut first).await.is_none());

    let mut second = request("/search?q=2");
    assert!(guard.inspect_request(&mut second).await.is_none());

    config.route_challenge_threshold = 2;
    guard.update_config(&config);

    let mut third = request("/search?q=3");
    let result = guard.inspect_request(&mut third).await;
    assert!(
        result.is_some(),
        "existing counters should survive config updates"
    );
    assert_eq!(
        result.unwrap().action,
        crate::core::InspectionAction::Respond
    );
}

#[test]
fn validates_signed_challenge_cookie() {
    let config = CcDefenseConfig::default();
    let guard = L7CcGuard::new(&config);
    let mut request = request("/");
    let expires_at = unix_timestamp() + 60;
    let nonce = "abc123";
    let signature = sign_challenge(
        &guard.secret,
        "203.0.113.10".parse().unwrap(),
        "example.com",
        expires_at,
        nonce,
    );
    request.add_header(
        "cookie".to_string(),
        format!(
            "{}={expires_at}:{nonce}:{signature}",
            guard.config().challenge_cookie_name
        ),
    );

    let config = guard.config();
    assert!(guard.has_valid_challenge_cookie(
        &request,
        "203.0.113.10".parse().unwrap(),
        "example.com",
        &config,
    ));
}

#[test]
fn browser_fingerprint_report_requires_valid_challenge_cookie() {
    let config = CcDefenseConfig::default();
    let guard = L7CcGuard::new(&config);
    let client_ip = "203.0.113.10".parse().unwrap();
    let mut request = request("/");
    let expires_at = unix_timestamp() + 60;
    let nonce = "fpcheck";
    let signature = sign_challenge(&guard.secret, client_ip, "example.com", expires_at, nonce);
    request.add_header(
        "cookie".to_string(),
        format!(
            "{}={expires_at}:{nonce}:{signature}",
            guard.config().challenge_cookie_name
        ),
    );

    assert!(guard.allows_browser_fingerprint_report(&request, client_ip));
    request.headers.remove("cookie");
    assert!(!guard.allows_browser_fingerprint_report(&request, client_ip));
}

#[test]
fn cleanup_strategy_scales_with_map_size() {
    assert_eq!(cleanup_interval_for_size(128), 1_024);
    assert_eq!(cleanup_batch_for_size(128), 128);
    assert_eq!(cleanup_interval_for_size(4_096), 256);
    assert_eq!(cleanup_batch_for_size(4_096), 512);
    assert_eq!(cleanup_interval_for_size(16_384), 64);
    assert_eq!(cleanup_batch_for_size(16_384), 2_048);
}

#[test]
fn long_route_and_host_are_compacted() {
    let mut request = request("/");
    request.add_header("host".to_string(), "a".repeat(MAX_HOST_LEN + 48));
    let host = normalized_host(&request);
    assert!(host.len() <= MAX_HOST_LEN);
    assert!(host.starts_with("host:"));

    let route = normalized_route_path(&format!("/{}", "x".repeat(MAX_ROUTE_PATH_LEN + 48)));
    assert!(route.len() <= MAX_ROUTE_PATH_LEN);
    assert!(route.starts_with("route:"));
}

#[test]
fn bounded_dashmap_key_overflows_when_limit_is_hit() {
    let map = DashMap::new();
    map.insert("first".to_string(), SlidingWindowCounter::new());
    map.insert("second".to_string(), SlidingWindowCounter::new());

    let key = bounded_dashmap_key(&map, "third".to_string(), 2, "cc-test", 4);

    assert!(key.starts_with("__overflow__:cc-test:"));
}

#[tokio::test]
async fn interactive_same_origin_sessions_relax_host_and_ip_pressure() {
    let config = CcDefenseConfig {
        route_challenge_threshold: 8,
        route_block_threshold: 16,
        host_challenge_threshold: 6,
        host_block_threshold: 10,
        ip_challenge_threshold: 6,
        ip_block_threshold: 10,
        ..CcDefenseConfig::default()
    };
    let guard = L7CcGuard::new(&config);

    for index in 0..7 {
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            if index % 2 == 0 { "GET" } else { "POST" }.to_string(),
            format!("/console/route-{index}"),
        );
        request.set_client_ip("203.0.113.10".to_string());
        request.add_header("host".to_string(), "example.com".to_string());
        request.add_header("cookie".to_string(), "rwaf_fp=stablefp".to_string());
        request.add_header("sec-fetch-site".to_string(), "same-origin".to_string());
        request.add_header(
            "sec-fetch-mode".to_string(),
            if index % 2 == 0 { "navigate" } else { "cors" }.to_string(),
        );
        request.add_header(
            "referer".to_string(),
            "https://example.com/console/home".to_string(),
        );
        if index % 2 == 0 {
            request.add_header("accept".to_string(), "text/html".to_string());
            request.add_metadata(
                "l7.behavior.flags".to_string(),
                "broad_navigation_context".to_string(),
            );
            request.add_metadata("l7.behavior.score".to_string(), "0".to_string());
        } else {
            request.add_header("accept".to_string(), "application/json".to_string());
            request.add_header("x-requested-with".to_string(), "XMLHttpRequest".to_string());
            request.add_metadata(
                "l7.behavior.flags".to_string(),
                "broad_navigation_context".to_string(),
            );
            request.add_metadata("l7.behavior.score".to_string(), "0".to_string());
        }
        let result = guard.inspect_request(&mut request).await;
        assert!(
            result.is_none(),
            "interactive same-origin traffic should not trip host/ip pressure on iteration {index}"
        );
        assert_eq!(
            request
                .get_metadata("l7.cc.interactive_session")
                .map(String::as_str),
            Some("true")
        );
    }
}

#[tokio::test]
async fn delay_is_upgraded_to_challenge_under_runtime_pressure() {
    let config = CcDefenseConfig {
        route_challenge_threshold: 100,
        route_block_threshold: 200,
        host_challenge_threshold: 100,
        host_block_threshold: 200,
        ip_challenge_threshold: 100,
        ip_block_threshold: 200,
        delay_threshold_percent: 1,
        delay_ms: 150,
        ..CcDefenseConfig::default()
    };
    let guard = L7CcGuard::new(&config);
    let mut request = request("/hot");
    request.add_metadata(
        "runtime.pressure.drop_delay".to_string(),
        "true".to_string(),
    );

    let result = guard.inspect_request(&mut request).await;

    assert!(result.is_some());
    assert_eq!(
        request.get_metadata("l7.cc.action").map(String::as_str),
        Some("challenge")
    );
}
