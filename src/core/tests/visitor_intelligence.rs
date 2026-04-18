use super::*;

#[tokio::test]
async fn test_visitor_intelligence_trusts_verified_browser_session() {
    let context = WafContext::new(Config {
        sqlite_enabled: false,
        ..Config::default()
    })
    .await
    .unwrap();

    for uri in [
        "/",
        "/assets/app.css",
        "/assets/app.js",
        "/assets/logo.png",
        "/about",
        "/assets/site.woff2",
    ] {
        let mut request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http1_1,
            "GET".to_string(),
            uri.to_string(),
        );
        request.set_client_ip("203.0.113.210".to_string());
        request.add_header("host".to_string(), "example.test".to_string());
        request.add_header(
            "user-agent".to_string(),
            "Mozilla/5.0 visitor intelligence test".to_string(),
        );
        request.add_header("referer".to_string(), "https://example.test/".to_string());
        request.add_header("cookie".to_string(), "rwaf_fp=verified-browser".to_string());
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_ai_route_result(
            &request,
            AiRouteResultObservation {
                status_code: 200,
                latency_ms: Some(18),
                upstream_error: false,
                local_response: false,
                blocked: false,
            },
        );
    }

    let snapshot = context.visitor_intelligence_snapshot(10);
    let profile = snapshot
        .profiles
        .iter()
        .find(|item| item.identity_key == "fp:verified-browser")
        .expect("verified browser visitor should be tracked");
    assert_eq!(profile.state, "trusted_session");
    assert!(profile.human_confidence >= 75);
    assert!(snapshot
        .recommendations
        .iter()
        .any(|item| item.action == "mark_trusted_temporarily"));
}

#[tokio::test]
async fn test_visitor_intelligence_triggers_ai_after_suspicious_volume() {
    let context = WafContext::new(Config {
        sqlite_enabled: false,
        ..Config::default()
    })
    .await
    .unwrap();

    for _ in 0..8 {
        let mut request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http1_1,
            "GET".to_string(),
            "/wp-login.php".to_string(),
        );
        request.set_client_ip("203.0.113.211".to_string());
        request.add_header("host".to_string(), "example.test".to_string());
        request.add_header("user-agent".to_string(), "curl/8.0".to_string());
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_ai_route_result(
            &request,
            AiRouteResultObservation {
                status_code: 404,
                latency_ms: Some(12),
                upstream_error: false,
                local_response: false,
                blocked: false,
            },
        );
    }

    let snapshot = context.visitor_intelligence_snapshot(10);
    let profile = snapshot
        .profiles
        .iter()
        .find(|item| item.client_ip == "203.0.113.211")
        .expect("suspicious visitor should be tracked");
    assert_eq!(profile.state, "suspected_probe");
    assert_eq!(profile.tracking_priority, "high");
    assert!(snapshot
        .recommendations
        .iter()
        .any(|item| item.action == "increase_challenge"));

    let trigger = context.consume_ai_auto_defense_trigger(unix_timestamp());
    assert!(trigger
        .as_deref()
        .is_some_and(|reason| reason.starts_with("visitor_intelligence:increase_challenge")));
}

#[tokio::test]
async fn test_visitor_intelligence_uses_ai_route_profile_business_semantics() {
    let db_path = unique_test_db_path("visitor_ai_route_semantics");
    let context = WafContext::new(Config {
        sqlite_enabled: true,
        sqlite_path: db_path,
        sqlite_auto_migrate: true,
        ..Config::default()
    })
    .await
    .unwrap();
    context
        .sqlite_store
        .as_ref()
        .unwrap()
        .upsert_ai_route_profile(&crate::storage::AiRouteProfileUpsert {
            site_id: "site-a".to_string(),
            route_pattern: "/secure".to_string(),
            match_mode: "prefix".to_string(),
            route_type: "admin".to_string(),
            sensitivity: "high".to_string(),
            auth_required: "true".to_string(),
            normal_traffic_pattern: "authenticated users only".to_string(),
            recommended_actions: vec!["increase_challenge".to_string()],
            avoid_actions: vec!["temp_block_ip".to_string()],
            evidence_json: "{}".to_string(),
            confidence: 91,
            source: "ai_observed".to_string(),
            status: "active".to_string(),
            rationale: "AI labeled protected admin area".to_string(),
            last_observed_at: Some(unix_timestamp()),
            reviewed_at: Some(unix_timestamp()),
        })
        .await
        .unwrap();
    context.refresh_ai_route_profiles().await.unwrap();

    for status_code in [403, 403, 200] {
        let mut request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http1_1,
            "GET".to_string(),
            "/secure/panel".to_string(),
        );
        request.set_client_ip("203.0.113.212".to_string());
        request.add_header("host".to_string(), "example.test".to_string());
        request.add_header("user-agent".to_string(), "Mozilla/5.0".to_string());
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_ai_route_result(
            &request,
            AiRouteResultObservation {
                status_code,
                latency_ms: Some(22),
                upstream_error: false,
                local_response: false,
                blocked: false,
            },
        );
    }

    let snapshot = context.visitor_intelligence_snapshot(10);
    let profile = snapshot
        .profiles
        .iter()
        .find(|item| item.client_ip == "203.0.113.212")
        .expect("visitor should be tracked");
    assert_eq!(profile.business_route_types.get("admin"), Some(&3));
    assert_eq!(profile.auth_required_route_count, 3);
    assert_eq!(profile.auth_rejected_count, 2);
    assert_eq!(profile.auth_success_count, 1);
}

#[tokio::test]
async fn test_visitor_intelligence_records_challenge_js_telemetry() {
    let context = WafContext::new(Config {
        sqlite_enabled: false,
        ..Config::default()
    })
    .await
    .unwrap();
    let mut request = crate::protocol::UnifiedHttpRequest::new(
        crate::protocol::HttpVersion::Http1_1,
        "POST".to_string(),
        "/.well-known/waf/browser-fingerprint-report".to_string(),
    );
    request.set_client_ip("203.0.113.213".to_string());
    request.add_header("user-agent".to_string(), "Mozilla/5.0".to_string());
    request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
    let payload = serde_json::json!({
        "fingerprintId": "challenge-js-browser",
        "challenge": {
            "rendered": true,
            "js": true,
            "waitMs": 2800
        }
    });

    context.note_visitor_fingerprint_report(&request, "challenge-js-browser", Some(&payload));

    let snapshot = context.visitor_intelligence_snapshot(10);
    let profile = snapshot
        .profiles
        .iter()
        .find(|item| item.identity_key == "fp:challenge-js-browser")
        .expect("challenge js visitor should be tracked");
    assert_eq!(profile.challenge_page_report_count, 1);
    assert_eq!(profile.challenge_js_report_count, 1);
    assert!(profile
        .flags
        .iter()
        .any(|flag| flag == "challenge_js_report_seen"));
}
