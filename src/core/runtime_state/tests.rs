use super::*;
use crate::core::InspectionLayer;
use crate::protocol::{HttpVersion, UnifiedHttpRequest};

#[tokio::test]
async fn route_defense_tightens_only_the_hot_route() {
    let config = crate::config::Config {
        sqlite_enabled: false,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let result = InspectionResult::drop(InspectionLayer::L7, "route pressure");

    for _ in 0..2 {
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/api/login?from=test".to_string(),
        );
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_site_defense_signal(&request, &result);
    }

    let mut hot = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "GET".to_string(),
        "/api/login".to_string(),
    );
    hot.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
    hot.add_metadata("runtime.defense.depth".to_string(), "balanced".to_string());
    context.annotate_site_runtime_budget(&mut hot);

    assert_eq!(
        hot.get_metadata("runtime.route.defense_depth")
            .map(String::as_str),
        Some("lean")
    );
    assert_eq!(
        hot.get_metadata("ai.cc.route_threshold_scale_percent")
            .map(String::as_str),
        Some("70")
    );
    assert_eq!(
        hot.get_metadata("ai.cc.host_threshold_scale_percent")
            .map(String::as_str),
        Some("85")
    );

    let mut cold = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "GET".to_string(),
        "/api/profile".to_string(),
    );
    cold.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
    cold.add_metadata("runtime.defense.depth".to_string(), "balanced".to_string());
    context.annotate_site_runtime_budget(&mut cold);

    assert!(cold.get_metadata("runtime.route.defense_depth").is_none());
    assert!(cold
        .get_metadata("ai.cc.route_threshold_scale_percent")
        .is_none());
}

#[tokio::test]
async fn site_defense_tightens_all_routes_without_cross_site_leakage() {
    let config = crate::config::Config {
        sqlite_enabled: false,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let result = InspectionResult::drop(InspectionLayer::L7, "site pressure");

    for _ in 0..4 {
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "POST".to_string(),
            "/api/login".to_string(),
        );
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_site_defense_signal(&request, &result);
    }

    let mut same_site_cold_route = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "GET".to_string(),
        "/products".to_string(),
    );
    same_site_cold_route.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
    same_site_cold_route.add_metadata("runtime.defense.depth".to_string(), "balanced".to_string());
    context.annotate_site_runtime_budget(&mut same_site_cold_route);

    assert_eq!(
        same_site_cold_route
            .get_metadata("runtime.site.defense_depth")
            .map(String::as_str),
        Some("lean")
    );
    assert!(same_site_cold_route
        .get_metadata("runtime.route.defense_depth")
        .is_none());

    let mut other_site = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "GET".to_string(),
        "/products".to_string(),
    );
    other_site.add_metadata("gateway.site_id".to_string(), "site-b".to_string());
    other_site.add_metadata("runtime.defense.depth".to_string(), "balanced".to_string());
    context.annotate_site_runtime_budget(&mut other_site);

    assert!(other_site
        .get_metadata("runtime.site.defense_depth")
        .is_none());
}

#[tokio::test]
async fn site_survival_budget_enables_runtime_event_aggregation_metadata() {
    let config = crate::config::Config {
        sqlite_enabled: false,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let result = InspectionResult::drop(InspectionLayer::L7, "site pressure");

    for _ in 0..12 {
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "POST".to_string(),
            "/api/login".to_string(),
        );
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_site_defense_signal(&request, &result);
    }

    let mut request = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "GET".to_string(),
        "/checkout".to_string(),
    );
    request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
    request.add_metadata("runtime.defense.depth".to_string(), "balanced".to_string());
    request.add_metadata(
        "runtime.pressure.storage_queue_percent".to_string(),
        "95".to_string(),
    );
    context.annotate_site_runtime_budget(&mut request);

    assert_eq!(
        request
            .get_metadata("runtime.site.defense_depth")
            .map(String::as_str),
        Some("survival")
    );
    assert_eq!(
        request
            .get_metadata("runtime.aggregate_events")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        request
            .get_metadata("runtime.prefer_drop")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        request
            .get_metadata("runtime.budget.behavior_sample_stride")
            .map(String::as_str),
        Some("18446744073709551615")
    );
}

#[test]
fn protocol_stream_budgets_shrink_under_runtime_depth() {
    assert_eq!(protocol_stream_budget(128, "survival", 100), 8);
    assert_eq!(protocol_stream_budget(128, "lean", 100), 24);
    assert_eq!(protocol_stream_budget(128, "balanced", 100), 64);
    assert_eq!(protocol_stream_budget(4, "survival", 100), 4);
    assert_eq!(protocol_stream_budget(128, "full", 100), 128);
}

#[test]
fn protocol_stream_budgets_scale_with_server_mode() {
    assert_eq!(protocol_stream_budget(128, "balanced", 120), 76);
    assert_eq!(protocol_stream_budget(128, "balanced", 85), 54);
    assert_eq!(protocol_stream_budget(128, "full", 120), 128);
}

#[tokio::test]
async fn local_defense_recommendations_preview_hot_routes() {
    let config = crate::config::Config {
        sqlite_enabled: false,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let result = InspectionResult::drop(InspectionLayer::L7, "route pressure");

    for _ in 0..5 {
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "POST".to_string(),
            "/api/login".to_string(),
        );
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_site_defense_signal(&request, &result);
    }

    let recommendations = context.local_defense_recommendations(10);

    assert_eq!(recommendations.len(), 1);
    let recommendation = &recommendations[0];
    assert_eq!(recommendation.site_id, "site-a");
    assert_eq!(recommendation.route, "/api/login");
    assert_eq!(recommendation.defense_depth, "survival");
    assert_eq!(recommendation.action, "tighten_route_cc");
    assert_eq!(recommendation.suggested_value, "45");
    assert_eq!(recommendation.ttl_secs, 900);
    assert!(recommendation.confidence >= 90);
}

#[tokio::test]
async fn ai_defense_trigger_waits_for_enough_route_signals() {
    let config = crate::config::Config {
        sqlite_enabled: false,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();
    let result = InspectionResult::drop(InspectionLayer::L7, "route pressure");

    let mut request = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "POST".to_string(),
        "/api/login".to_string(),
    );
    request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
    context.note_site_defense_signal(&request, &result);

    assert!(context
        .consume_ai_auto_defense_trigger(unix_timestamp())
        .is_none());

    context.note_site_defense_signal(&request, &result);

    assert!(context
        .consume_ai_auto_defense_trigger(unix_timestamp())
        .as_deref()
        .is_some_and(|reason| reason.starts_with("route_pressure:site-a:/api/login")));
}

#[tokio::test]
async fn site_runtime_budget_marks_best_effort_site_for_shedding_in_survival() {
    let config = crate::config::Config {
        sqlite_enabled: false,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();

    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
    request.add_metadata(
        "gateway.site_priority".to_string(),
        "best_effort".to_string(),
    );
    request.add_metadata(
        "gateway.site_overload_policy".to_string(),
        "sacrificial".to_string(),
    );
    request.add_metadata("gateway.site_reserved_rps".to_string(), "1".to_string());
    request.add_metadata("runtime.defense.depth".to_string(), "survival".to_string());
    request.add_metadata("runtime.capacity.class".to_string(), "small".to_string());
    request.add_metadata(
        "runtime.pressure.storage_queue_percent".to_string(),
        "90".to_string(),
    );
    request.add_metadata(
        "runtime.server.mode_scale_percent".to_string(),
        "85".to_string(),
    );

    context.annotate_site_runtime_budget(&mut request);

    assert_eq!(
        request
            .get_metadata("runtime.site.action")
            .map(String::as_str),
        Some("shed")
    );
    assert_eq!(
        request
            .get_metadata("runtime.site.proxy_mode")
            .map(String::as_str),
        Some("shed")
    );
}

#[tokio::test]
async fn site_runtime_budget_challenges_critical_site_when_rps_exceeded() {
    let config = crate::config::Config {
        sqlite_enabled: false,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();

    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
    request.add_metadata("gateway.site_priority".to_string(), "critical".to_string());
    request.add_metadata(
        "gateway.site_overload_policy".to_string(),
        "challenge_first".to_string(),
    );
    request.add_metadata("gateway.site_reserved_rps".to_string(), "1".to_string());
    request.add_metadata("runtime.defense.depth".to_string(), "lean".to_string());
    request.add_metadata("runtime.capacity.class".to_string(), "tiny".to_string());
    request.add_metadata(
        "runtime.pressure.storage_queue_percent".to_string(),
        "80".to_string(),
    );

    for _ in 0..800 {
        context.annotate_site_runtime_budget(&mut request);
    }

    assert_eq!(
        request
            .get_metadata("runtime.site.action")
            .map(String::as_str),
        Some("challenge")
    );
    assert_eq!(
        request
            .get_metadata("runtime.site.over_rps_budget")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn server_mode_scales_site_rps_budget() {
    let config = crate::config::Config {
        sqlite_enabled: false,
        ..crate::config::Config::default()
    };
    let context = WafContext::new(config).await.unwrap();

    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
    request.add_metadata("gateway.site_priority".to_string(), "critical".to_string());
    request.add_metadata("gateway.site_reserved_rps".to_string(), "100".to_string());
    request.add_metadata("runtime.defense.depth".to_string(), "balanced".to_string());
    request.add_metadata(
        "runtime.server.mode_scale_percent".to_string(),
        "85".to_string(),
    );

    context.annotate_site_runtime_budget(&mut request);

    assert_eq!(
        request
            .get_metadata("runtime.site.effective_rps_limit")
            .map(String::as_str),
        Some("76")
    );
}
