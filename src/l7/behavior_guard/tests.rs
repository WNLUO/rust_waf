use super::*;
use crate::protocol::HttpVersion;

fn request(method: &str, uri: &str, accept: &str) -> UnifiedHttpRequest {
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, method.to_string(), uri.to_string());
    request.set_client_ip("203.0.113.10".to_string());
    request.add_header("host".to_string(), "example.com".to_string());
    request.add_header("accept".to_string(), accept.to_string());
    request.add_header("user-agent".to_string(), "MobileSafari".to_string());
    request
}

#[tokio::test]
async fn repeated_document_requests_trigger_behavior_response() {
    let guard = L7BehaviorGuard::new();
    let mut last = None;
    for _ in 0..6 {
        let mut request = request("GET", "/", "text/html");
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), "/".to_string());
        last = guard.inspect_request(&mut request).await;
    }
    assert!(last.is_some());
}

#[tokio::test]
async fn browser_document_navigation_refreshes_are_not_behavior_blocked() {
    let guard = L7BehaviorGuard::new();

    for index in 0..18 {
        let mut document = request("GET", "/", "text/html");
        document.add_header("sec-fetch-dest".to_string(), "document".to_string());
        document.add_header("sec-fetch-mode".to_string(), "navigate".to_string());
        document.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        document.add_metadata("l7.cc.route".to_string(), "/".to_string());

        let result = guard.inspect_request(&mut document).await;
        assert!(
            result.is_none(),
            "browser navigation refresh should not be behavior blocked at request {index}"
        );
        assert_eq!(
            document
                .get_metadata("l7.behavior.skipped")
                .map(String::as_str),
            Some("browser_document_navigation")
        );
    }
}

#[tokio::test]
async fn browser_document_navigation_skip_does_not_depend_on_cc_kind_metadata() {
    let guard = L7BehaviorGuard::new();

    for index in 0..18 {
        let mut document = request("GET", "/", "*/*");
        document.add_header("sec-fetch-dest".to_string(), "document".to_string());
        document.add_header("sec-fetch-mode".to_string(), "navigate".to_string());
        document.add_metadata("l7.cc.request_kind".to_string(), "other".to_string());
        document.add_metadata("l7.cc.route".to_string(), "/".to_string());

        let result = guard.inspect_request(&mut document).await;
        assert!(
            result.is_none(),
            "browser navigation signal should win over stale request kind at request {index}"
        );
        assert_eq!(
            document
                .get_metadata("l7.behavior.skipped")
                .map(String::as_str),
            Some("browser_document_navigation")
        );
    }
}

#[tokio::test]
async fn browser_like_document_loop_without_fetch_headers_is_not_persistently_blocked() {
    let guard = L7BehaviorGuard::new();
    let mut last = None;

    for _ in 0..18 {
        let mut document = request("GET", "/", "text/html,application/xhtml+xml");
        document.add_header(
            "user-agent".to_string(),
            "Mozilla/5.0 MobileSafari".to_string(),
        );
        document.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        document.add_metadata("l7.cc.route".to_string(), "/".to_string());
        last = guard.inspect_request(&mut document).await;
    }

    let result = last.expect("browser-like document loop should get a local response");
    assert!(!result.persist_blocked_ip);
}

#[tokio::test]
async fn scripted_document_loop_still_persistently_blocks() {
    let guard = L7BehaviorGuard::new();
    let mut last = None;

    for _ in 0..18 {
        let mut document = request("GET", "/", "*/*");
        document.add_header("user-agent".to_string(), "curl/8.0".to_string());
        document.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        document.add_metadata("l7.cc.route".to_string(), "/".to_string());
        last = guard.inspect_request(&mut document).await;
    }

    let result = last.expect("scripted document loop should be blocked");
    assert!(result.persist_blocked_ip);
}

#[tokio::test]
async fn browser_same_origin_async_loop_is_skipped_by_behavior_guard() {
    let guard = L7BehaviorGuard::new();

    for index in 0..18 {
        let mut api = request(
            "POST",
            "/admin/async/state",
            "application/json, text/javascript, */*; q=0.01",
        );
        api.add_header(
            "user-agent".to_string(),
            "Mozilla/5.0 AppleWebKit/537.36 Chrome/147.0 Safari/537.36".to_string(),
        );
        api.add_header("host".to_string(), "example.com".to_string());
        api.add_header("origin".to_string(), "https://example.com".to_string());
        api.add_header(
            "referer".to_string(),
            "https://example.com/admin/".to_string(),
        );
        api.add_header(
            "content-type".to_string(),
            "application/x-www-form-urlencoded; charset=UTF-8".to_string(),
        );
        api.add_metadata("l7.cc.request_kind".to_string(), "api".to_string());
        api.add_metadata("l7.cc.route".to_string(), "/admin/async/state".to_string());

        let result = guard.inspect_request(&mut api).await;
        assert!(
            result.is_none(),
            "same-origin browser async request should not be behavior challenged at request {index}"
        );
        assert_eq!(
            api.get_metadata("l7.behavior.skipped").map(String::as_str),
            Some("browser_same_origin_async")
        );
    }
}

#[tokio::test]
async fn scripted_api_loop_still_persistently_blocks() {
    let guard = L7BehaviorGuard::new();
    let mut last = None;

    for _ in 0..18 {
        let mut api = request("POST", "/api/feed", "application/json");
        api.add_header("user-agent".to_string(), "curl/8.0".to_string());
        api.add_metadata("l7.cc.request_kind".to_string(), "api".to_string());
        api.add_metadata("l7.cc.route".to_string(), "/api/feed".to_string());
        last = guard.inspect_request(&mut api).await;
    }

    let result = last.expect("scripted api loop should be blocked");
    assert!(result.persist_blocked_ip);
}

#[tokio::test]
async fn unresolved_trusted_proxy_document_loop_is_not_persistently_blocked() {
    let guard = L7BehaviorGuard::new();
    let mut last = None;

    for _ in 0..18 {
        let mut document = request("GET", "/", "*/*");
        document.add_metadata(
            "network.identity_state".to_string(),
            "trusted_cdn_unresolved".to_string(),
        );
        document.add_metadata(
            "network.client_ip_unresolved".to_string(),
            "true".to_string(),
        );
        document.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        document.add_metadata("l7.cc.route".to_string(), "/".to_string());
        last = guard.inspect_request(&mut document).await;
    }

    let result = last.expect("unresolved proxy document loop should get a local response");
    assert!(!result.persist_blocked_ip);
}

#[tokio::test]
async fn mixed_navigation_keeps_behavior_score_low() {
    let guard = L7BehaviorGuard::new();
    let mut doc = request("GET", "/", "text/html");
    doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
    doc.add_metadata("l7.cc.route".to_string(), "/".to_string());
    assert!(guard.inspect_request(&mut doc).await.is_none());

    let mut js = request("GET", "/app.js", "*/*");
    js.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
    js.add_metadata("l7.cc.route".to_string(), "/app.js".to_string());
    assert!(guard.inspect_request(&mut js).await.is_none());

    let mut api = request("GET", "/api/feed", "application/json");
    api.add_metadata("l7.cc.request_kind".to_string(), "api".to_string());
    api.add_metadata("l7.cc.route".to_string(), "/api/feed".to_string());
    assert!(guard.inspect_request(&mut api).await.is_none());
    assert!(
        api.get_metadata("l7.behavior.score")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_default()
            < CHALLENGE_SCORE
    );
}

#[tokio::test]
async fn repeated_document_refreshes_with_sparse_assets_trigger_challenge() {
    let guard = L7BehaviorGuard::new();
    let mut last = None;
    for index in 0..8 {
        let mut doc = request("GET", "/", "text/html");
        doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        doc.add_metadata("l7.cc.route".to_string(), "/".to_string());
        last = guard.inspect_request(&mut doc).await;

        if index % 2 == 0 {
            let mut favicon = request("GET", "/favicon.ico", "*/*");
            favicon.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
            favicon.add_metadata("l7.cc.route".to_string(), "/favicon.ico".to_string());
            let _ = guard.inspect_request(&mut favicon).await;
        }
    }

    assert!(last.is_some());
}

#[tokio::test]
async fn repeated_full_page_reloads_with_many_assets_do_not_persist_block() {
    let guard = L7BehaviorGuard::new();
    let mut last = None;

    for _cycle in 0..4 {
        let mut doc = request("GET", "/article.html", "text/html");
        doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        doc.add_metadata("l7.cc.route".to_string(), "/article.html".to_string());
        last = guard.inspect_request(&mut doc).await;

        for asset in 0..12 {
            let mut static_request = request("GET", &format!("/static/{asset}.js"), "*/*");
            static_request.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
            static_request.add_metadata("l7.cc.route".to_string(), format!("/static/{asset}.js"));
            let _ = guard.inspect_request(&mut static_request).await;
        }
    }

    assert!(
        last.as_ref()
            .map(|result| !result.persist_blocked_ip)
            .unwrap_or(true),
        "browser page reloads with asset waterfalls must not persistently block the visitor"
    );
}

#[tokio::test]
async fn normal_page_asset_waterfall_is_ignored_by_behavior_guard() {
    let guard = L7BehaviorGuard::new();

    for cycle in 0..2 {
        let mut doc = request("GET", "/", "text/html");
        doc.add_header("sec-fetch-dest".to_string(), "document".to_string());
        doc.add_header("sec-fetch-mode".to_string(), "navigate".to_string());
        doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        doc.add_metadata("l7.cc.route".to_string(), "/".to_string());
        let result = guard.inspect_request(&mut doc).await;
        assert!(
            result
                .as_ref()
                .map(|result| !result.persist_blocked_ip)
                .unwrap_or(true),
            "document request in a normal page load must not persistently block"
        );

        for asset in [
            "/wp-content/themes/CoreNext/static/js/home.min.js",
            "/wp-content/themes/CoreNext/static/js/global.min.js",
            "/wp-content/themes/CoreNext/static/img/icon/icp.svg",
            "/wp-content/themes/CoreNext/static/img/icon/police.svg",
            "/wp-content/themes/CoreNext/static/lib/element-ui/fonts/element-icons.woff",
            "/wp-content/themes/CoreNext/static/lib/strawberry/fonts/StrawberryIcon-Free.ttf?83lfek",
            "/wp-content/plugins/wp-opt/static/js/front.min.js",
            "/wp-content/uploads/2024/04/20240430084128505162.gif",
            "/wp-content/uploads/2024/05/20240501113833599823.webp",
            "/wp-content/uploads/2026/02/20260214160334660789.jpg",
        ] {
            let mut static_request = request("GET", asset, "*/*");
            static_request.add_header("sec-fetch-site".to_string(), "same-origin".to_string());
            static_request.add_header("referer".to_string(), "https://example.com/".to_string());
            static_request.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
            static_request.add_metadata(
                "l7.cc.route".to_string(),
                normalized_route_path(request_path(asset)),
            );

            assert!(
                guard.inspect_request(&mut static_request).await.is_none(),
                "static asset {asset} in normal page cycle {cycle} should not be challenged or blocked"
            );
            assert_eq!(
                static_request
                    .get_metadata("l7.behavior.skipped")
                    .map(String::as_str),
                Some("static_asset")
            );
        }
    }

    let mut final_doc = request("GET", "/", "text/html");
    final_doc.add_header("sec-fetch-dest".to_string(), "document".to_string());
    final_doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
    final_doc.add_metadata("l7.cc.route".to_string(), "/".to_string());

    let result = guard.inspect_request(&mut final_doc).await;
    assert!(
        result
            .as_ref()
            .map(|result| !result.persist_blocked_ip)
            .unwrap_or(true),
        "follow-up document after asset waterfall must not persistently block"
    );
    assert_ne!(
        final_doc
            .get_metadata("l7.behavior.action")
            .map(String::as_str),
        Some("block")
    );
}

#[tokio::test]
async fn distributed_document_burst_triggers_aggregate_behavior_response() {
    let guard = L7BehaviorGuard::new();
    let mut last = None;

    for index in 0..8 {
        let mut request = request("GET", "/", "text/html");
        request.set_client_ip(format!("203.0.113.{}", index + 1));
        request.add_header(
            "user-agent".to_string(),
            format!("DistributedTestBrowser/{index}"),
        );
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), "/".to_string());
        last = guard.inspect_request(&mut request).await;
    }

    assert!(last.is_some());
    let mut request = request("GET", "/", "text/html");
    request.set_client_ip("203.0.113.99".to_string());
    request.add_header(
        "user-agent".to_string(),
        "DistributedTestBrowser/final".to_string(),
    );
    request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
    request.add_metadata("l7.cc.route".to_string(), "/".to_string());
    let _ = guard.inspect_request(&mut request).await;

    assert!(request
        .get_metadata("l7.behavior.flags")
        .is_some_and(|flags| flags.contains("distributed_document")));
    assert!(request
        .get_metadata("l7.behavior.distinct_client_ips")
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|count| count >= 4));
}

#[tokio::test]
async fn route_burst_gate_blocks_scripted_multi_source_documents_within_seconds() {
    let guard = L7BehaviorGuard::new();
    let mut last = None;

    for index in 0..10 {
        let mut request = request("GET", "/", "*/*");
        request.set_client_ip(format!("203.0.113.{}", index + 1));
        request.add_header("user-agent".to_string(), "curl/8.0".to_string());
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), "/".to_string());
        last = guard.inspect_request(&mut request).await;
    }

    let result = last.expect("route burst gate should block scripted burst");
    assert_eq!(result.action, crate::core::InspectionAction::Drop);
    assert_eq!(
        result.persist_blocked_ip, false,
        "route burst gate should not persistently block rotating IPs"
    );
    let mut followup = request("GET", "/", "*/*");
    followup.set_client_ip("203.0.113.250".to_string());
    followup.add_header("user-agent".to_string(), "curl/8.0".to_string());
    followup.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
    followup.add_metadata("l7.cc.route".to_string(), "/".to_string());
    let result = guard
        .inspect_request(&mut followup)
        .await
        .expect("route burst gate should keep blocking during burst window");
    assert_eq!(result.action, crate::core::InspectionAction::Drop);
    assert_eq!(
        followup
            .get_metadata("l7.behavior.action")
            .map(String::as_str),
        Some("aggregate_block")
    );
    assert_eq!(
        followup
            .get_metadata("l7.behavior.aggregate_enforcement")
            .map(String::as_str),
        Some("route_burst")
    );
}

#[tokio::test]
async fn route_burst_gate_does_not_block_browser_like_broad_user_agents() {
    let guard = L7BehaviorGuard::new();

    for index in 0..10 {
        let mut request = request("GET", "/", "text/html");
        request.set_client_ip(format!("198.51.100.{}", index + 1));
        request.add_header(
            "user-agent".to_string(),
            format!("Mozilla/5.0 BrowserBurst/{index}"),
        );
        request.add_header("accept-language".to_string(), "zh-CN,zh;q=0.9".to_string());
        request.add_header("sec-fetch-dest".to_string(), "document".to_string());
        request.add_header("sec-fetch-mode".to_string(), "navigate".to_string());
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), "/".to_string());
        let result = guard.inspect_request(&mut request).await;
        assert!(
            request
                .get_metadata("l7.behavior.aggregate_enforcement")
                .map_or(true, |value| value != "route_burst"),
            "browser-like simultaneous visits should not trigger the route burst gate"
        );
        drop(result);
    }
}

#[tokio::test]
async fn distributed_document_burst_activates_aggregate_block_enforcement() {
    let guard = L7BehaviorGuard::new();

    for index in 0..12 {
        let mut request = request("GET", "/", "text/html");
        request.set_client_ip(format!("203.0.113.{}", index + 1));
        request.add_header(
            "user-agent".to_string(),
            format!("DistributedBlockBrowser/{index}"),
        );
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), "/".to_string());
        let _ = guard.inspect_request(&mut request).await;
    }

    let mut next = request("GET", "/", "text/html");
    next.set_client_ip("203.0.113.250".to_string());
    next.add_header(
        "user-agent".to_string(),
        "DistributedBlockBrowser/fresh".to_string(),
    );
    next.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
    next.add_metadata("l7.cc.route".to_string(), "/".to_string());

    let result = guard
        .inspect_request(&mut next)
        .await
        .expect("aggregate enforcement should block fresh source");

    assert_eq!(result.action, crate::core::InspectionAction::Drop);
    assert!(!result.persist_blocked_ip);
    assert_eq!(
        next.get_metadata("l7.behavior.aggregate_enforcement")
            .map(String::as_str),
        Some("active")
    );
    assert_eq!(
        next.get_metadata("l7.behavior.action").map(String::as_str),
        Some("aggregate_block")
    );
}

#[tokio::test]
async fn aggregate_enforcement_uses_normalized_host() {
    let guard = L7BehaviorGuard::new();

    for index in 0..12 {
        let mut request = request("GET", "/", "text/html");
        request.add_header("host".to_string(), "Example.COM:443".to_string());
        request.set_client_ip(format!("203.0.113.{}", index + 1));
        request.add_header(
            "user-agent".to_string(),
            format!("DistributedHostBrowser/{index}"),
        );
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), "/".to_string());
        let _ = guard.inspect_request(&mut request).await;
    }

    let mut next = request("GET", "/", "text/html");
    next.add_header("host".to_string(), "example.com".to_string());
    next.set_client_ip("203.0.113.250".to_string());
    next.add_header(
        "user-agent".to_string(),
        "DistributedHostBrowser/fresh".to_string(),
    );
    next.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
    next.add_metadata("l7.cc.route".to_string(), "/".to_string());

    let result = guard
        .inspect_request(&mut next)
        .await
        .expect("normalized host aggregate enforcement should apply");

    assert_eq!(result.action, crate::core::InspectionAction::Drop);
    assert_eq!(
        next.get_metadata("l7.behavior.action").map(String::as_str),
        Some("aggregate_block")
    );
}

#[tokio::test]
async fn single_source_identity_rotation_triggers_behavior_without_route_enforcement() {
    let guard = L7BehaviorGuard::new();
    let mut last = None;

    for index in 0..8 {
        let mut request = request("GET", "/", "text/html");
        request.set_client_ip("203.0.113.80".to_string());
        request.add_header("user-agent".to_string(), format!("RotatingClient/{index}"));
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), "/".to_string());
        last = guard.inspect_request(&mut request).await;
    }

    let result = last.expect("single-source rotating identities should be challenged");
    assert_eq!(result.action, crate::core::InspectionAction::Respond);

    let mut other_ip = request("GET", "/", "text/html");
    other_ip.set_client_ip("203.0.113.200".to_string());
    other_ip.add_header("user-agent".to_string(), "NormalBrowser".to_string());
    other_ip.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
    other_ip.add_metadata("l7.cc.route".to_string(), "/".to_string());

    let result = guard.inspect_request(&mut other_ip).await;
    assert!(
        !matches!(
            other_ip
                .get_metadata("l7.behavior.aggregate_enforcement")
                .map(String::as_str),
            Some("active")
        ),
        "single-source identity rotation must not enable route-wide enforcement"
    );
    assert!(
        result.is_none()
            || other_ip
                .get_metadata("l7.behavior.flags")
                .map_or(true, |flags| {
                    !flags.contains("single_source_identity_rotation")
                })
    );
}

#[tokio::test]
async fn distributed_document_probe_activates_aggregate_challenge_enforcement() {
    let guard = L7BehaviorGuard::new();

    for index in 0..8 {
        let mut request = request("GET", "/", "text/html");
        request.set_client_ip(format!("198.51.100.{}", index + 1));
        request.add_header(
            "user-agent".to_string(),
            format!("DistributedProbeBrowser/{index}"),
        );
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), "/".to_string());
        let _ = guard.inspect_request(&mut request).await;
    }

    let mut next = request("GET", "/", "text/html");
    next.set_client_ip("198.51.100.250".to_string());
    next.add_header(
        "user-agent".to_string(),
        "DistributedProbeBrowser/fresh".to_string(),
    );
    next.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
    next.add_metadata("l7.cc.route".to_string(), "/".to_string());

    let result = guard
        .inspect_request(&mut next)
        .await
        .expect("aggregate enforcement should challenge fresh source");

    assert_eq!(result.action, crate::core::InspectionAction::Respond);
    assert!(!result.persist_blocked_ip);
    assert!(matches!(
        next.get_metadata("l7.behavior.action").map(String::as_str),
        Some("challenge" | "aggregate_challenge")
    ));
}

#[tokio::test]
async fn distributed_broad_navigation_stays_below_aggregate_behavior_response() {
    let guard = L7BehaviorGuard::new();

    for index in 0..12 {
        let mut request = request("GET", &format!("/article-{index}.html"), "text/html");
        request.set_client_ip(format!("203.0.113.{}", index + 1));
        request.add_header(
            "user-agent".to_string(),
            format!("DistributedNormalBrowser/{index}"),
        );
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), format!("/article-{index}.html"));

        assert!(guard.inspect_request(&mut request).await.is_none());
    }
}

#[tokio::test]
async fn distributed_article_family_burst_triggers_behavior_response() {
    let guard = L7BehaviorGuard::new();
    let mut last = None;

    for index in 0..8 {
        let mut request = request(
            "GET",
            &format!("/20260214{:04}.html", 1900 + index),
            "text/html",
        );
        request.set_client_ip(format!("203.0.113.{}", index + 1));
        request.add_header("user-agent".to_string(), format!("ArticleProbe/{index}"));
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata(
            "l7.cc.route".to_string(),
            format!("/20260214{:04}.html", 1900 + index),
        );
        last = guard.inspect_request(&mut request).await;
    }

    assert!(last.is_some());
}

#[tokio::test]
async fn distributed_wordpress_plugin_family_burst_triggers_behavior_response() {
    let guard = L7BehaviorGuard::new();
    let mut last = None;

    for (index, plugin) in [
        "tabs-responsive",
        "woodly-core",
        "pods",
        "wc-spod",
        "multisafepay",
        "jc-importer",
        "block-slider",
        "mailchimp-forms-by-mailmunch",
    ]
    .iter()
    .enumerate()
    {
        let path = format!("/wp-content/plugins/{plugin}/readme.txt");
        let mut request = request("GET", &path, "text/html");
        request.set_client_ip(format!("203.0.113.{}", index + 1));
        request.add_header("user-agent".to_string(), format!("PluginProbe/{index}"));
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), path);
        last = guard.inspect_request(&mut request).await;
    }

    assert!(last.is_some());
}

#[tokio::test]
async fn crawler_well_known_routes_do_not_trigger_aggregate_behavior_response() {
    let guard = L7BehaviorGuard::new();

    for index in 0..12 {
        let path = if index % 2 == 0 {
            "/robots.txt"
        } else {
            "/sitemap.xml"
        };
        let mut request = request("GET", path, "text/plain");
        request.set_client_ip(format!("203.0.113.{}", index + 1));
        request.add_header("user-agent".to_string(), format!("Crawler/{index}"));
        request.add_metadata("l7.cc.request_kind".to_string(), "other".to_string());
        request.add_metadata("l7.cc.route".to_string(), path.to_string());

        assert!(guard.inspect_request(&mut request).await.is_none());
    }
}

#[tokio::test]
async fn broad_navigation_with_many_assets_stays_below_challenge() {
    let guard = L7BehaviorGuard::new();

    for page in 0..3 {
        let mut doc = request(
            "GET",
            "/wp-admin/edit-tags.php?taxonomy=category",
            "text/html",
        );
        doc.add_header("sec-fetch-dest".to_string(), "document".to_string());
        doc.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        doc.add_metadata(
            "l7.cc.route".to_string(),
            "/wp-admin/edit-tags.php".to_string(),
        );
        assert!(guard.inspect_request(&mut doc).await.is_none());

        for asset in 0..32 {
            let mut req = request("GET", &format!("/wp-admin/load-{page}-{asset}.css"), "*/*");
            req.add_header("sec-fetch-dest".to_string(), "style".to_string());
            req.add_metadata("l7.cc.request_kind".to_string(), "static".to_string());
            req.add_metadata(
                "l7.cc.route".to_string(),
                format!("/wp-admin/load-{page}-{asset}.css"),
            );
            assert!(guard.inspect_request(&mut req).await.is_none());
        }

        let mut api = request("POST", "/admin/async/state", "application/json");
        api.add_header(
            "content-type".to_string(),
            "application/json; charset=utf-8".to_string(),
        );
        api.add_header("x-requested-with".to_string(), "XMLHttpRequest".to_string());
        api.add_metadata("l7.cc.request_kind".to_string(), "api".to_string());
        api.add_metadata("l7.cc.route".to_string(), "/admin/async/state".to_string());
        assert!(guard.inspect_request(&mut api).await.is_none());
    }

    let mut summary = request("GET", "/wp-admin/tools.php", "text/html");
    summary.add_header("sec-fetch-dest".to_string(), "document".to_string());
    summary.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
    summary.add_metadata("l7.cc.route".to_string(), "/wp-admin/tools.php".to_string());
    let _ = guard.inspect_request(&mut summary).await;

    let score = summary
        .get_metadata("l7.behavior.score")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_default();
    assert!(score < CHALLENGE_SCORE, "unexpected score {score}");
}

#[tokio::test]
async fn repeated_challenges_escalate_to_block_and_persist() {
    let guard = L7BehaviorGuard::new();
    let mut actions = Vec::new();
    let mut persisted = Vec::new();

    for _ in 0..8 {
        let mut request = request("GET", "/", "text/html");
        request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
        request.add_metadata("l7.cc.route".to_string(), "/".to_string());
        let result = guard.inspect_request(&mut request).await;
        actions.push(
            request
                .get_metadata("l7.behavior.action")
                .cloned()
                .unwrap_or_default(),
        );
        persisted.push(result.map(|item| item.persist_blocked_ip).unwrap_or(false));
    }

    assert!(actions.iter().any(|action| action == "challenge"));
    assert!(actions.iter().any(|action| action == "block"));
    assert!(persisted.iter().any(|flag| *flag));
}

#[test]
fn snapshot_profiles_excludes_idle_identities() {
    let guard = L7BehaviorGuard::new();
    let stale_unix = unix_timestamp() - (ACTIVE_PROFILE_IDLE_SECS + 5);
    let stale_window = BehaviorWindow::new();
    {
        let mut samples = stale_window
            .samples
            .lock()
            .expect("behavior window lock poisoned");
        samples.push_back(RequestSample {
            route: "/stale".to_string(),
            kind: RequestKind::Document,
            client_ip: Some("203.0.113.10".to_string()),
            user_agent: None,
            header_signature: None,
            at: Instant::now(),
        });
    }
    stale_window
        .last_seen_unix
        .store(stale_unix, Ordering::Relaxed);
    guard.buckets.insert("fp:stale".to_string(), stale_window);

    let fresh_window = BehaviorWindow::new();
    {
        let mut samples = fresh_window
            .samples
            .lock()
            .expect("behavior window lock poisoned");
        samples.push_back(RequestSample {
            route: "/fresh".to_string(),
            kind: RequestKind::Document,
            client_ip: Some("203.0.113.11".to_string()),
            user_agent: None,
            header_signature: None,
            at: Instant::now(),
        });
    }
    guard.buckets.insert("fp:fresh".to_string(), fresh_window);

    let profiles = guard.snapshot_profiles(16);
    assert!(profiles
        .iter()
        .any(|profile| profile.identity == "fp:fresh"));
    assert!(!profiles
        .iter()
        .any(|profile| profile.identity == "fp:stale"));
}

#[test]
fn request_identity_is_compacted_for_long_values() {
    let mut req = request("GET", "/", "text/html");
    req.add_header("x-browser-fingerprint-id".to_string(), "x".repeat(512));

    let identity = request_identity(&req).expect("identity");

    assert!(identity.len() <= MAX_BEHAVIOR_KEY_LEN);
    assert!(identity.starts_with("identity:"));
}

#[test]
fn bounded_dashmap_key_overflows_when_limit_is_hit() {
    let map = DashMap::new();
    map.insert("first".to_string(), BehaviorWindow::new());
    map.insert("second".to_string(), BehaviorWindow::new());

    let key = bounded_dashmap_key(&map, "third".to_string(), 2, "behavior-test", 4);

    assert!(key.starts_with("__overflow__:behavior-test:"));
}

#[test]
fn cc_other_root_request_is_treated_as_document_behavior() {
    let mut req = request("GET", "/", "*/*");
    req.add_metadata("l7.cc.request_kind".to_string(), "other".to_string());

    assert_eq!(request_kind(&req), RequestKind::Document);
}

#[tokio::test]
async fn delay_is_upgraded_to_challenge_under_runtime_pressure() {
    let guard = L7BehaviorGuard::new();
    let mut request = request("GET", "/", "text/html");
    request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
    request.add_metadata("l7.cc.route".to_string(), "/".to_string());
    request.add_metadata("ai.behavior.force_watch".to_string(), "true".to_string());
    request.add_metadata(
        "runtime.pressure.drop_delay".to_string(),
        "true".to_string(),
    );

    let result = guard.inspect_request(&mut request).await;

    assert!(result.is_some());
    assert_eq!(
        request
            .get_metadata("l7.behavior.action")
            .map(String::as_str),
        Some("challenge")
    );
}

#[tokio::test]
async fn tighten_stage_is_recorded_on_behavior_challenge() {
    let guard = L7BehaviorGuard::new();
    let mut request = request("GET", "/", "text/html");
    request.add_metadata("l7.cc.request_kind".to_string(), "document".to_string());
    request.add_metadata("l7.cc.route".to_string(), "/".to_string());
    request.add_metadata("ai.behavior.force_watch".to_string(), "true".to_string());
    request.add_metadata("runtime.defense.stage".to_string(), "challenge".to_string());

    let result = guard.inspect_request(&mut request).await;

    assert!(result.is_some());
    assert_eq!(
        request
            .get_metadata("l7.behavior.runtime_stage")
            .map(String::as_str),
        Some("challenge")
    );
    assert_eq!(
        request
            .get_metadata("l7.behavior.action")
            .map(String::as_str),
        Some("challenge")
    );
}
