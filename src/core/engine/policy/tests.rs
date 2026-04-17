use super::*;

#[test]
fn rewrite_host_template_expands_http_host() {
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
    request.add_header("host".to_string(), "wnluo.com:660".to_string());
    request.add_metadata("listener_port".to_string(), "660".to_string());
    request.add_metadata("scheme".to_string(), "https".to_string());

    let rendered = expand_request_template("$http_host", &request);
    assert_eq!(rendered, "wnluo.com:660");
}

#[test]
fn rewrite_host_template_expands_host_without_port() {
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.add_header("host".to_string(), "wnluo.com:660".to_string());

    let rendered = expand_request_template("$host", &request);
    assert_eq!(rendered, "wnluo.com");
}

#[test]
fn default_gateway_rewrite_host_value_uses_http_host_template() {
    let config = crate::config::Config::default();

    assert!(config.gateway_config.rewrite_host_enabled);
    assert_eq!(config.gateway_config.rewrite_host_value, "$http_host");
}

#[tokio::test]
async fn apply_response_policies_replaces_existing_hsts_header() {
    let mut config = crate::config::Config::default();
    config.gateway_config.enable_hsts = true;
    let context = WafContext::new(config).await.unwrap();
    let mut response = vec![
        (
            "strict-transport-security".to_string(),
            "max-age=123".to_string(),
        ),
        ("content-type".to_string(), "text/plain".to_string()),
    ];

    apply_response_policies(&context, &mut response, 200);

    let hsts: Vec<_> = response
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("strict-transport-security"))
        .collect();
    assert_eq!(hsts.len(), 1);
    assert_eq!(hsts[0].1, "max-age=31536000; includeSubDomains");
}

#[tokio::test]
async fn l7_bloom_filter_blocks_known_suspicious_method() {
    let mut config = crate::config::Config {
        l7_bloom_false_positive_verification: false,
        ..crate::config::Config::default()
    };
    config.sqlite_enabled = false;
    let context = WafContext::new(config).await.unwrap();
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "TRACE".to_string(), "/".to_string());

    let result = inspect_l7_bloom_filter(&context, &mut request, false)
        .expect("TRACE should match the default L7 bloom method set");

    assert!(result.blocked);
    assert_eq!(result.layer, InspectionLayer::L7);
    assert_eq!(
        request
            .get_metadata("l7.bloom.category")
            .map(String::as_str),
        Some("method")
    );
    assert_eq!(
        request.get_metadata("l7.drop_reason").map(String::as_str),
        Some("l7_bloom_filter")
    );
}

#[tokio::test]
async fn apply_client_identity_preserves_custom_source_ip_header_for_proxy() {
    let mut config = crate::config::Config::default();
    config.l4_config.trusted_cdn.manual_cidrs = vec!["203.0.113.0/24".to_string()];
    config.gateway_config.source_ip_strategy = crate::config::SourceIpStrategy::Header;
    config.gateway_config.custom_source_ip_header = "x-cdn-real-ip".to_string();
    let context = WafContext::new(config).await.unwrap();
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.add_header("x-cdn-real-ip".to_string(), "198.51.100.8".to_string());

    apply_client_identity(&context, "203.0.113.10:443".parse().unwrap(), &mut request);

    assert_eq!(
        request.get_header("x-cdn-real-ip").map(String::as_str),
        Some("198.51.100.8")
    );
    assert_eq!(
        request.get_header("x-real-ip").map(String::as_str),
        Some("198.51.100.8")
    );
    assert_eq!(
        request.get_header("x-forwarded-for").map(String::as_str),
        Some("198.51.100.8")
    );
    assert_eq!(
        request
            .get_metadata("network.trusted_proxy_peer")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        request
            .get_metadata("network.client_ip_unresolved")
            .map(String::as_str),
        Some("false")
    );
}

#[tokio::test]
async fn apply_client_identity_learns_cdn_peer_from_custom_source_ip_header_when_auth_is_disabled()
{
    let mut config = crate::config::Config::default();
    config.gateway_config.source_ip_strategy = crate::config::SourceIpStrategy::Header;
    config.gateway_config.custom_source_ip_header = "x-cdn-real-ip".to_string();
    let context = WafContext::new(config).await.unwrap();
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.add_header("x-cdn-real-ip".to_string(), "198.51.100.8".to_string());

    apply_client_identity(&context, "198.18.0.10:443".parse().unwrap(), &mut request);

    assert_eq!(request.client_ip.as_deref(), Some("198.51.100.8"));
    assert_eq!(
        request
            .get_metadata("network.trusted_proxy_peer")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        request
            .get_metadata("network.client_ip_source")
            .map(String::as_str),
        Some("forwarded_header")
    );
    assert_eq!(
        request
            .get_metadata("network.client_ip_unresolved")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        request
            .get_metadata("network.identity_state")
            .map(String::as_str),
        Some("trusted_cdn_forwarded")
    );
    assert_eq!(
        request
            .get_metadata("network.forward_header_valid")
            .map(String::as_str),
        Some("true")
    );
    assert!(context
        .config_snapshot()
        .l4_config
        .trusted_cdn
        .manual_cidrs
        .iter()
        .any(|cidr| cidr == "198.18.0.10/32"));
}

#[tokio::test]
async fn apply_client_identity_marks_unresolved_client_ip_for_trusted_proxy() {
    let mut config = crate::config::Config::default();
    config.l4_config.trusted_cdn.manual_cidrs = vec!["203.0.113.0/24".to_string()];
    config.gateway_config.source_ip_strategy = crate::config::SourceIpStrategy::XForwardedForFirst;
    let context = WafContext::new(config).await.unwrap();
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());

    apply_client_identity(&context, "203.0.113.10:443".parse().unwrap(), &mut request);

    assert_eq!(
        request
            .get_metadata("network.trusted_proxy_peer")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        request
            .get_metadata("network.client_ip_source")
            .map(String::as_str),
        Some("socket_peer")
    );
    assert_eq!(
        request
            .get_metadata("network.client_ip_unresolved")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        request
            .get_metadata("network.identity_state")
            .map(String::as_str),
        Some("trusted_cdn_unresolved")
    );
}

#[tokio::test]
async fn apply_client_identity_marks_trusted_header_resolution_state() {
    let mut config = crate::config::Config::default();
    config.l4_config.trusted_cdn.manual_cidrs = vec!["203.0.113.0/24".to_string()];
    config.gateway_config.source_ip_strategy = crate::config::SourceIpStrategy::Header;
    config.gateway_config.custom_source_ip_header = "x-cdn-real-ip".to_string();
    let context = WafContext::new(config).await.unwrap();
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.add_header("x-cdn-real-ip".to_string(), "198.51.100.8".to_string());

    apply_client_identity(&context, "203.0.113.10:443".parse().unwrap(), &mut request);

    assert_eq!(request.client_ip.as_deref(), Some("198.51.100.8"));
    assert_eq!(
        request
            .get_metadata("network.identity_state")
            .map(String::as_str),
        Some("trusted_cdn_forwarded")
    );
    assert_eq!(
        request
            .get_metadata("network.forward_header_valid")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        request
            .get_metadata("network.trusted_proxy_peer")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn apply_client_identity_requires_auth_header_when_enabled() {
    let mut config = crate::config::Config::default();
    config.l4_config.trusted_cdn.manual_cidrs = vec!["43.168.34.0/24".to_string()];
    config.gateway_config.source_ip_strategy = crate::config::SourceIpStrategy::Header;
    config.gateway_config.custom_source_ip_header = "x-cdn-real-ip".to_string();
    config.gateway_config.custom_source_ip_header_auth_enabled = true;
    config.gateway_config.custom_source_ip_header_auth_header = "x-cdn-auth".to_string();
    config.gateway_config.custom_source_ip_header_auth_secret = "secret-token".to_string();
    let context = WafContext::new(config).await.unwrap();

    let mut trusted_request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    trusted_request.add_header("x-cdn-real-ip".to_string(), "198.51.100.9".to_string());
    trusted_request.add_header("x-cdn-auth".to_string(), "secret-token".to_string());

    apply_client_identity(
        &context,
        "43.168.34.114:443".parse().unwrap(),
        &mut trusted_request,
    );
    assert_eq!(
        trusted_request
            .get_metadata("network.identity_state")
            .map(String::as_str),
        Some("trusted_cdn_forwarded")
    );
    assert_eq!(trusted_request.client_ip.as_deref(), Some("198.51.100.9"));

    let mut spoofed_request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    spoofed_request.add_header("x-cdn-real-ip".to_string(), "198.51.100.9".to_string());

    apply_client_identity(
        &context,
        "43.168.34.114:443".parse().unwrap(),
        &mut spoofed_request,
    );
    assert_eq!(
        spoofed_request
            .get_metadata("network.identity_state")
            .map(String::as_str),
        Some("trusted_cdn_unresolved")
    );
    assert_eq!(
        spoofed_request
            .get_metadata("network.forward_header_valid")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        spoofed_request
            .get_metadata("network.client_ip_unresolved")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(spoofed_request.client_ip.as_deref(), Some("43.168.34.114"));
}

#[tokio::test]
async fn apply_client_identity_learns_unknown_cdn_peer_only_with_valid_auth_header() {
    let mut config = crate::config::Config::default();
    config.gateway_config.source_ip_strategy = crate::config::SourceIpStrategy::Header;
    config.gateway_config.custom_source_ip_header = "x-cdn-real-ip".to_string();
    config.gateway_config.custom_source_ip_header_auth_enabled = true;
    config.gateway_config.custom_source_ip_header_auth_header = "x-cdn-auth".to_string();
    config.gateway_config.custom_source_ip_header_auth_secret = "secret-token".to_string();
    let context = WafContext::new(config).await.unwrap();

    let mut rejected =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    rejected.add_header("x-cdn-real-ip".to_string(), "198.51.100.10".to_string());
    rejected.add_header("x-cdn-auth".to_string(), "wrong".to_string());

    apply_client_identity(&context, "198.18.0.20:443".parse().unwrap(), &mut rejected);

    assert_eq!(
        rejected
            .get_metadata("network.identity_state")
            .map(String::as_str),
        Some("spoofed_forward_header")
    );
    assert_eq!(rejected.client_ip.as_deref(), Some("198.18.0.20"));
    assert!(!context
        .config_snapshot()
        .l4_config
        .trusted_cdn
        .manual_cidrs
        .iter()
        .any(|cidr| cidr == "198.18.0.20/32"));

    let mut accepted =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    accepted.add_header("x-cdn-real-ip".to_string(), "198.51.100.10".to_string());
    accepted.add_header("x-cdn-auth".to_string(), "secret-token".to_string());

    apply_client_identity(&context, "198.18.0.20:443".parse().unwrap(), &mut accepted);

    assert_eq!(
        accepted
            .get_metadata("network.identity_state")
            .map(String::as_str),
        Some("trusted_cdn_forwarded")
    );
    assert_eq!(accepted.client_ip.as_deref(), Some("198.51.100.10"));
    assert!(context
        .config_snapshot()
        .l4_config
        .trusted_cdn
        .manual_cidrs
        .iter()
        .any(|cidr| cidr == "198.18.0.20/32"));
}

#[tokio::test]
async fn inspect_blocked_client_ip_matches_resolved_forwarded_client_ip() {
    let mut config = crate::config::Config::default();
    config.l4_config.trusted_cdn.manual_cidrs = vec!["203.0.113.0/24".to_string()];
    config.gateway_config.source_ip_strategy = crate::config::SourceIpStrategy::Header;
    config.gateway_config.custom_source_ip_header = "cf-connecting-ip".to_string();
    let context = WafContext::new(config).await.unwrap();

    let store = context.sqlite_store.as_ref().unwrap();
    let blocked_at = unix_timestamp();
    store.enqueue_blocked_ip(crate::storage::BlockedIpRecord::new(
        "198.51.100.25".to_string(),
        "manual ban".to_string(),
        blocked_at,
        blocked_at + 3600,
    ));
    store.flush().await.unwrap();

    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.add_header("cf-connecting-ip".to_string(), "198.51.100.25".to_string());

    apply_client_identity(&context, "203.0.113.10:443".parse().unwrap(), &mut request);

    let result = inspect_blocked_client_ip(&context, &request).await;
    assert!(result.is_some());
    let result = result.unwrap();
    assert!(result.blocked);
    assert_eq!(result.layer, InspectionLayer::L7);
    assert!(result.reason.contains("198.51.100.25"));
}

#[tokio::test]
async fn inspect_blocked_client_ip_skips_socket_peer_when_header_strategy_unresolved() {
    let mut config = crate::config::Config::default();
    config.l4_config.trusted_cdn.manual_cidrs = vec!["111.123.42.0/24".to_string()];
    config.gateway_config.source_ip_strategy = crate::config::SourceIpStrategy::Header;
    config.gateway_config.custom_source_ip_header = "x-cdn-real-ip".to_string();
    let context = WafContext::new(config).await.unwrap();

    let store = context.sqlite_store.as_ref().unwrap();
    let blocked_at = unix_timestamp();
    store.enqueue_blocked_ip(crate::storage::BlockedIpRecord::new(
        "111.123.42.35".to_string(),
        "cdn node ban".to_string(),
        blocked_at,
        blocked_at + 3600,
    ));
    store.flush().await.unwrap();

    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.add_header("x-cdn-real-ip".to_string(), "not-an-ip".to_string());

    apply_client_identity(&context, "111.123.42.35:443".parse().unwrap(), &mut request);

    let result = inspect_blocked_client_ip(&context, &request).await;
    assert!(result.is_none());
}

#[tokio::test]
async fn server_public_ip_is_marked_and_skips_local_blocklist() {
    let mut config = crate::config::Config::default();
    config.l4_config.trusted_cdn.manual_cidrs = vec!["203.0.113.0/24".to_string()];
    config.gateway_config.source_ip_strategy = crate::config::SourceIpStrategy::Header;
    config.gateway_config.custom_source_ip_header = "x-cdn-real-ip".to_string();
    let context = WafContext::new(config).await.unwrap();
    let server_ip = "198.51.100.25".parse().unwrap();
    context.replace_server_public_ips_for_test([server_ip]);

    let store = context.sqlite_store.as_ref().unwrap();
    let blocked_at = unix_timestamp();
    store.enqueue_blocked_ip(crate::storage::BlockedIpRecord::new(
        "198.51.100.25".to_string(),
        "previous self ban".to_string(),
        blocked_at,
        blocked_at + 3600,
    ));
    store.flush().await.unwrap();

    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.add_header("x-cdn-real-ip".to_string(), "198.51.100.25".to_string());

    apply_client_identity(&context, "203.0.113.10:443".parse().unwrap(), &mut request);

    assert_eq!(
        request
            .get_metadata("network.server_public_ip_exempt")
            .map(String::as_str),
        Some("true")
    );
    let result = inspect_blocked_client_ip(&context, &request).await;
    assert!(result.is_none());
    assert!(store
        .load_active_local_blocked_ip_by_ip("198.51.100.25")
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn server_public_ip_can_be_learned_from_destination_match() {
    let mut config = crate::config::Config::default();
    config.sqlite_enabled = false;
    let context = WafContext::new(config).await.unwrap();
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.set_client_ip("8.8.8.8".to_string());
    let packet = PacketInfo::from_socket_addrs(
        "203.0.113.10:443".parse().unwrap(),
        "8.8.8.8:660".parse().unwrap(),
        Protocol::TCP,
    );

    apply_server_public_ip_metadata(&context, &packet, &mut request);

    assert_eq!(
        request
            .get_metadata("network.server_public_ip_exempt")
            .map(String::as_str),
        Some("true")
    );
    assert!(context.is_server_public_ip("8.8.8.8".parse().unwrap()));
}
