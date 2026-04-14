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
async fn apply_client_identity_preserves_custom_source_ip_header_for_proxy() {
    let mut config = crate::config::Config::default();
    config.l7_config.trusted_proxy_cidrs = vec!["203.0.113.0/24".to_string()];
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
async fn apply_client_identity_marks_unresolved_client_ip_for_trusted_proxy() {
    let mut config = crate::config::Config::default();
    config.l7_config.trusted_proxy_cidrs = vec!["203.0.113.0/24".to_string()];
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
}
