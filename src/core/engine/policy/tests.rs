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
async fn resolve_client_ip_falls_back_to_real_ip_headers_for_trusted_proxy() {
    let mut config = crate::config::Config::default();
    config.l7_config.trusted_proxy_cidrs = vec!["203.0.113.0/24".to_string()];
    config.l7_config.real_ip_headers = vec![
        "cf-connecting-ip".to_string(),
        "x-forwarded-for".to_string(),
    ];
    let context = WafContext::new(config).await.unwrap();
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.add_header("cf-connecting-ip".to_string(), "198.51.100.7".to_string());

    let (resolved, source) =
        resolve_client_ip(&context, "203.0.113.10:443".parse().unwrap(), &request);

    assert_eq!(
        resolved,
        "198.51.100.7".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(source, "real_ip_header");
}
