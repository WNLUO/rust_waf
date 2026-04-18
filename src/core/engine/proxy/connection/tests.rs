use super::http2::{select_upstream_transport, UpstreamTransport};
use super::request::{build_http2_upstream_request, effective_http2_upstream_authority};
use super::tls::resolve_upstream_tls_server_name;
use super::*;
use crate::config::{Config, L7Config, UpstreamProtocolPolicy};

fn https_upstream(authority: &str) -> crate::core::gateway::UpstreamEndpoint {
    crate::core::gateway::UpstreamEndpoint {
        scheme: UpstreamScheme::Https,
        authority: authority.to_string(),
    }
}

#[test]
fn upstream_tls_server_name_prefers_original_host_without_port() {
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
    request.add_header("host".to_string(), "wnluo.com:660".to_string());

    let resolved =
        resolve_upstream_tls_server_name(&request, &https_upstream("origin.example.com:880"))
            .unwrap();

    assert_eq!(resolved.as_deref(), Some("wnluo.com"));
}

#[test]
fn upstream_tls_server_name_preserves_wildcard_request_host() {
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
    request.add_header("host".to_string(), "api.wnluo.com".to_string());

    let resolved =
        resolve_upstream_tls_server_name(&request, &https_upstream("origin.example.com:880"))
            .unwrap();

    assert_eq!(resolved.as_deref(), Some("api.wnluo.com"));
}

#[test]
fn upstream_tls_server_name_falls_back_to_site_primary_hostname() {
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
    request.add_metadata(
        "gateway.primary_hostname".to_string(),
        "portal.example.com".to_string(),
    );

    let resolved =
        resolve_upstream_tls_server_name(&request, &https_upstream("origin.example.com:880"))
            .unwrap();

    assert_eq!(resolved.as_deref(), Some("portal.example.com"));
}

#[test]
fn upstream_tls_server_name_falls_back_to_upstream_host() {
    let request = UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());

    let resolved =
        resolve_upstream_tls_server_name(&request, &https_upstream("origin.example.com:8443"))
            .unwrap();

    assert_eq!(resolved.as_deref(), Some("origin.example.com"));
}

async fn test_context(l7_config: L7Config) -> WafContext {
    WafContext::new(Config {
        sqlite_enabled: false,
        metrics_enabled: false,
        l7_config,
        ..Config::default()
    })
    .await
    .expect("context should build")
}

#[tokio::test]
async fn strict_http1_validation_rejects_multiple_content_length() {
    let context = test_context(L7Config::default()).await;
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http1_1, "POST".to_string(), "/".to_string());
    request.add_header("content-length".to_string(), "5".to_string());
    request.add_metadata("http1.content_length_count".to_string(), "2".to_string());

    let result = enforce_http1_request_safety(&context, &request);

    assert!(result.is_err());
}

#[tokio::test]
async fn upstream_selection_prefers_http2_for_https_when_enabled() {
    let mut l7_config = L7Config::default();
    l7_config.upstream_protocol_policy = UpstreamProtocolPolicy::Http2Preferred;
    let context = test_context(l7_config).await;
    let request = UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());

    let selected = select_upstream_transport(&context, &request, &https_upstream("up.example:443"))
        .expect("selection should succeed");

    assert_eq!(selected, UpstreamTransport::Http2);
}

#[tokio::test]
async fn upstream_selection_falls_back_to_http1_for_plain_http() {
    let mut l7_config = L7Config::default();
    l7_config.upstream_protocol_policy = UpstreamProtocolPolicy::Http2Preferred;
    let context = test_context(l7_config).await;
    let request = UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
    let upstream = crate::core::gateway::UpstreamEndpoint {
        scheme: UpstreamScheme::Http,
        authority: "127.0.0.1:8080".to_string(),
    };

    let selected =
        select_upstream_transport(&context, &request, &upstream).expect("selection should succeed");

    assert_eq!(selected, UpstreamTransport::Http1);
}

#[test]
fn http2_upstream_authority_prefers_original_host() {
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
    request.add_header("host".to_string(), "wnluo.com".to_string());

    let authority = effective_http2_upstream_authority(&request, &https_upstream("127.0.0.1:880"));

    assert_eq!(authority, "wnluo.com");
}

#[test]
fn http2_upstream_request_preserves_forwarded_headers() {
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
    request.add_header("host".to_string(), "wnluo.com".to_string());
    request.add_header("eo-log-uuid".to_string(), "trace".to_string());
    request.add_header(
        "cdn-loop".to_string(),
        "TencentEdgeOne; loops=2".to_string(),
    );
    request.add_header("via".to_string(), "ens-cache".to_string());
    request.add_header("x-cdn-real-ip".to_string(), "1.2.3.4".to_string());
    request.add_header("x-forwarded-for".to_string(), "1.2.3.4".to_string());

    let built = build_http2_upstream_request(&request, &https_upstream("127.0.0.1:880"))
        .expect("request should build");

    assert_eq!(
        built.uri().authority().map(|value| value.as_str()),
        Some("wnluo.com")
    );
    assert!(built.headers().get("host").is_none());
    assert!(built.headers().get("eo-log-uuid").is_none());
    assert!(built.headers().get("cdn-loop").is_none());
    assert!(built.headers().get("via").is_none());
    assert_eq!(built.headers()["x-cdn-real-ip"], "1.2.3.4");
    assert_eq!(built.headers()["x-forwarded-for"], "1.2.3.4");
}
