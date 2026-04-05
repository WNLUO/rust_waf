// HTTP/2.0支持测试

use waf::protocol::{ProtocolDetector, HttpVersion};
use waf::l7::L7Inspector;
use waf::config::L7Config;
use waf::core::{PacketInfo, Protocol};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_protocol_detector_http1() {
    let detector = ProtocolDetector::new(100);

    // 测试HTTP/1.1请求
    let http1_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let version = detector.detect_version(http1_request);

    assert_eq!(version, HttpVersion::Http1_1);
}

#[test]
fn test_protocol_detector_http2_direct() {
    let detector = ProtocolDetector::new(100);

    // 测试HTTP/2.0直接模式
    let http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let version = detector.detect_version(http2_preface);

    assert_eq!(version, HttpVersion::Http2_0);
}

#[test]
fn test_protocol_detector_http2_upgrade() {
    let detector = ProtocolDetector::new(100);

    // 测试HTTP/2.0升级请求
    let upgrade_request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\n\r\n";
    let version = detector.detect_version(upgrade_request);

    assert_eq!(version, HttpVersion::Http2_0);
}

#[test]
fn test_protocol_detector_empty() {
    let detector = ProtocolDetector::new(100);

    // 测试空数据，应该默认回退到HTTP/1.1
    let empty_data = b"";
    let version = detector.detect_version(empty_data);

    assert_eq!(version, HttpVersion::Http1_1);
}

#[test]
fn test_unified_request_creation() {
    use waf::protocol::UnifiedHttpRequest;

    let mut request = UnifiedHttpRequest::new(
        HttpVersion::Http2_0,
        "POST".to_string(),
        "/api/data".to_string()
    );

    request.add_header("Content-Type".to_string(), "application/json".to_string());
    request.add_header("User-Agent".to_string(), "TestClient/1.0".to_string());
    request.body = b"test data".to_vec();

    assert_eq!(request.version, HttpVersion::Http2_0);
    assert_eq!(request.method, "POST");
    assert_eq!(request.uri, "/api/data");
    assert_eq!(request.get_header("content-type"), Some(&"application/json".to_string()));
}

#[test]
fn test_l7_config_http2_enabled() {
    let mut config = L7Config::default();

    // 验证默认配置中HTTP/2.0是禁用的
    assert!(!config.http2_config.enabled);

    // 启用HTTP/2.0
    config.http2_config.enabled = true;
    assert!(config.http2_config.enabled);
}

#[test]
fn test_http2_config_defaults() {
    let config = L7Config::default();
    let http2_config = config.http2_config;

    // 验证HTTP/2.0配置的默认值
    assert_eq!(http2_config.max_concurrent_streams, 100);
    assert_eq!(http2_config.max_frame_size, 16384);
    assert!(http2_config.enable_priorities);
    assert_eq!(http2_config.initial_window_size, 65535);
}

#[test]
fn test_l7_inspector_with_unified_request() {
    use waf::protocol::UnifiedHttpRequest;

    let config = L7Config::default();
    let inspector = L7Inspector::new(config.clone(), false, false);

    // 创建测试请求
    let mut request = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "GET".to_string(),
        "/".to_string()
    );

    request.add_header("Host".to_string(), "example.com".to_string());
    request.add_header("User-Agent".to_string(), "Test/1.0".to_string());

    // 创建测试数据包
    let packet = PacketInfo {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        source_port: 12345,
        dest_port: 8080,
        protocol: Protocol::TCP,
        timestamp: 0,
    };

    // 检查请求
    let result = inspector.inspect_unified_request(&packet, &request);

    // 验证正常请求被允许
    assert!(!result.blocked);
    assert_eq!(result.layer, waf::core::InspectionLayer::L7);
}

#[test]
fn test_l7_inspector_sql_injection_detection() {
    use waf::protocol::UnifiedHttpRequest;

    let config = L7Config::default();
    let inspector = L7Inspector::new(config.clone(), false, false);

    // 创建测试数据包
    let packet = PacketInfo {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        source_port: 12345,
        dest_port: 8080,
        protocol: Protocol::TCP,
        timestamp: 0,
    };

    // 使用包含SQL注入的简单测试字符串
    let test_payload = b"UNION SELECT * FROM users".to_vec();
    let inspection_str = String::from_utf8_lossy(&test_payload).to_string();

    // 检查请求
    let result = inspector.inspect_http_request(&packet, inspection_str.as_bytes());

    // 验证SQL注入被检测到
    assert!(result.blocked);
    assert!(result.reason.contains("SQL injection"));
}

#[test]
fn test_l7_inspector_xss_detection() {
    use waf::protocol::UnifiedHttpRequest;

    let config = L7Config::default();
    let inspector = L7Inspector::new(config.clone(), false, false);

    // 创建包含XSS的请求
    let mut request = UnifiedHttpRequest::new(
        HttpVersion::Http1_1,
        "GET".to_string(),
        "/search".to_string()
    );

    request.add_header("Host".to_string(), "example.com".to_string());
    request.add_header("Content-Type".to_string(), "application/json".to_string());

    // 创建测试数据包
    let packet = PacketInfo {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        source_port: 12345,
        dest_port: 8080,
        protocol: Protocol::TCP,
        timestamp: 0,
    };

    // 使用to_inspection_string方法来测试XSS检测
    let test_payload = b"<script>alert('xss')</script>".to_vec();
    let test_str = String::from_utf8_lossy(&test_payload).to_string();

    // 创建包含XSS的请求字符串
    let inspection_str = format!("GET /search\nHost: example.com\nContent-Type: application/json\n\n{}", test_str);

    // 检查请求
    let result = inspector.inspect_http_request(&packet, inspection_str.as_bytes());

    // 验证XSS被检测到
    assert!(result.blocked);
    assert!(result.reason.contains("XSS"));
}

#[test]
fn test_http_version_display() {
    assert_eq!(format!("{}", HttpVersion::Http1_1), "HTTP/1.1");
    assert_eq!(format!("{}", HttpVersion::Http2_0), "HTTP/2.0");
    assert_eq!(format!("{}", HttpVersion::Http3_0), "HTTP/3.0");
}

#[test]
fn test_http_version_default() {
    let version = HttpVersion::default();
    assert_eq!(version, HttpVersion::Http1_1);
}