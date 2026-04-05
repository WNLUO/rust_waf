// HTTP/3.0支持测试

use waf::protocol::{HttpVersion, Http3Handler, Http3StreamManager, ProtocolDetector, UnifiedHttpRequest};
use waf::config::Http3Config;
use waf::l7::L7Inspector;
use waf::core::{PacketInfo, Protocol, InspectionLayer};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn test_http3_config_default() {
    let config = Http3Config::default();

    assert!(!config.enabled);
    assert_eq!(config.listen_addr, "0.0.0.0:8443");
    assert_eq!(config.max_concurrent_streams, 100);
    assert_eq!(config.idle_timeout_secs, 300);
    assert_eq!(config.mtu, 1350);
    assert_eq!(config.max_frame_size, 65536);
    assert!(config.enable_connection_migration);
    assert_eq!(config.qpack_table_size, 4096);
    assert!(config.enable_tls13);
}

#[test]
fn test_http3_config_production() {
    let config = Http3Config::production();

    assert!(config.enabled);
    assert_eq!(config.listen_addr, "0.0.0.0:8443");
    assert_eq!(config.max_concurrent_streams, 100);
    assert_eq!(config.idle_timeout_secs, 300);
}

#[test]
fn test_http3_config_development() {
    let config = Http3Config::development();

    assert!(config.enabled);
    assert_eq!(config.listen_addr, "127.0.0.1:8443");
    assert_eq!(config.max_concurrent_streams, 50);
    assert_eq!(config.idle_timeout_secs, 60);
    assert_eq!(config.mtu, 1200);
    assert!(!config.enable_connection_migration);
}

#[test]
fn test_http3_config_validation() {
    let mut config = Http3Config::default();

    // 测试有效配置
    assert!(config.validate().is_ok());

    // 测试无效的MTU
    config.mtu = 1100;
    assert!(config.validate().is_err());

    // 测试无效的并发流数
    config.max_concurrent_streams = 0;
    assert!(config.validate().is_err());

    config.max_concurrent_streams = 2000;
    assert!(config.validate().is_err());

    // 测试无效的QPACK表大小
    config.qpack_table_size = 512;
    assert!(config.validate().is_err());

    // 测试TLS证书配置
    config.enable_tls13 = true;
    config.certificate_path = Some("/path/to/cert.pem".to_string());
    config.private_key_path = None;
    assert!(config.validate().is_err());

    config.certificate_path = None;
    config.private_key_path = Some("/path/to/key.pem".to_string());
    assert!(config.validate().is_err());
}

#[test]
fn test_http3_handler_creation() {
    let config = Http3Config::default();
    let handler = Http3Handler::new(config);

    assert_eq!(handler.max_concurrent_streams, 100);
}

#[test]
fn test_http3_handler_with_options() {
    let config = Http3Config::default();
    let handler = Http3Handler::new(config)
        .with_max_concurrent_streams(50)
        .with_quic_metrics(false);

    assert_eq!(handler.max_concurrent_streams, 50);
}

#[test]
fn test_http_version_display() {
    assert_eq!(format!("{}", HttpVersion::Http3_0), "HTTP/3.0");
}

#[test]
fn test_http_version_default() {
    let version = HttpVersion::default();
    assert_eq!(version, HttpVersion::Http1_1);
}

#[test]
fn test_http_version_equality() {
    assert_eq!(HttpVersion::Http1_1, HttpVersion::Http1_1);
    assert_eq!(HttpVersion::Http2_0, HttpVersion::Http2_0);
    assert_eq!(HttpVersion::Http3_0, HttpVersion::Http3_0);

    assert_ne!(HttpVersion::Http1_1, HttpVersion::Http2_0);
    assert_ne!(HttpVersion::Http2_0, HttpVersion::Http3_0);
    assert_ne!(HttpVersion::Http3_0, HttpVersion::Http1_1);
}

#[test]
fn test_unified_request_http3() {
    let mut request = UnifiedHttpRequest::new(
        HttpVersion::Http3_0,
        "GET".to_string(),
        "/api/data".to_string()
    );

    request.add_header(":method".to_string(), "GET".to_string());
    request.add_header(":path".to_string(), "/api/data".to_string());
    request.add_header(":scheme".to_string(), "https".to_string());
    request.add_header(":authority".to_string(), "api.example.com".to_string());

    assert_eq!(request.version, HttpVersion::Http3_0);
    assert_eq!(request.method, "GET");
    assert_eq!(request.uri, "/api/data");
    assert_eq!(request.get_header(":method"), Some(&"GET".to_string()));
    assert_eq!(request.get_header(":path"), Some(&"/api/data".to_string()));
}

#[test]
fn test_l7_inspector_with_unified_request_http3() {
    let l7_config = waf::config::L7Config::default();
    let inspector = L7Inspector::new(l7_config, false, false);

    // 创建HTTP/3.0请求
    let mut request = UnifiedHttpRequest::new(
        HttpVersion::Http3_0,
        "GET".to_string(),
        "/".to_string()
    );

    request.add_header("User-Agent".to_string(), "HTTP/3.0 Test Client".to_string());
    request.body = b"UNION SELECT * FROM users".to_vec();

    // 创建测试数据包
    let packet = PacketInfo {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        source_port: 12345,
        dest_port: 8443,
        protocol: Protocol::TCP,
        timestamp: 0,
    };

    // 检查请求
    let result = inspector.inspect_unified_request(&packet, &request);

    // 验证SQL注入被检测到
    assert!(result.blocked);
    assert!(result.reason.contains("SQL injection"));
}

#[test]
fn test_l7_inspector_xss_detection_http3() {
    let l7_config = waf::config::L7Config::default();
    let inspector = L7Inspector::new(l7_config, false, false);

    // 创建包含XSS的请求
    let mut request = UnifiedHttpRequest::new(
        HttpVersion::Http3_0,
        "GET".to_string(),
        "/search".to_string()
    );

    request.add_header("User-Agent".to_string(), "HTTP/3.0 Browser".to_string());
    request.body = b"<script>alert('xss')</script>".to_vec();

    // 创建测试数据包
    let packet = PacketInfo {
        source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2)),
        source_port: 12345,
        dest_port: 8443,
        protocol: Protocol::TCP,
        timestamp: 0,
    };

    // 检查请求
    let result = inspector.inspect_unified_request(&packet, &request);

    // 验证XSS被检测到
    assert!(result.blocked);
    assert!(result.reason.contains("XSS"));
}

#[test]
fn test_protocol_detector_http1() {
    let detector = ProtocolDetector::new(100);

    // 测试HTTP/1.1请求
    let http1_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert_eq!(detector.detect_version(http1_request), HttpVersion::Http1_1);
}

#[test]
fn test_protocol_detector_http2_direct() {
    let detector = ProtocolDetector::new(100);

    // 测试HTTP/2.0直接请求
    let http2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    assert_eq!(detector.detect_version(http2_preface), HttpVersion::Http2_0);
}

#[test]
fn test_protocol_detector_http2_upgrade() {
    let detector = ProtocolDetector::new(100);

    // 测试HTTP/2.0升级请求
    let http2_upgrade = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\n\r\n";
    assert_eq!(detector.detect_version(http2_upgrade), HttpVersion::Http2_0);
}

#[test]
fn test_protocol_detector_http3_quic() {
    let detector = ProtocolDetector::new(100);

    // 测试QUIC长头格式
    let quic_long_header = [0xC0u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert!(detector.is_http3_quic(&quic_long_header));

    // 测试QUIC短头格式
    let quic_short_header = [0x80u8, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    assert!(detector.is_http3_quic(&quic_short_header));

    // 测试非QUIC包
    let non_quic = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    assert!(!detector.is_http3_quic(non_quic));
}

#[test]
fn test_stream_manager_creation() {
    let manager = Http3StreamManager::new(10, true);

    assert_eq!(manager.active_stream_count(), 0);
    assert_eq!(manager.max_concurrent_streams, 10);
    assert!(manager.enable_priorities);
}

#[test]
fn test_stream_manager_basic_operations() {
    let mut manager = Http3StreamManager::new(10, true);

    // 测试流创建
    let stream_id1 = manager.create_stream();
    let stream_id2 = manager.create_stream();

    assert_eq!(stream_id1, Some(1));
    assert_eq!(stream_id2, Some(5));
    assert_eq!(manager.active_stream_count(), 2);

    // 测试流关闭
    manager.close_stream(1);
    assert_eq!(manager.active_stream_count(), 1);
    assert!(!manager.stream_exists(1));

    // 测试流限制
    for _ in 0..8 {
        manager.create_stream();
    }
    let over_limit = manager.create_stream();
    assert!(over_limit.is_some()); // Should succeed (1 + 8 + 1 = 10)
    assert_eq!(manager.active_stream_count(), 10);

    // Test exceeding the limit
    let exceed_limit = manager.create_stream();
    assert!(exceed_limit.is_none()); // Should fail (10 + 1 = 11 > 10)
    assert_eq!(manager.active_stream_count(), 10);
}

#[test]
fn test_stream_manager_priorities() {
    let mut manager = Http3StreamManager::new(10, true);

    let stream_id = manager.create_stream().unwrap();
    manager.set_priority(stream_id, 255);

    let stats = manager.get_stream_stats(stream_id).unwrap();
    assert_eq!(stats.3, 255); // 高优先级
}

#[test]
fn test_stream_manager_window_update() {
    let mut manager = Http3StreamManager::new(10, false);

    let stream_id = manager.create_stream().unwrap();
    manager.update_window(stream_id, 1000);

    let stats = manager.get_stream_stats(stream_id).unwrap();
    assert_eq!(stats.2, 65535 + 1000); // 默认窗口大小+增量
}

#[tokio::test]
async fn test_http3_handler_unified_request() {
    let config = Http3Config::production(); // Use production config with HTTP/3.0 enabled
    let handler = Http3Handler::new(config);

    // 读取HTTP/3.0请求（模拟）
    let mut conn = MockQuicConnection::new();
    let result = handler.read_request(&mut conn, 8192).await;

    assert!(result.is_ok());
    let request = result.unwrap();
    assert_eq!(request.version, HttpVersion::Http3_0);
    assert_eq!(request.method, "GET");
}

#[tokio::test]
async fn test_http3_handler_response() {
    let config = Http3Config::production(); // Use production config with HTTP/3.0 enabled
    let handler = Http3Handler::new(config);

    // 写入HTTP/3.0响应（模拟）
    let mut stream = MockQuicStream::new();
    let status = handler.write_response(&mut stream, 123, 200, &[], b"Test response").await;

    assert!(status.is_ok());
}

// Mock类型用于测试HTTP/3.0处理器
struct MockQuicConnection;

impl MockQuicConnection {
    pub fn new() -> Self {
        Self
    }
}

struct MockQuicStream {
    data: Vec<u8>,
}

impl MockQuicStream {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
        }
    }
}

// Mock implementations removed - the tests work without custom trait implementations
// The handler methods only require Send + Sync bounds for generic parameters