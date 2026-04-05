use super::{HttpVersion, ProtocolError};
use log::{debug, info};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

/// HTTP协议检测器
pub struct ProtocolDetector {
    #[allow(dead_code)]
    detection_timeout: Duration,
}

impl ProtocolDetector {
    /// 创建新的协议检测器
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            detection_timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// 检测HTTP协议版本
    ///
    /// 检测策略：
    /// 1. 检查HTTP/2.0直接模式前置请求
    /// 2. 默认回退到HTTP/1.1
    ///
    /// 说明：
    /// - h2c Upgrade 请求本质上仍然是 HTTP/1.1 首请求，应先按 HTTP/1.1 读取；
    /// - HTTP/3.0 / QUIC 基于 UDP，不应在 TCP 连接分流阶段误判。
    pub fn detect_version(&self, initial_bytes: &[u8]) -> HttpVersion {
        // 1. 检查HTTP/2.0直接模式
        if self.is_http2_direct(initial_bytes) {
            debug!("Detected HTTP/2.0 direct mode");
            return HttpVersion::Http2_0;
        }

        // 2. 默认回退到HTTP/1.1
        debug!("Defaulting to HTTP/1.1");
        HttpVersion::Http1_1
    }

    /// 从流中检测协议版本（读取初始字节）
    #[allow(dead_code)]
    pub async fn detect_from_stream<R>(&self, reader: &mut R) -> Result<HttpVersion, ProtocolError>
    where
        R: AsyncReadExt + Unpin,
    {
        let mut buffer = vec![0u8; 256]; // 读取前256字节用于检测

        let bytes_read = timeout(self.detection_timeout, reader.read(&mut buffer))
            .await
            .map_err(|_| ProtocolError::Timeout)??;

        if bytes_read == 0 {
            debug!("No data read, defaulting to HTTP/1.1");
            return Ok(HttpVersion::Http1_1);
        }

        let version = self.detect_version(&buffer[..bytes_read]);
        info!("Detected protocol version: {}", version);
        Ok(version)
    }

    /// 检查是否为HTTP/2.0直接模式
    ///
    /// HTTP/2.0直接模式前置请求：
    /// PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
    fn is_http2_direct(&self, bytes: &[u8]) -> bool {
        const HTTP2_PRI: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        if bytes.len() < HTTP2_PRI.len() {
            return false;
        }

        bytes.starts_with(HTTP2_PRI)
    }

    /// 检查HTTP/2.0升级请求
    ///
    /// h2c Upgrade 首包仍然是合法的 HTTP/1.1 请求，
    /// 这里只做“识别”而不用于 TCP 分流。
    pub fn is_http2_upgrade_request(&self, bytes: &[u8]) -> bool {
        let request_str = String::from_utf8_lossy(bytes);

        if request_str.contains("Upgrade: h2c")
            || request_str.contains("Upgrade: h2")
        {
            return true;
        }

        false
    }

    /// 检查是否为HTTP/3.0（QUIC协议）
    ///
    /// QUIC协议包检测逻辑
    #[allow(dead_code)]
    pub fn is_http3_quic(&self, bytes: &[u8]) -> bool {
        // QUIC包格式检测
        // QUIC包以特定头部格式开始

        // 检查QUIC长头格式 (0xC0)
        if bytes.len() >= 1 && (bytes[0] & 0xC0) == 0xC0 {
            debug!("Detected QUIC long header format");
            return true;
        }

        // 检查QUIC短头格式 (0x80)
        if bytes.len() >= 1 && (bytes[0] & 0x80) == 0x80 {
            debug!("Detected QUIC short header format");
            return true;
        }

        false
    }
}

impl Default for ProtocolDetector {
    fn default() -> Self {
        Self::new(100) // 默认100ms超时
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http2_direct_detection() {
        let detector = ProtocolDetector::new(100);
        let http2_pri = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

        assert_eq!(detector.detect_version(http2_pri), HttpVersion::Http2_0);
    }

    #[test]
    fn test_http2_upgrade_detection() {
        let detector = ProtocolDetector::new(100);
        let upgrade_request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: h2c\r\nConnection: Upgrade, HTTP2-Settings\r\n";

        assert_eq!(detector.detect_version(upgrade_request), HttpVersion::Http1_1);
        assert!(detector.is_http2_upgrade_request(upgrade_request));
    }

    #[test]
    fn test_http1_detection() {
        let detector = ProtocolDetector::new(100);
        let http1_request = b"GET / HTTP/1.1\r\nHost: example.com\r\n";

        assert_eq!(detector.detect_version(http1_request), HttpVersion::Http1_1);
    }

    #[test]
    fn test_empty_bytes_defaults_to_http1() {
        let detector = ProtocolDetector::new(100);
        let empty_bytes = b"";

        assert_eq!(detector.detect_version(empty_bytes), HttpVersion::Http1_1);
    }
}
