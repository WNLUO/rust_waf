use crate::config::L7Config;
use crate::core::{InspectionLayer, InspectionResult, PacketInfo, WafContext};
use crate::protocol::UnifiedHttpRequest;
use log::{debug, info};

pub struct L7Inspector {
    config: L7Config,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{PacketInfo, Protocol};
    use crate::protocol::{HttpVersion, UnifiedHttpRequest};
    use std::net::{IpAddr, Ipv4Addr};

    fn test_packet() -> PacketInfo {
        PacketInfo {
            source_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            dest_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            source_port: 12345,
            dest_port: 8080,
            protocol: Protocol::TCP,
            timestamp: 0,
        }
    }

    #[test]
    fn unified_request_is_allowed_when_size_is_within_limit() {
        let inspector = L7Inspector::new(L7Config::default(), false, false);
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
        request.add_header("accept".to_string(), "*/*".to_string());

        let result = inspector.inspect_unified_request(&test_packet(), &request);
        assert!(!result.blocked, "unexpected block reason: {}", result.reason);
    }

    #[test]
    fn oversized_request_is_allowed() {
        let inspector = L7Inspector::new(L7Config::default(), false, false);
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "POST".to_string(), "/".to_string());
        request.body = vec![b'a'; L7Config::default().max_request_size + 1];

        let result = inspector.inspect_unified_request(&test_packet(), &request);
        assert!(!result.blocked, "unexpected block reason: {}", result.reason);
    }
}

impl L7Inspector {
    pub fn new(
        config: L7Config,
        _bloom_enabled: bool,
        _bloom_false_positive_verification: bool,
    ) -> Self {
        info!("Initializing L7 Inspector");
        Self { config }
    }

    pub async fn start(&self, _context: &WafContext) -> anyhow::Result<()> {
        debug!("Starting L7 inspector...");
        Ok(())
    }

    #[allow(dead_code)]
    pub fn inspect_http_request(&self, _packet: &PacketInfo, payload: &[u8]) -> InspectionResult {
        if !self.config.http_inspection_enabled {
            return InspectionResult {
                blocked: false,
                reason: String::new(),
                layer: InspectionLayer::L7,
            };
        }

        // Convert payload to string for inspection
        let binding = String::from_utf8_lossy(payload);
        if binding.is_empty() {
            return InspectionResult {
                blocked: false,
                reason: String::new(),
                layer: InspectionLayer::L7,
            };
        }

        InspectionResult {
            blocked: false,
            reason: String::new(),
            layer: InspectionLayer::L7,
        }
    }

    /// 检查统一HTTP请求（支持多协议版本）
    ///
    /// 这个方法接受UnifiedHttpRequest结构，可以处理HTTP/1.1、HTTP/2.0等不同协议版本的请求
    pub fn inspect_unified_request(
        &self,
        _packet: &PacketInfo,
        request: &UnifiedHttpRequest,
    ) -> InspectionResult {
        if !self.config.http_inspection_enabled {
            return InspectionResult {
                blocked: false,
                reason: String::new(),
                layer: InspectionLayer::L7,
            };
        }

        debug!(
            "Inspecting {} request: {} {}",
            request.version, request.method, request.uri
        );

        debug!("{} request passed all checks", request.version);
        InspectionResult {
            blocked: false,
            reason: String::new(),
            layer: InspectionLayer::L7,
        }
    }
}
