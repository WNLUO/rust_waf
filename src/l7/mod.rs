pub mod bloom_filter;

use crate::config::L7Config;
use crate::core::{InspectionLayer, InspectionResult, PacketInfo, WafContext};
use crate::l7::bloom_filter::L7BloomFilterManager;
use crate::protocol::UnifiedHttpRequest;
use lazy_static::lazy_static;
use log::{debug, info};
use regex::Regex;

pub struct L7Inspector {
    config: L7Config,
    bloom_manager: Option<L7BloomFilterManager>,
}

lazy_static! {
    static ref SQL_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"'(?i)(or|and)\s+\d+\s*=\s*\d+").unwrap(),
        Regex::new(r"(?i)(union\s+select|drop\s+table|delete\s+from|insert\s+into)").unwrap(),
        Regex::new(r"(?i);\s*(select|union|drop|delete|insert|update|exec|from|where)\b")
            .unwrap(),
        Regex::new(r#"(?i)(?:^|[\s'"=])(--|/\*)(?:[\s]|$)"#).unwrap(),
        Regex::new(r#"(?i)(?:^|[\s'"=])\*/(?:[\s]|$)"#).unwrap(),
    ];
    static ref XSS_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)<script[^>]*>.*?</script>").unwrap(),
        Regex::new(r"(?i)javascript:").unwrap(),
        Regex::new(r"(?i)on\w+\s*=").unwrap(),
    ];
    static ref PATH_TRAVERSAL_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"\.\.\/").unwrap(),
        Regex::new(r"\.\.\\").unwrap(),
    ];
    static ref COMMAND_INJECTION_PATTERNS: Vec<Regex> = vec![
        Regex::new(r"(?i)(;\s*)(ls|cat|pwd|whoami|rm|mv|cp)\s").unwrap(),
        Regex::new(r"(?i)(\|\s*)(ls|cat|pwd|whoami|rm|mv|cp)\s").unwrap(),
        Regex::new(r"(?i)(`.*?`)").unwrap(),
    ];
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
    fn wildcard_accept_header_is_not_flagged_as_sql_injection() {
        let inspector = L7Inspector::new(L7Config::default(), false, false);
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http2_0, "GET".to_string(), "/".to_string());
        request.add_header("accept".to_string(), "*/*".to_string());

        let result = inspector.inspect_unified_request(&test_packet(), &request);
        assert!(!result.blocked, "unexpected block reason: {}", result.reason);
    }

    #[test]
    fn sql_comment_marker_still_triggers_detection() {
        let inspector = L7Inspector::new(L7Config::default(), false, false);
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/?id=1' --".to_string(),
        );
        request.add_header("accept".to_string(), "text/plain".to_string());

        let result = inspector.inspect_unified_request(&test_packet(), &request);
        assert!(result.blocked);
        assert!(result.reason.contains("SQL injection"));
    }
}

impl L7Inspector {
    pub fn new(
        config: L7Config,
        bloom_enabled: bool,
        bloom_false_positive_verification: bool,
    ) -> Self {
        info!("Initializing L7 Inspector");
        info!(
            "Bloom filter enabled: {}, false positive verification: {}",
            bloom_enabled, bloom_false_positive_verification
        );

        let bloom_manager = if bloom_enabled {
            Some(L7BloomFilterManager::new(
                config.clone(),
                bloom_enabled,
                bloom_false_positive_verification,
            ))
        } else {
            None
        };

        if bloom_enabled {
            info!("Bloom filter support is enabled");
        }

        Self {
            config: config.clone(),
            bloom_manager,
        }
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

        // Bloom filter checks first
        if let Some(bloom_manager) = &self.bloom_manager {
            if bloom_manager.is_enabled() {
                debug!("Running L7 bloom filter checks");

                let payload_str = String::from_utf8_lossy(payload);

                // Check payload
                if bloom_manager.check_payload(payload_str.as_ref()) {
                    debug!("Payload matched in bloom filter");
                    return InspectionResult {
                        blocked: true,
                        reason: "Blocked by L7 bloom filter: payload".to_string(),
                        layer: InspectionLayer::L7,
                    };
                }
            }
        }

        // Check request size
        if payload.len() > self.config.max_request_size {
            return InspectionResult {
                blocked: true,
                reason: "Request size exceeded limit".to_string(),
                layer: InspectionLayer::L7,
            };
        }

        // Convert payload to string for inspection
        let binding = String::from_utf8_lossy(payload);
        let payload_str = match binding.as_ref() {
            "" => {
                return InspectionResult {
                    blocked: false,
                    reason: String::new(),
                    layer: InspectionLayer::L7,
                }
            }
            s => s,
        };

        let lowered = if self.config.prefilter_enabled {
            Some(payload_str.to_ascii_lowercase())
        } else {
            None
        };

        // SQL Injection detection
        if self.config.enable_sql_injection_detection
            && self.should_run_sql_checks(payload_str, lowered.as_deref())
        {
            if self.detect_sql_injection(payload_str) {
                return InspectionResult {
                    blocked: true,
                    reason: "SQL injection attack detected".to_string(),
                    layer: InspectionLayer::L7,
                };
            }
        }

        // XSS detection
        if self.config.enable_xss_detection
            && self.should_run_xss_checks(payload_str, lowered.as_deref())
        {
            if self.detect_xss(payload_str) {
                return InspectionResult {
                    blocked: true,
                    reason: "XSS attack detected".to_string(),
                    layer: InspectionLayer::L7,
                };
            }
        }

        // Path traversal detection
        if self.config.enable_path_traversal_detection
            && self.should_run_path_traversal_checks(payload_str, lowered.as_deref())
        {
            if self.detect_path_traversal(payload_str) {
                return InspectionResult {
                    blocked: true,
                    reason: "Path traversal attack detected".to_string(),
                    layer: InspectionLayer::L7,
                };
            }
        }

        // Command injection detection
        if self.config.enable_command_injection_detection
            && self.should_run_command_checks(payload_str, lowered.as_deref())
        {
            if self.detect_command_injection(payload_str) {
                return InspectionResult {
                    blocked: true,
                    reason: "Command injection attack detected".to_string(),
                    layer: InspectionLayer::L7,
                };
            }
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

        // Check request size
        if request.total_size() > self.config.max_request_size {
            return InspectionResult {
                blocked: true,
                reason: format!(
                    "Request size exceeded limit: {} bytes",
                    request.total_size()
                ),
                layer: InspectionLayer::L7,
            };
        }

        // Convert unified request to inspection string
        let payload_str = request.to_inspection_string();

        let lowered = if self.config.prefilter_enabled {
            Some(payload_str.to_ascii_lowercase())
        } else {
            None
        };

        // Bloom filter checks
        if let Some(bloom_manager) = &self.bloom_manager {
            if bloom_manager.is_enabled() {
                debug!("Running L7 bloom filter checks on unified request");

                // Check payload
                if bloom_manager.check_payload(&payload_str) {
                    debug!("Payload matched in bloom filter");
                    return InspectionResult {
                        blocked: true,
                        reason: format!("Blocked by L7 bloom filter: {} request", request.version),
                        layer: InspectionLayer::L7,
                    };
                }

                // Check URL
                if bloom_manager.check_url(&request.uri) {
                    debug!("URL matched in bloom filter");
                    return InspectionResult {
                        blocked: true,
                        reason: format!("Blocked by L7 bloom filter: URL {}", request.uri),
                        layer: InspectionLayer::L7,
                    };
                }

                // Check HTTP method
                if bloom_manager.check_http_method(&request.method) {
                    debug!("HTTP method matched in bloom filter");
                    return InspectionResult {
                        blocked: true,
                        reason: format!(
                            "Blocked by L7 bloom filter: HTTP method {}",
                            request.method
                        ),
                        layer: InspectionLayer::L7,
                    };
                }

                // Check user agent
                if let Some(user_agent) = request.user_agent() {
                    if bloom_manager.check_user_agent(user_agent) {
                        debug!("User-Agent matched in bloom filter");
                        return InspectionResult {
                            blocked: true,
                            reason: format!(
                                "Blocked by L7 bloom filter: User-Agent {}",
                                user_agent
                            ),
                            layer: InspectionLayer::L7,
                        };
                    }
                }

                if let Some(cookie_value) = request.get_header("cookie") {
                    if bloom_manager.check_cookie(cookie_value) {
                        debug!("Cookie matched in bloom filter");
                        return InspectionResult {
                            blocked: true,
                            reason: "Blocked by L7 bloom filter: cookie".to_string(),
                            layer: InspectionLayer::L7,
                        };
                    }
                }

                if !request.headers.is_empty() {
                    let header_pairs: Vec<(String, String)> = request
                        .headers
                        .iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect();
                    if bloom_manager.check_headers(&header_pairs) {
                        debug!("Headers matched in bloom filter");
                        return InspectionResult {
                            blocked: true,
                            reason: "Blocked by L7 bloom filter: headers".to_string(),
                            layer: InspectionLayer::L7,
                        };
                    }
                }
            }
        }

        // SQL Injection detection
        if self.config.enable_sql_injection_detection
            && self.should_run_sql_checks(&payload_str, lowered.as_deref())
        {
            if self.detect_sql_injection(&payload_str) {
                return InspectionResult {
                    blocked: true,
                    reason: format!(
                        "SQL injection attack detected in {} request",
                        request.version
                    ),
                    layer: InspectionLayer::L7,
                };
            }
        }

        // XSS detection
        if self.config.enable_xss_detection
            && self.should_run_xss_checks(&payload_str, lowered.as_deref())
        {
            if self.detect_xss(&payload_str) {
                return InspectionResult {
                    blocked: true,
                    reason: format!("XSS attack detected in {} request", request.version),
                    layer: InspectionLayer::L7,
                };
            }
        }

        // Path traversal detection
        if self.config.enable_path_traversal_detection
            && self.should_run_path_traversal_checks(&payload_str, lowered.as_deref())
        {
            if self.detect_path_traversal(&payload_str) {
                return InspectionResult {
                    blocked: true,
                    reason: format!(
                        "Path traversal attack detected in {} request",
                        request.version
                    ),
                    layer: InspectionLayer::L7,
                };
            }
        }

        // Command injection detection
        if self.config.enable_command_injection_detection
            && self.should_run_command_checks(&payload_str, lowered.as_deref())
        {
            if self.detect_command_injection(&payload_str) {
                return InspectionResult {
                    blocked: true,
                    reason: format!(
                        "Command injection attack detected in {} request",
                        request.version
                    ),
                    layer: InspectionLayer::L7,
                };
            }
        }

        debug!("{} request passed all checks", request.version);
        InspectionResult {
            blocked: false,
            reason: String::new(),
            layer: InspectionLayer::L7,
        }
    }

    fn detect_sql_injection(&self, payload: &str) -> bool {
        SQL_INJECTION_PATTERNS
            .iter()
            .any(|pattern| pattern.is_match(payload))
    }

    fn detect_xss(&self, payload: &str) -> bool {
        XSS_PATTERNS.iter().any(|pattern| pattern.is_match(payload))
    }

    fn detect_path_traversal(&self, payload: &str) -> bool {
        PATH_TRAVERSAL_PATTERNS
            .iter()
            .any(|pattern| pattern.is_match(payload))
    }

    fn detect_command_injection(&self, payload: &str) -> bool {
        COMMAND_INJECTION_PATTERNS
            .iter()
            .any(|pattern| pattern.is_match(payload))
    }

    fn should_run_sql_checks(&self, payload: &str, lowered: Option<&str>) -> bool {
        !self.config.prefilter_enabled
            || Self::contains_any(
                lowered.unwrap_or(payload),
                &[
                    "select", "union", "drop", "insert", "delete", " or ", " and ", "--", "/*",
                ],
            )
    }

    fn should_run_xss_checks(&self, payload: &str, lowered: Option<&str>) -> bool {
        !self.config.prefilter_enabled
            || Self::contains_any(
                lowered.unwrap_or(payload),
                &["<script", "javascript:", "onerror=", "onload=", "onclick="],
            )
    }

    fn should_run_path_traversal_checks(&self, payload: &str, lowered: Option<&str>) -> bool {
        !self.config.prefilter_enabled
            || Self::contains_any(lowered.unwrap_or(payload), &["../", "..\\", "%2e%2e"])
    }

    fn should_run_command_checks(&self, payload: &str, lowered: Option<&str>) -> bool {
        !self.config.prefilter_enabled
            || Self::contains_any(
                lowered.unwrap_or(payload),
                &[
                    ";", "|", "`", "whoami", "cat ", "rm ", "ls ", "curl ", "wget ",
                ],
            )
    }

    fn contains_any(haystack: &str, needles: &[&str]) -> bool {
        needles.iter().any(|needle| haystack.contains(needle))
    }

    #[allow(dead_code)]
    pub fn get_bloom_manager_mut(&mut self) -> Option<&mut L7BloomFilterManager> {
        self.bloom_manager.as_mut()
    }

    #[allow(dead_code)]
    pub fn enable_bloom_filter(&mut self, enabled: bool) {
        if let Some(ref mut bloom_manager) = self.bloom_manager {
            bloom_manager.set_enabled(enabled);
        }
    }

    #[allow(dead_code)]
    pub fn set_bloom_false_positive_verification(&mut self, verification: bool) {
        if let Some(ref mut bloom_manager) = self.bloom_manager {
            bloom_manager.set_false_positive_verification(verification);
        }
    }

    #[allow(dead_code)]
    pub fn get_bloom_statistics(&self) -> Option<crate::l7::bloom_filter::L7BloomStats> {
        self.bloom_manager.as_ref().map(|m| m.get_statistics())
    }

    #[allow(dead_code)]
    pub fn get_bloom_false_positive_stats(
        &self,
    ) -> Option<crate::l7::bloom_filter::L7FalsePositiveStats> {
        self.bloom_manager
            .as_ref()
            .map(|m| m.get_false_positive_stats())
    }
}
