use super::HttpVersion;
use std::collections::HashMap;
use std::time::SystemTime;

/// 统一的HTTP请求抽象
///
/// 这个结构提供了协议无关的HTTP请求表示，
/// 使得L7检测逻辑可以无缝处理不同HTTP版本的流量
#[derive(Debug, Clone)]
pub struct UnifiedHttpRequest {
    /// HTTP协议版本
    pub version: HttpVersion,

    /// HTTP方法 (GET, POST, PUT, DELETE等)
    pub method: String,

    /// 请求URI
    pub uri: String,

    /// HTTP头部
    pub headers: HashMap<String, String>,

    /// 请求体
    pub body: Vec<u8>,

    /// HTTP/2.0流ID (仅HTTP/2.0有效)
    pub stream_id: Option<u32>,

    /// 流优先级 (0-255, 仅HTTP/2.0有效)
    pub priority: Option<u8>,

    /// 请求时间戳
    pub timestamp: u64,

    /// 客户端IP地址
    pub client_ip: Option<String>,

    /// 协议特定元数据
    pub metadata: HashMap<String, String>,
}

impl UnifiedHttpRequest {
    /// 创建新的统一HTTP请求
    pub fn new(version: HttpVersion, method: String, uri: String) -> Self {
        Self {
            version,
            method,
            uri,
            headers: HashMap::new(),
            body: Vec::new(),
            stream_id: None,
            priority: None,
            timestamp: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            client_ip: None,
            metadata: HashMap::new(),
        }
    }

    /// 添加HTTP头部
    pub fn add_header(&mut self, key: String, value: String) {
        // 统一头部名称为小写，便于后续处理
        let normalized_key = key.to_lowercase();
        self.headers.insert(normalized_key, value);
    }

    /// 获取HTTP头部
    pub fn get_header(&self, key: &str) -> Option<&String> {
        self.headers.get(&key.to_lowercase())
    }

    /// 添加元数据
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// 获取元数据
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// 获取请求的完整文本表示（用于L7检测）
    ///
    /// 将头部和请求体组合成文本格式，供现有的正则表达式检测使用
    pub fn to_inspection_string(&self) -> String {
        let mut inspection_text = String::new();

        // 添加方法和URI
        inspection_text.push_str(&format!("{} {}\n", self.method, self.uri));

        // 添加头部
        for (key, value) in &self.headers {
            inspection_text.push_str(&format!("{}: {}\n", key, value));
        }

        // 添加请求体
        if !self.body.is_empty() {
            inspection_text.push_str("\n");
            let body_str = String::from_utf8_lossy(&self.body);
            inspection_text.push_str(&body_str);
        }

        inspection_text
    }

    /// 获取请求体作为UTF-8字符串
    pub fn get_body_as_string(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    /// 获取Content-Length头部值
    pub fn content_length(&self) -> Option<usize> {
        self.get_header("content-length")
            .and_then(|v| v.parse().ok())
    }

    /// 获取Content-Type头部值
    pub fn content_type(&self) -> Option<&String> {
        self.get_header("content-type")
    }

    /// 获取User-Agent头部值
    pub fn user_agent(&self) -> Option<&String> {
        self.get_header("user-agent")
    }

    /// 检查是否为JSON请求
    pub fn is_json(&self) -> bool {
        self.content_type()
            .map(|ct| ct.contains("application/json"))
            .unwrap_or(false)
    }

    /// 检查是否为表单提交
    pub fn is_form(&self) -> bool {
        self.content_type()
            .map(|ct| {
                ct.contains("application/x-www-form-urlencoded") ||
                ct.contains("multipart/form-data")
            })
            .unwrap_or(false)
    }

    /// 设置HTTP/2.0流ID
    pub fn set_stream_id(&mut self, stream_id: u32) {
        self.stream_id = Some(stream_id);
    }

    /// 设置流优先级
    pub fn set_priority(&mut self, priority: u8) {
        self.priority = Some(priority);
    }

    /// 设置客户端IP
    pub fn set_client_ip(&mut self, ip: String) {
        self.client_ip = Some(ip);
    }

    /// 获取请求总大小（头部+请求体）
    pub fn total_size(&self) -> usize {
        let headers_size = self.headers.iter()
            .map(|(k, v)| k.len() + v.len() + 4) // 4 for ": " and "\n"
            .sum::<usize>();

        headers_size + self.body.len()
    }
}

impl Default for UnifiedHttpRequest {
    fn default() -> Self {
        Self::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_request_creation() {
        let request = UnifiedHttpRequest::new(
            HttpVersion::Http2_0,
            "POST".to_string(),
            "/api/data".to_string(),
        );

        assert_eq!(request.version, HttpVersion::Http2_0);
        assert_eq!(request.method, "POST");
        assert_eq!(request.uri, "/api/data");
    }

    #[test]
    fn test_header_handling() {
        let mut request = UnifiedHttpRequest::default();
        request.add_header("Content-Type".to_string(), "application/json".to_string());
        request.add_header("User-Agent".to_string(), "TestClient/1.0".to_string());

        assert_eq!(request.get_header("content-type"), Some(&"application/json".to_string()));
        assert_eq!(request.get_header("USER-AGENT"), Some(&"TestClient/1.0".to_string()));
    }

    #[test]
    fn test_inspection_string() {
        let mut request = UnifiedHttpRequest::default();
        request.add_header("Host".to_string(), "example.com".to_string());
        request.add_header("User-Agent".to_string(), "Test/1.0".to_string());
        request.body = b"test data".to_vec();

        let inspection_text = request.to_inspection_string();
        assert!(inspection_text.contains("GET /"));
        assert!(inspection_text.contains("host: example.com"));
        assert!(inspection_text.contains("test data"));
    }

    #[test]
    fn test_content_type_detection() {
        let mut request = UnifiedHttpRequest::default();
        request.add_header("Content-Type".to_string(), "application/json".to_string());

        assert!(request.is_json());
        assert!(!request.is_form());
    }

    #[test]
    fn test_stream_metadata() {
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http2_0,
            "GET".to_string(),
            "/api".to_string(),
        );

        request.set_stream_id(123);
        request.set_priority(5);

        assert_eq!(request.stream_id, Some(123));
        assert_eq!(request.priority, Some(5));
    }
}