use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SourceIpStrategy {
    #[default]
    Connection,
    #[serde(alias = "x_forwarded_for_any")]
    XForwardedForFirst,
    XForwardedForLast,
    XForwardedForLastButOne,
    XForwardedForLastButTwo,
    Header,
    ProxyProtocol,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HeaderOperationScope {
    #[default]
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HeaderOperationAction {
    #[default]
    Set,
    Add,
    Remove,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HeaderOperation {
    #[serde(default)]
    pub scope: HeaderOperationScope,
    #[serde(default)]
    pub action: HeaderOperationAction,
    #[serde(default)]
    pub header: String,
    #[serde(default)]
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    #[serde(default)]
    pub https_listen_addr: String,
    #[serde(default)]
    pub default_certificate_id: Option<i64>,
    #[serde(default)]
    pub listen_ipv6: bool,
    #[serde(default = "default_enable_http1_0")]
    pub enable_http1_0: bool,
    #[serde(default)]
    pub source_ip_strategy: SourceIpStrategy,
    #[serde(default)]
    pub custom_source_ip_header: String,
    #[serde(default)]
    pub http_to_https_redirect: bool,
    #[serde(default)]
    pub enable_hsts: bool,
    #[serde(default)]
    pub rewrite_host_enabled: bool,
    #[serde(default)]
    pub rewrite_host_value: String,
    #[serde(default = "default_add_x_forwarded_headers")]
    pub add_x_forwarded_headers: bool,
    #[serde(default)]
    pub rewrite_x_forwarded_for: bool,
    #[serde(default = "default_support_gzip")]
    pub support_gzip: bool,
    #[serde(default = "default_support_brotli")]
    pub support_brotli: bool,
    #[serde(default = "default_support_sse")]
    pub support_sse: bool,
    #[serde(default)]
    pub enable_ntlm: bool,
    #[serde(default)]
    pub fallback_self_signed_certificate: bool,
    #[serde(default = "default_ssl_protocols")]
    pub ssl_protocols: Vec<String>,
    #[serde(default)]
    pub ssl_ciphers: String,
    #[serde(default)]
    pub header_operations: Vec<HeaderOperation>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            https_listen_addr: "660".to_string(),
            default_certificate_id: None,
            listen_ipv6: false,
            enable_http1_0: default_enable_http1_0(),
            source_ip_strategy: SourceIpStrategy::default(),
            custom_source_ip_header: String::new(),
            http_to_https_redirect: true,
            enable_hsts: true,
            rewrite_host_enabled: true,
            rewrite_host_value: String::new(),
            add_x_forwarded_headers: default_add_x_forwarded_headers(),
            rewrite_x_forwarded_for: true,
            support_gzip: default_support_gzip(),
            support_brotli: default_support_brotli(),
            support_sse: default_support_sse(),
            enable_ntlm: true,
            fallback_self_signed_certificate: true,
            ssl_protocols: default_ssl_protocols(),
            ssl_ciphers: String::new(),
            header_operations: Vec::new(),
        }
    }
}

const fn default_enable_http1_0() -> bool {
    true
}

const fn default_add_x_forwarded_headers() -> bool {
    true
}

const fn default_support_gzip() -> bool {
    true
}

const fn default_support_brotli() -> bool {
    true
}

const fn default_support_sse() -> bool {
    true
}

pub fn default_ssl_protocols() -> Vec<String> {
    vec!["TLSv1.2".to_string(), "TLSv1.3".to_string()]
}
