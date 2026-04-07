use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Http2Config {
    pub enabled: bool,
    pub max_concurrent_streams: usize,
    pub max_frame_size: usize,
    pub enable_priorities: bool,
    pub initial_window_size: u32,
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            enabled: false, // 默认关闭HTTP/2.0，需要显式启用
            max_concurrent_streams: 100,
            max_frame_size: 16384,
            enable_priorities: true,
            initial_window_size: 65535,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7Config {
    pub http_inspection_enabled: bool,
    pub max_request_size: usize,
    pub http2_config: Http2Config,
    #[serde(default = "default_real_ip_headers")]
    pub real_ip_headers: Vec<String>,
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
    #[serde(default = "default_first_byte_timeout_ms")]
    pub first_byte_timeout_ms: u64,
    #[serde(default = "default_read_idle_timeout_ms")]
    pub read_idle_timeout_ms: u64,
    #[serde(default = "default_tls_handshake_timeout_ms")]
    pub tls_handshake_timeout_ms: u64,
    #[serde(default = "default_proxy_connect_timeout_ms")]
    pub proxy_connect_timeout_ms: u64,
    #[serde(default = "default_proxy_write_timeout_ms")]
    pub proxy_write_timeout_ms: u64,
    #[serde(default = "default_proxy_read_timeout_ms")]
    pub proxy_read_timeout_ms: u64,
    #[serde(default)]
    pub upstream_healthcheck_enabled: bool,
    #[serde(default = "default_upstream_healthcheck_interval_secs")]
    pub upstream_healthcheck_interval_secs: u64,
    #[serde(default = "default_upstream_healthcheck_timeout_ms")]
    pub upstream_healthcheck_timeout_ms: u64,
    #[serde(default)]
    pub upstream_failure_mode: UpstreamFailureMode,
    #[serde(default = "default_bloom_filter_scale")]
    pub bloom_filter_scale: f64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamFailureMode {
    #[default]
    FailOpen,
    FailClose,
}

pub fn default_real_ip_headers() -> Vec<String> {
    vec![
        "cf-connecting-ip".to_string(),
        "x-forwarded-for".to_string(),
        "x-real-ip".to_string(),
    ]
}

const fn default_first_byte_timeout_ms() -> u64 {
    2_000
}

const fn default_read_idle_timeout_ms() -> u64 {
    5_000
}

const fn default_tls_handshake_timeout_ms() -> u64 {
    3_000
}

const fn default_proxy_connect_timeout_ms() -> u64 {
    1_500
}

const fn default_proxy_write_timeout_ms() -> u64 {
    3_000
}

const fn default_proxy_read_timeout_ms() -> u64 {
    10_000
}

const fn default_upstream_healthcheck_interval_secs() -> u64 {
    5
}

const fn default_upstream_healthcheck_timeout_ms() -> u64 {
    1_000
}

const fn default_bloom_filter_scale() -> f64 {
    1.0
}

impl Default for L7Config {
    fn default() -> Self {
        Self {
            http_inspection_enabled: true,
            max_request_size: 8192,
            http2_config: Http2Config::default(),
            real_ip_headers: default_real_ip_headers(),
            trusted_proxy_cidrs: Vec::new(),
            first_byte_timeout_ms: default_first_byte_timeout_ms(),
            read_idle_timeout_ms: default_read_idle_timeout_ms(),
            tls_handshake_timeout_ms: default_tls_handshake_timeout_ms(),
            proxy_connect_timeout_ms: default_proxy_connect_timeout_ms(),
            proxy_write_timeout_ms: default_proxy_write_timeout_ms(),
            proxy_read_timeout_ms: default_proxy_read_timeout_ms(),
            upstream_healthcheck_enabled: true,
            upstream_healthcheck_interval_secs: default_upstream_healthcheck_interval_secs(),
            upstream_healthcheck_timeout_ms: default_upstream_healthcheck_timeout_ms(),
            upstream_failure_mode: UpstreamFailureMode::default(),
            bloom_filter_scale: default_bloom_filter_scale(),
        }
    }
}
