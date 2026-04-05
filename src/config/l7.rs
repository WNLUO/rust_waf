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
    pub prefilter_enabled: bool,
    pub enable_sql_injection_detection: bool,
    pub enable_xss_detection: bool,
    pub enable_path_traversal_detection: bool,
    pub enable_command_injection_detection: bool,
    pub http2_config: Http2Config,
    #[serde(default = "default_bloom_filter_scale")]
    pub bloom_filter_scale: f64,
}

const fn default_bloom_filter_scale() -> f64 {
    1.0
}

impl Default for L7Config {
    fn default() -> Self {
        Self {
            http_inspection_enabled: true,
            max_request_size: 8192,
            prefilter_enabled: true,
            enable_sql_injection_detection: true,
            enable_xss_detection: true,
            enable_path_traversal_detection: true,
            enable_command_injection_detection: true,
            http2_config: Http2Config::default(),
            bloom_filter_scale: default_bloom_filter_scale(),
        }
    }
}
