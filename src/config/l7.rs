use super::{RuleResponseBodySource, RuleResponseHeader, RuleResponseTemplate};
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
            enabled: true,
            max_concurrent_streams: 100,
            max_frame_size: 16384,
            enable_priorities: true,
            initial_window_size: 65535,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L7Config {
    #[serde(
        default = "default_http_entry_enabled",
        alias = "http_inspection_enabled"
    )]
    pub http_entry_enabled: bool,
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
    #[serde(default = "default_upstream_healthcheck_enabled")]
    pub upstream_healthcheck_enabled: bool,
    #[serde(default = "default_upstream_healthcheck_interval_secs")]
    pub upstream_healthcheck_interval_secs: u64,
    #[serde(default = "default_upstream_healthcheck_timeout_ms")]
    pub upstream_healthcheck_timeout_ms: u64,
    #[serde(default)]
    pub upstream_failure_mode: UpstreamFailureMode,
    #[serde(default)]
    pub upstream_protocol_policy: UpstreamProtocolPolicy,
    #[serde(default = "default_upstream_http1_strict_mode")]
    pub upstream_http1_strict_mode: bool,
    #[serde(default = "default_upstream_http1_allow_connection_reuse")]
    pub upstream_http1_allow_connection_reuse: bool,
    #[serde(default = "default_reject_ambiguous_http1_requests")]
    pub reject_ambiguous_http1_requests: bool,
    #[serde(default = "default_reject_http1_transfer_encoding_requests")]
    pub reject_http1_transfer_encoding_requests: bool,
    #[serde(default = "default_reject_body_on_safe_http_methods")]
    pub reject_body_on_safe_http_methods: bool,
    #[serde(default = "default_reject_expect_100_continue")]
    pub reject_expect_100_continue: bool,
    #[serde(default = "default_bloom_filter_scale")]
    pub bloom_filter_scale: f64,
    #[serde(default)]
    pub cc_defense: CcDefenseConfig,
    #[serde(default)]
    pub slow_attack_defense: SlowAttackDefenseConfig,
    #[serde(default)]
    pub safeline_intercept: SafeLineInterceptConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CcDefenseConfig {
    #[serde(default = "default_cc_defense_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cc_request_window_secs")]
    pub request_window_secs: u64,
    #[serde(default = "default_cc_ip_challenge_threshold")]
    pub ip_challenge_threshold: u32,
    #[serde(default = "default_cc_ip_block_threshold")]
    pub ip_block_threshold: u32,
    #[serde(default = "default_cc_host_challenge_threshold")]
    pub host_challenge_threshold: u32,
    #[serde(default = "default_cc_host_block_threshold")]
    pub host_block_threshold: u32,
    #[serde(default = "default_cc_route_challenge_threshold")]
    pub route_challenge_threshold: u32,
    #[serde(default = "default_cc_route_block_threshold")]
    pub route_block_threshold: u32,
    #[serde(default = "default_cc_hot_path_challenge_threshold")]
    pub hot_path_challenge_threshold: u32,
    #[serde(default = "default_cc_hot_path_block_threshold")]
    pub hot_path_block_threshold: u32,
    #[serde(default = "default_cc_delay_threshold_percent")]
    pub delay_threshold_percent: u8,
    #[serde(default = "default_cc_delay_ms")]
    pub delay_ms: u64,
    #[serde(default = "default_cc_challenge_ttl_secs")]
    pub challenge_ttl_secs: u64,
    #[serde(default = "default_cc_cookie_name")]
    pub challenge_cookie_name: String,
    #[serde(default = "default_cc_static_request_weight_percent")]
    pub static_request_weight_percent: u8,
    #[serde(default = "default_cc_page_subresource_weight_percent")]
    pub page_subresource_weight_percent: u8,
    #[serde(default = "default_cc_page_load_grace_secs")]
    pub page_load_grace_secs: u64,
    #[serde(default = "default_cc_hard_route_block_multiplier")]
    pub hard_route_block_multiplier: u8,
    #[serde(default = "default_cc_hard_host_block_multiplier")]
    pub hard_host_block_multiplier: u8,
    #[serde(default = "default_cc_hard_ip_block_multiplier")]
    pub hard_ip_block_multiplier: u8,
    #[serde(default = "default_cc_hard_hot_path_block_multiplier")]
    pub hard_hot_path_block_multiplier: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlowAttackDefenseConfig {
    #[serde(default = "default_slow_attack_defense_enabled")]
    pub enabled: bool,
    #[serde(default = "default_slow_attack_header_min_bytes_per_sec")]
    pub header_min_bytes_per_sec: u32,
    #[serde(default = "default_slow_attack_body_min_bytes_per_sec")]
    pub body_min_bytes_per_sec: u32,
    #[serde(default = "default_slow_attack_idle_keepalive_timeout_ms")]
    pub idle_keepalive_timeout_ms: u64,
    #[serde(default = "default_slow_attack_event_window_secs")]
    pub event_window_secs: u64,
    #[serde(default = "default_slow_attack_max_events_per_window")]
    pub max_events_per_window: u32,
    #[serde(default = "default_slow_attack_block_duration_secs")]
    pub block_duration_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeLineInterceptConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub action: SafeLineInterceptAction,
    #[serde(default)]
    pub match_mode: SafeLineInterceptMatchMode,
    #[serde(default = "default_safeline_intercept_max_body_bytes")]
    pub max_body_bytes: usize,
    #[serde(default = "default_safeline_intercept_block_duration_secs")]
    pub block_duration_secs: u64,
    #[serde(default = "default_safeline_intercept_response_template")]
    pub response_template: RuleResponseTemplate,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SafeLineInterceptAction {
    #[default]
    Pass,
    Replace,
    Drop,
    ReplaceAndBlockIp,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SafeLineInterceptMatchMode {
    #[default]
    Strict,
    Relaxed,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamFailureMode {
    #[default]
    FailOpen,
    FailClose,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamProtocolPolicy {
    #[default]
    Http2Preferred,
    Auto,
    Http1Only,
    Http2Only,
}

pub fn default_real_ip_headers() -> Vec<String> {
    vec![
        "cf-connecting-ip".to_string(),
        "x-forwarded-for".to_string(),
        "x-real-ip".to_string(),
    ]
}

const fn default_http_entry_enabled() -> bool {
    true
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

const fn default_upstream_healthcheck_enabled() -> bool {
    true
}

const fn default_upstream_healthcheck_interval_secs() -> u64 {
    5
}

const fn default_upstream_healthcheck_timeout_ms() -> u64 {
    1_000
}

const fn default_upstream_http1_strict_mode() -> bool {
    true
}

const fn default_upstream_http1_allow_connection_reuse() -> bool {
    false
}

const fn default_reject_ambiguous_http1_requests() -> bool {
    true
}

const fn default_reject_http1_transfer_encoding_requests() -> bool {
    true
}

const fn default_reject_body_on_safe_http_methods() -> bool {
    true
}

const fn default_reject_expect_100_continue() -> bool {
    true
}

const fn default_bloom_filter_scale() -> f64 {
    1.0
}

const fn default_cc_defense_enabled() -> bool {
    true
}

const fn default_cc_request_window_secs() -> u64 {
    10
}

const fn default_cc_ip_challenge_threshold() -> u32 {
    60
}

const fn default_cc_ip_block_threshold() -> u32 {
    120
}

const fn default_cc_host_challenge_threshold() -> u32 {
    48
}

const fn default_cc_host_block_threshold() -> u32 {
    96
}

const fn default_cc_route_challenge_threshold() -> u32 {
    24
}

const fn default_cc_route_block_threshold() -> u32 {
    48
}

const fn default_cc_hot_path_challenge_threshold() -> u32 {
    800
}

const fn default_cc_hot_path_block_threshold() -> u32 {
    1_600
}

const fn default_cc_delay_threshold_percent() -> u8 {
    70
}

const fn default_cc_delay_ms() -> u64 {
    150
}

const fn default_cc_challenge_ttl_secs() -> u64 {
    1_800
}

fn default_cc_cookie_name() -> String {
    "rwaf_cc".to_string()
}

const fn default_cc_static_request_weight_percent() -> u8 {
    20
}

const fn default_cc_page_subresource_weight_percent() -> u8 {
    10
}

const fn default_cc_page_load_grace_secs() -> u64 {
    8
}

const fn default_cc_hard_route_block_multiplier() -> u8 {
    4
}

const fn default_cc_hard_host_block_multiplier() -> u8 {
    4
}

const fn default_cc_hard_ip_block_multiplier() -> u8 {
    4
}

const fn default_cc_hard_hot_path_block_multiplier() -> u8 {
    3
}

const fn default_slow_attack_defense_enabled() -> bool {
    true
}

const fn default_slow_attack_header_min_bytes_per_sec() -> u32 {
    128
}

const fn default_slow_attack_body_min_bytes_per_sec() -> u32 {
    256
}

const fn default_slow_attack_idle_keepalive_timeout_ms() -> u64 {
    15_000
}

const fn default_slow_attack_event_window_secs() -> u64 {
    300
}

const fn default_slow_attack_max_events_per_window() -> u32 {
    4
}

const fn default_slow_attack_block_duration_secs() -> u64 {
    900
}

const fn default_safeline_intercept_max_body_bytes() -> usize {
    32 * 1024
}

const fn default_safeline_intercept_block_duration_secs() -> u64 {
    600
}

fn default_safeline_intercept_response_template() -> RuleResponseTemplate {
    RuleResponseTemplate {
        status_code: 403,
        content_type: "text/html; charset=utf-8".to_string(),
        body_source: RuleResponseBodySource::InlineText,
        gzip: false,
        body_text: concat!(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
            "<title>Request Blocked</title></head><body>",
            "<h1>Request Blocked</h1>",
            "<p>Your request was rejected by the upstream security policy.</p>",
            "</body></html>"
        )
        .to_string(),
        body_file_path: String::new(),
        headers: vec![RuleResponseHeader {
            key: "cache-control".to_string(),
            value: "no-store".to_string(),
        }],
    }
}

impl Default for SafeLineInterceptConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action: SafeLineInterceptAction::Drop,
            match_mode: SafeLineInterceptMatchMode::Strict,
            max_body_bytes: default_safeline_intercept_max_body_bytes(),
            block_duration_secs: default_safeline_intercept_block_duration_secs(),
            response_template: default_safeline_intercept_response_template(),
        }
    }
}

impl Default for CcDefenseConfig {
    fn default() -> Self {
        Self {
            enabled: default_cc_defense_enabled(),
            request_window_secs: default_cc_request_window_secs(),
            ip_challenge_threshold: default_cc_ip_challenge_threshold(),
            ip_block_threshold: default_cc_ip_block_threshold(),
            host_challenge_threshold: default_cc_host_challenge_threshold(),
            host_block_threshold: default_cc_host_block_threshold(),
            route_challenge_threshold: default_cc_route_challenge_threshold(),
            route_block_threshold: default_cc_route_block_threshold(),
            hot_path_challenge_threshold: default_cc_hot_path_challenge_threshold(),
            hot_path_block_threshold: default_cc_hot_path_block_threshold(),
            delay_threshold_percent: default_cc_delay_threshold_percent(),
            delay_ms: default_cc_delay_ms(),
            challenge_ttl_secs: default_cc_challenge_ttl_secs(),
            challenge_cookie_name: default_cc_cookie_name(),
            static_request_weight_percent: default_cc_static_request_weight_percent(),
            page_subresource_weight_percent: default_cc_page_subresource_weight_percent(),
            page_load_grace_secs: default_cc_page_load_grace_secs(),
            hard_route_block_multiplier: default_cc_hard_route_block_multiplier(),
            hard_host_block_multiplier: default_cc_hard_host_block_multiplier(),
            hard_ip_block_multiplier: default_cc_hard_ip_block_multiplier(),
            hard_hot_path_block_multiplier: default_cc_hard_hot_path_block_multiplier(),
        }
    }
}

impl Default for SlowAttackDefenseConfig {
    fn default() -> Self {
        Self {
            enabled: default_slow_attack_defense_enabled(),
            header_min_bytes_per_sec: default_slow_attack_header_min_bytes_per_sec(),
            body_min_bytes_per_sec: default_slow_attack_body_min_bytes_per_sec(),
            idle_keepalive_timeout_ms: default_slow_attack_idle_keepalive_timeout_ms(),
            event_window_secs: default_slow_attack_event_window_secs(),
            max_events_per_window: default_slow_attack_max_events_per_window(),
            block_duration_secs: default_slow_attack_block_duration_secs(),
        }
    }
}

impl Default for L7Config {
    fn default() -> Self {
        Self {
            http_entry_enabled: default_http_entry_enabled(),
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
            upstream_healthcheck_enabled: default_upstream_healthcheck_enabled(),
            upstream_healthcheck_interval_secs: default_upstream_healthcheck_interval_secs(),
            upstream_healthcheck_timeout_ms: default_upstream_healthcheck_timeout_ms(),
            upstream_failure_mode: UpstreamFailureMode::default(),
            upstream_protocol_policy: UpstreamProtocolPolicy::default(),
            upstream_http1_strict_mode: default_upstream_http1_strict_mode(),
            upstream_http1_allow_connection_reuse: default_upstream_http1_allow_connection_reuse(),
            reject_ambiguous_http1_requests: default_reject_ambiguous_http1_requests(),
            reject_http1_transfer_encoding_requests:
                default_reject_http1_transfer_encoding_requests(),
            reject_body_on_safe_http_methods: default_reject_body_on_safe_http_methods(),
            reject_expect_100_continue: default_reject_expect_100_continue(),
            bloom_filter_scale: default_bloom_filter_scale(),
            cc_defense: CcDefenseConfig::default(),
            slow_attack_defense: SlowAttackDefenseConfig::default(),
            safeline_intercept: SafeLineInterceptConfig::default(),
        }
    }
}
