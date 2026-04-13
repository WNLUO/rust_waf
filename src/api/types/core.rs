use super::rules::RuleResponseTemplatePayload;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub(crate) status: String,
    pub(crate) version: String,
    pub(crate) upstream_healthy: bool,
    pub(crate) upstream_last_check_at: Option<i64>,
    pub(crate) upstream_last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SettingsResponse {
    pub(crate) gateway_name: String,
    pub(crate) drop_unmatched_requests: bool,
    pub(crate) https_listen_addr: String,
    pub(crate) default_certificate_id: Option<i64>,
    pub(crate) api_endpoint: String,
    pub(crate) notes: String,
    pub(crate) safeline: SafeLineSettingsResponse,
}

#[derive(Debug, Serialize)]
pub struct L4ConfigResponse {
    pub(crate) ddos_protection_enabled: bool,
    pub(crate) advanced_ddos_enabled: bool,
    pub(crate) connection_rate_limit: usize,
    pub(crate) syn_flood_threshold: usize,
    pub(crate) max_tracked_ips: usize,
    pub(crate) max_blocked_ips: usize,
    pub(crate) state_ttl_secs: u64,
    pub(crate) bloom_filter_scale: f64,
    pub(crate) behavior_event_channel_capacity: usize,
    pub(crate) behavior_drop_critical_threshold: u64,
    pub(crate) behavior_fallback_ratio_percent: u8,
    pub(crate) behavior_overload_blocked_connections_threshold: u64,
    pub(crate) behavior_overload_active_connections_threshold: u64,
    pub(crate) behavior_normal_connection_budget_per_minute: u32,
    pub(crate) behavior_suspicious_connection_budget_per_minute: u32,
    pub(crate) behavior_high_risk_connection_budget_per_minute: u32,
    pub(crate) behavior_high_overload_budget_scale_percent: u8,
    pub(crate) behavior_critical_overload_budget_scale_percent: u8,
    pub(crate) behavior_high_overload_delay_ms: u64,
    pub(crate) behavior_critical_overload_delay_ms: u64,
    pub(crate) behavior_soft_delay_threshold_percent: u16,
    pub(crate) behavior_hard_delay_threshold_percent: u16,
    pub(crate) behavior_soft_delay_ms: u64,
    pub(crate) behavior_hard_delay_ms: u64,
    pub(crate) behavior_reject_threshold_percent: u16,
    pub(crate) behavior_critical_reject_threshold_percent: u16,
    pub(crate) runtime_enabled: bool,
    pub(crate) bloom_enabled: bool,
    pub(crate) bloom_false_positive_verification: bool,
    pub(crate) runtime_profile: String,
}

#[derive(Debug, Serialize)]
pub struct L7ConfigResponse {
    pub(crate) max_request_size: usize,
    pub(crate) real_ip_headers: Vec<String>,
    pub(crate) trusted_proxy_cidrs: Vec<String>,
    pub(crate) first_byte_timeout_ms: u64,
    pub(crate) read_idle_timeout_ms: u64,
    pub(crate) tls_handshake_timeout_ms: u64,
    pub(crate) proxy_connect_timeout_ms: u64,
    pub(crate) proxy_write_timeout_ms: u64,
    pub(crate) proxy_read_timeout_ms: u64,
    pub(crate) upstream_healthcheck_enabled: bool,
    pub(crate) upstream_healthcheck_interval_secs: u64,
    pub(crate) upstream_healthcheck_timeout_ms: u64,
    pub(crate) upstream_failure_mode: String,
    pub(crate) bloom_filter_scale: f64,
    pub(crate) http2_enabled: bool,
    pub(crate) http2_max_concurrent_streams: usize,
    pub(crate) http2_max_frame_size: usize,
    pub(crate) http2_enable_priorities: bool,
    pub(crate) http2_initial_window_size: u32,
    pub(crate) runtime_enabled: bool,
    pub(crate) bloom_enabled: bool,
    pub(crate) bloom_false_positive_verification: bool,
    pub(crate) runtime_profile: String,
    pub(crate) listen_addrs: Vec<String>,
    pub(crate) upstream_endpoint: String,
    pub(crate) http3_enabled: bool,
    pub(crate) http3_listen_addr: String,
    pub(crate) http3_max_concurrent_streams: usize,
    pub(crate) http3_idle_timeout_secs: u64,
    pub(crate) http3_mtu: usize,
    pub(crate) http3_max_frame_size: usize,
    pub(crate) http3_enable_connection_migration: bool,
    pub(crate) http3_qpack_table_size: usize,
    pub(crate) http3_certificate_path: String,
    pub(crate) http3_private_key_path: String,
    pub(crate) http3_enable_tls13: bool,
    pub(crate) cc_defense: CcDefenseConfigResponse,
    pub(crate) safeline_intercept: SafeLineInterceptConfigResponse,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSettingsResponse {
    pub(crate) enabled: bool,
    pub(crate) auto_sync_events: bool,
    pub(crate) auto_sync_blocked_ips_push: bool,
    pub(crate) auto_sync_blocked_ips_pull: bool,
    pub(crate) auto_sync_interval_secs: u64,
    pub(crate) base_url: String,
    pub(crate) api_token: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) verify_tls: bool,
    pub(crate) openapi_doc_path: String,
    pub(crate) auth_probe_path: String,
    pub(crate) site_list_path: String,
    pub(crate) event_list_path: String,
    pub(crate) blocklist_sync_path: String,
    pub(crate) blocklist_delete_path: String,
    pub(crate) blocklist_ip_group_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SettingsUpdateRequest {
    pub(crate) gateway_name: String,
    pub(crate) drop_unmatched_requests: bool,
    pub(crate) https_listen_addr: String,
    pub(crate) default_certificate_id: Option<i64>,
    pub(crate) api_endpoint: String,
    pub(crate) notes: String,
    pub(crate) safeline: SafeLineSettingsRequest,
}

#[derive(Debug, Deserialize)]
pub struct L4ConfigUpdateRequest {
    pub(crate) ddos_protection_enabled: bool,
    pub(crate) advanced_ddos_enabled: bool,
    pub(crate) connection_rate_limit: usize,
    pub(crate) syn_flood_threshold: usize,
    pub(crate) max_tracked_ips: usize,
    pub(crate) max_blocked_ips: usize,
    pub(crate) state_ttl_secs: u64,
    pub(crate) bloom_filter_scale: f64,
    pub(crate) behavior_event_channel_capacity: usize,
    pub(crate) behavior_drop_critical_threshold: u64,
    pub(crate) behavior_fallback_ratio_percent: u8,
    pub(crate) behavior_overload_blocked_connections_threshold: u64,
    pub(crate) behavior_overload_active_connections_threshold: u64,
    pub(crate) behavior_normal_connection_budget_per_minute: u32,
    pub(crate) behavior_suspicious_connection_budget_per_minute: u32,
    pub(crate) behavior_high_risk_connection_budget_per_minute: u32,
    pub(crate) behavior_high_overload_budget_scale_percent: u8,
    pub(crate) behavior_critical_overload_budget_scale_percent: u8,
    pub(crate) behavior_high_overload_delay_ms: u64,
    pub(crate) behavior_critical_overload_delay_ms: u64,
    pub(crate) behavior_soft_delay_threshold_percent: u16,
    pub(crate) behavior_hard_delay_threshold_percent: u16,
    pub(crate) behavior_soft_delay_ms: u64,
    pub(crate) behavior_hard_delay_ms: u64,
    pub(crate) behavior_reject_threshold_percent: u16,
    pub(crate) behavior_critical_reject_threshold_percent: u16,
}

#[derive(Debug, Deserialize)]
pub struct L7ConfigUpdateRequest {
    pub(crate) runtime_profile: String,
    pub(crate) max_request_size: usize,
    pub(crate) real_ip_headers: Vec<String>,
    pub(crate) trusted_proxy_cidrs: Vec<String>,
    pub(crate) first_byte_timeout_ms: u64,
    pub(crate) read_idle_timeout_ms: u64,
    pub(crate) tls_handshake_timeout_ms: u64,
    pub(crate) proxy_connect_timeout_ms: u64,
    pub(crate) proxy_write_timeout_ms: u64,
    pub(crate) proxy_read_timeout_ms: u64,
    pub(crate) upstream_healthcheck_enabled: bool,
    pub(crate) upstream_healthcheck_interval_secs: u64,
    pub(crate) upstream_healthcheck_timeout_ms: u64,
    pub(crate) upstream_failure_mode: String,
    pub(crate) bloom_filter_scale: f64,
    pub(crate) http2_enabled: bool,
    pub(crate) http2_max_concurrent_streams: usize,
    pub(crate) http2_max_frame_size: usize,
    pub(crate) http2_enable_priorities: bool,
    pub(crate) http2_initial_window_size: u32,
    pub(crate) bloom_enabled: bool,
    pub(crate) bloom_false_positive_verification: bool,
    pub(crate) listen_addrs: Vec<String>,
    pub(crate) upstream_endpoint: String,
    pub(crate) http3_enabled: bool,
    pub(crate) http3_max_concurrent_streams: usize,
    pub(crate) http3_idle_timeout_secs: u64,
    pub(crate) http3_mtu: usize,
    pub(crate) http3_max_frame_size: usize,
    pub(crate) http3_enable_connection_migration: bool,
    pub(crate) http3_qpack_table_size: usize,
    pub(crate) http3_certificate_path: String,
    pub(crate) http3_private_key_path: String,
    pub(crate) http3_enable_tls13: bool,
    #[serde(default)]
    pub(crate) cc_defense: Option<CcDefenseConfigRequest>,
    #[serde(default)]
    pub(crate) safeline_intercept: Option<SafeLineInterceptConfigRequest>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CcDefenseConfigResponse {
    pub(crate) enabled: bool,
    pub(crate) request_window_secs: u64,
    pub(crate) ip_challenge_threshold: u32,
    pub(crate) ip_block_threshold: u32,
    pub(crate) host_challenge_threshold: u32,
    pub(crate) host_block_threshold: u32,
    pub(crate) route_challenge_threshold: u32,
    pub(crate) route_block_threshold: u32,
    pub(crate) hot_path_challenge_threshold: u32,
    pub(crate) hot_path_block_threshold: u32,
    pub(crate) delay_threshold_percent: u8,
    pub(crate) delay_ms: u64,
    pub(crate) challenge_ttl_secs: u64,
    pub(crate) challenge_cookie_name: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CcDefenseConfigRequest {
    pub(crate) enabled: bool,
    pub(crate) request_window_secs: u64,
    pub(crate) ip_challenge_threshold: u32,
    pub(crate) ip_block_threshold: u32,
    pub(crate) host_challenge_threshold: u32,
    pub(crate) host_block_threshold: u32,
    pub(crate) route_challenge_threshold: u32,
    pub(crate) route_block_threshold: u32,
    pub(crate) hot_path_challenge_threshold: u32,
    pub(crate) hot_path_block_threshold: u32,
    pub(crate) delay_threshold_percent: u8,
    pub(crate) delay_ms: u64,
    pub(crate) challenge_ttl_secs: u64,
    pub(crate) challenge_cookie_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SafeLineInterceptConfigResponse {
    pub(crate) enabled: bool,
    pub(crate) action: String,
    pub(crate) match_mode: String,
    pub(crate) max_body_bytes: usize,
    pub(crate) block_duration_secs: u64,
    pub(crate) response_template: RuleResponseTemplatePayload,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SafeLineInterceptConfigRequest {
    pub(crate) enabled: bool,
    pub(crate) action: String,
    pub(crate) match_mode: String,
    pub(crate) max_body_bytes: usize,
    pub(crate) block_duration_secs: u64,
    pub(crate) response_template: RuleResponseTemplatePayload,
}

#[derive(Debug, Deserialize)]
pub struct SafeLineSettingsRequest {
    pub(crate) auto_sync_events: bool,
    pub(crate) auto_sync_blocked_ips_push: bool,
    pub(crate) auto_sync_blocked_ips_pull: bool,
    pub(crate) auto_sync_interval_secs: u64,
    pub(crate) base_url: String,
    pub(crate) api_token: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) verify_tls: bool,
}

#[derive(Debug, Deserialize)]
pub struct SafeLineTestRequest {
    pub(crate) base_url: String,
    pub(crate) api_token: String,
    pub(crate) username: String,
    pub(crate) password: String,
    pub(crate) verify_tls: bool,
    pub(crate) openapi_doc_path: String,
    pub(crate) auth_probe_path: String,
    pub(crate) site_list_path: String,
    pub(crate) event_list_path: String,
    pub(crate) blocklist_sync_path: String,
    pub(crate) blocklist_delete_path: String,
    pub(crate) blocklist_ip_group_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineTestResponse {
    pub(crate) status: String,
    pub(crate) message: String,
    pub(crate) openapi_doc_reachable: bool,
    pub(crate) openapi_doc_status: Option<u16>,
    pub(crate) authenticated: bool,
    pub(crate) auth_probe_status: Option<u16>,
}
