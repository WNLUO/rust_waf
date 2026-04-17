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
    pub(crate) adaptive_protection: AdaptiveProtectionConfigResponse,
    pub(crate) https_listen_addr: String,
    pub(crate) default_certificate_id: Option<i64>,
    pub(crate) api_endpoint: String,
    pub(crate) notes: String,
    pub(crate) safeline: SafeLineSettingsResponse,
}

#[derive(Debug, Serialize)]
pub struct L4ConfigResponse {
    pub(crate) ddos_protection_enabled: bool,
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
    pub(crate) adaptive_managed_fields: bool,
    pub(crate) adaptive_runtime: AdaptiveProtectionRuntimeResponse,
    pub(crate) advanced_compatibility: L4AdvancedCompatibilityResponse,
}

#[derive(Debug, Serialize)]
pub struct L7ConfigResponse {
    pub(crate) max_request_size: usize,
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
    pub(crate) upstream_protocol_policy: String,
    pub(crate) upstream_http1_strict_mode: bool,
    pub(crate) upstream_http1_allow_connection_reuse: bool,
    pub(crate) reject_ambiguous_http1_requests: bool,
    pub(crate) reject_http1_transfer_encoding_requests: bool,
    pub(crate) reject_body_on_safe_http_methods: bool,
    pub(crate) reject_expect_100_continue: bool,
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
    pub(crate) adaptive_managed_fields: bool,
    pub(crate) adaptive_runtime: AdaptiveProtectionRuntimeResponse,
    pub(crate) advanced_compatibility: L7AdvancedCompatibilityResponse,
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
    pub(crate) slow_attack_defense: SlowAttackDefenseConfigResponse,
    pub(crate) safeline_intercept: SafeLineInterceptConfigResponse,
    pub(crate) auto_tuning: AutoTuningConfigResponse,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSettingsResponse {
    pub(crate) enabled: bool,
    pub(crate) auto_sync_events: bool,
    pub(crate) auto_sync_blocked_ips_push: bool,
    pub(crate) auto_sync_blocked_ips_pull: bool,
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
    pub(crate) adaptive_protection: AdaptiveProtectionConfigRequest,
    pub(crate) https_listen_addr: String,
    pub(crate) default_certificate_id: Option<i64>,
    pub(crate) api_endpoint: String,
    pub(crate) notes: String,
    pub(crate) safeline: SafeLineSettingsRequest,
}

#[derive(Debug, Deserialize)]
pub struct L4ConfigUpdateRequest {}

#[derive(Debug, Clone, Serialize)]
pub struct AdaptiveProtectionConfigResponse {}

#[derive(Debug, Clone, Deserialize)]
pub struct AdaptiveProtectionConfigRequest {}

#[derive(Debug, Clone, Serialize)]
pub struct AdaptiveProtectionRuntimeResponse {
    pub(crate) enabled: bool,
    pub(crate) mode: String,
    pub(crate) goal: String,
    pub(crate) system_pressure: String,
    pub(crate) reasons: Vec<String>,
    pub(crate) identity_pressure_percent: f64,
    pub(crate) l7_friction_pressure_percent: f64,
    pub(crate) slow_attack_pressure_percent: f64,
    pub(crate) l4: AdaptiveProtectionL4RuntimeResponse,
    pub(crate) l7: AdaptiveProtectionL7RuntimeResponse,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdaptiveProtectionL4RuntimeResponse {
    pub(crate) normal_connection_budget_per_minute: u32,
    pub(crate) suspicious_connection_budget_per_minute: u32,
    pub(crate) high_risk_connection_budget_per_minute: u32,
    pub(crate) soft_delay_ms: u64,
    pub(crate) hard_delay_ms: u64,
    pub(crate) high_overload_delay_ms: u64,
    pub(crate) critical_overload_delay_ms: u64,
    pub(crate) reject_threshold_percent: u16,
    pub(crate) critical_reject_threshold_percent: u16,
    pub(crate) emergency_reject_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AdaptiveProtectionL7RuntimeResponse {
    pub(crate) request_window_secs: u64,
    pub(crate) delay_ms: u64,
    pub(crate) route_challenge_threshold: u32,
    pub(crate) route_block_threshold: u32,
    pub(crate) ip_challenge_threshold: u32,
    pub(crate) ip_block_threshold: u32,
    pub(crate) challenge_enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct L4AdvancedCompatibilityResponse {
    pub(crate) persisted_behavior_event_channel_capacity: usize,
    pub(crate) persisted_behavior_drop_critical_threshold: u64,
    pub(crate) persisted_behavior_fallback_ratio_percent: u8,
    pub(crate) persisted_behavior_overload_blocked_connections_threshold: u64,
    pub(crate) persisted_behavior_overload_active_connections_threshold: u64,
    pub(crate) persisted_behavior_normal_connection_budget_per_minute: u32,
    pub(crate) persisted_behavior_suspicious_connection_budget_per_minute: u32,
    pub(crate) persisted_behavior_high_risk_connection_budget_per_minute: u32,
    pub(crate) persisted_behavior_high_overload_budget_scale_percent: u8,
    pub(crate) persisted_behavior_critical_overload_budget_scale_percent: u8,
    pub(crate) persisted_behavior_high_overload_delay_ms: u64,
    pub(crate) persisted_behavior_critical_overload_delay_ms: u64,
    pub(crate) persisted_behavior_soft_delay_threshold_percent: u16,
    pub(crate) persisted_behavior_hard_delay_threshold_percent: u16,
    pub(crate) persisted_behavior_soft_delay_ms: u64,
    pub(crate) persisted_behavior_hard_delay_ms: u64,
    pub(crate) persisted_behavior_reject_threshold_percent: u16,
    pub(crate) persisted_behavior_critical_reject_threshold_percent: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct L7AdvancedCompatibilityResponse {
    pub(crate) persisted_cc_defense: CcDefenseConfigResponse,
    pub(crate) persisted_auto_tuning: AutoTuningConfigResponse,
}

#[derive(Debug, Clone, Serialize)]
pub struct SlowAttackDefenseConfigResponse {
    pub(crate) enabled: bool,
    pub(crate) header_min_bytes_per_sec: u32,
    pub(crate) body_min_bytes_per_sec: u32,
    pub(crate) idle_keepalive_timeout_ms: u64,
    pub(crate) event_window_secs: u64,
    pub(crate) max_events_per_window: u32,
    pub(crate) block_duration_secs: u64,
}

#[derive(Debug, Deserialize)]
pub struct L7ConfigUpdateRequest {
    pub(crate) upstream_healthcheck_enabled: bool,
    pub(crate) upstream_failure_mode: String,
    pub(crate) upstream_protocol_policy: String,
    pub(crate) upstream_http1_strict_mode: bool,
    pub(crate) upstream_http1_allow_connection_reuse: bool,
    pub(crate) reject_ambiguous_http1_requests: bool,
    pub(crate) reject_http1_transfer_encoding_requests: bool,
    pub(crate) reject_body_on_safe_http_methods: bool,
    pub(crate) reject_expect_100_continue: bool,
    pub(crate) http2_enabled: bool,
    pub(crate) bloom_enabled: bool,
    pub(crate) listen_addrs: Vec<String>,
    pub(crate) upstream_endpoint: String,
    pub(crate) http3_enabled: bool,
    pub(crate) http3_certificate_path: String,
    pub(crate) http3_private_key_path: String,
    pub(crate) http3_enable_tls13: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutoTuningConfigResponse {
    pub(crate) mode: String,
    pub(crate) intent: String,
    pub(crate) runtime_adjust_enabled: bool,
    pub(crate) bootstrap_secs: u64,
    pub(crate) control_interval_secs: u64,
    pub(crate) cooldown_secs: u64,
    pub(crate) max_step_percent: u8,
    pub(crate) rollback_window_minutes: u64,
    pub(crate) pinned_fields: Vec<String>,
    pub(crate) slo: AutoSloTargetsResponse,
}

#[derive(Debug, Clone, Serialize)]
pub struct AutoSloTargetsResponse {
    pub(crate) tls_handshake_timeout_rate_percent: f64,
    pub(crate) bucket_reject_rate_percent: f64,
    pub(crate) p95_proxy_latency_ms: u64,
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
    pub(crate) static_request_weight_percent: u8,
    pub(crate) page_subresource_weight_percent: u8,
    pub(crate) page_load_grace_secs: u64,
    pub(crate) hard_route_block_multiplier: u8,
    pub(crate) hard_host_block_multiplier: u8,
    pub(crate) hard_ip_block_multiplier: u8,
    pub(crate) hard_hot_path_block_multiplier: u8,
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
