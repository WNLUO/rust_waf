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
    pub(crate) auto_refresh_seconds: u32,
    pub(crate) https_listen_addr: String,
    pub(crate) default_certificate_id: Option<i64>,
    pub(crate) upstream_endpoint: String,
    pub(crate) api_endpoint: String,
    pub(crate) notification_level: String,
    pub(crate) retain_days: u32,
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
    pub(crate) auto_refresh_seconds: u32,
    pub(crate) https_listen_addr: String,
    pub(crate) default_certificate_id: Option<i64>,
    pub(crate) upstream_endpoint: String,
    pub(crate) api_endpoint: String,
    pub(crate) notification_level: String,
    pub(crate) retain_days: u32,
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

#[derive(Debug, Serialize)]
pub struct SafeLineSitesResponse {
    pub(crate) total: u32,
    pub(crate) cached_at: Option<i64>,
    pub(crate) sites: Vec<SafeLineSiteResponse>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSiteResponse {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) domain: String,
    pub(crate) status: String,
    pub(crate) enabled: Option<bool>,
    pub(crate) server_names: Vec<String>,
    pub(crate) ports: Vec<String>,
    pub(crate) ssl_ports: Vec<String>,
    pub(crate) upstreams: Vec<String>,
    pub(crate) ssl_enabled: bool,
    pub(crate) cert_id: Option<i64>,
    pub(crate) cert_type: Option<i64>,
    pub(crate) cert_filename: Option<String>,
    pub(crate) key_filename: Option<String>,
    pub(crate) health_check: Option<bool>,
    pub(crate) raw: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct SafeLineMappingsResponse {
    pub(crate) total: u32,
    pub(crate) mappings: Vec<SafeLineMappingResponse>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineMappingResponse {
    pub(crate) id: i64,
    pub(crate) safeline_site_id: String,
    pub(crate) safeline_site_name: String,
    pub(crate) safeline_site_domain: String,
    pub(crate) local_alias: String,
    pub(crate) enabled: bool,
    pub(crate) is_primary: bool,
    pub(crate) notes: String,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct SafeLineMappingsUpdateRequest {
    pub(crate) mappings: Vec<SafeLineMappingUpsertRequest>,
}

#[derive(Debug, Deserialize)]
pub struct SafeLineMappingUpsertRequest {
    pub(crate) safeline_site_id: String,
    pub(crate) safeline_site_name: String,
    pub(crate) safeline_site_domain: String,
    pub(crate) local_alias: String,
    pub(crate) enabled: bool,
    pub(crate) is_primary: bool,
    pub(crate) notes: String,
}

#[derive(Debug, Serialize)]
pub struct LocalSitesResponse {
    pub(crate) total: u32,
    pub(crate) sites: Vec<LocalSiteResponse>,
}

#[derive(Debug, Serialize)]
pub struct LocalSiteResponse {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) primary_hostname: String,
    pub(crate) hostnames: Vec<String>,
    pub(crate) listen_ports: Vec<String>,
    pub(crate) upstreams: Vec<String>,
    pub(crate) enabled: bool,
    pub(crate) tls_enabled: bool,
    pub(crate) local_certificate_id: Option<i64>,
    pub(crate) source: String,
    pub(crate) sync_mode: String,
    pub(crate) notes: String,
    pub(crate) last_synced_at: Option<i64>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct LocalSiteUpsertRequest {
    pub(crate) name: String,
    pub(crate) primary_hostname: String,
    pub(crate) hostnames: Vec<String>,
    pub(crate) listen_ports: Vec<String>,
    pub(crate) upstreams: Vec<String>,
    pub(crate) enabled: bool,
    pub(crate) tls_enabled: bool,
    pub(crate) local_certificate_id: Option<i64>,
    pub(crate) source: String,
    pub(crate) sync_mode: String,
    pub(crate) notes: String,
    pub(crate) last_synced_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct LocalCertificatesResponse {
    pub(crate) total: u32,
    pub(crate) certificates: Vec<LocalCertificateResponse>,
}

#[derive(Debug, Serialize)]
pub struct LocalCertificateResponse {
    pub(crate) id: i64,
    pub(crate) name: String,
    pub(crate) domains: Vec<String>,
    pub(crate) issuer: String,
    pub(crate) valid_from: Option<i64>,
    pub(crate) valid_to: Option<i64>,
    pub(crate) source_type: String,
    pub(crate) provider_remote_id: Option<String>,
    pub(crate) trusted: bool,
    pub(crate) expired: bool,
    pub(crate) notes: String,
    pub(crate) last_synced_at: Option<i64>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct LocalCertificateUpsertRequest {
    pub(crate) name: String,
    pub(crate) domains: Vec<String>,
    pub(crate) issuer: String,
    pub(crate) valid_from: Option<i64>,
    pub(crate) valid_to: Option<i64>,
    pub(crate) source_type: String,
    pub(crate) provider_remote_id: Option<String>,
    pub(crate) trusted: bool,
    pub(crate) expired: bool,
    pub(crate) notes: String,
    pub(crate) last_synced_at: Option<i64>,
    pub(crate) certificate_pem: Option<String>,
    pub(crate) private_key_pem: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct GeneratedLocalCertificateRequest {
    pub(crate) name: Option<String>,
    pub(crate) domains: Vec<String>,
    pub(crate) notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SiteSyncLinksResponse {
    pub(crate) total: u32,
    pub(crate) links: Vec<SiteSyncLinkResponse>,
}

#[derive(Debug, Serialize)]
pub struct SiteSyncLinkResponse {
    pub(crate) id: i64,
    pub(crate) local_site_id: i64,
    pub(crate) provider: String,
    pub(crate) remote_site_id: String,
    pub(crate) remote_site_name: String,
    pub(crate) remote_cert_id: Option<String>,
    pub(crate) sync_mode: String,
    pub(crate) last_local_hash: Option<String>,
    pub(crate) last_remote_hash: Option<String>,
    pub(crate) last_error: Option<String>,
    pub(crate) last_synced_at: Option<i64>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct SiteSyncLinkUpsertRequest {
    pub(crate) local_site_id: i64,
    pub(crate) provider: String,
    pub(crate) remote_site_id: String,
    pub(crate) remote_site_name: String,
    pub(crate) remote_cert_id: Option<String>,
    pub(crate) sync_mode: String,
    pub(crate) last_local_hash: Option<String>,
    pub(crate) last_remote_hash: Option<String>,
    pub(crate) last_error: Option<String>,
    pub(crate) last_synced_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub(super) struct LocalCertificateSecretDraft {
    pub(super) certificate_pem: String,
    pub(super) private_key_pem: String,
}

#[derive(Debug, Clone)]
pub(super) struct GeneratedLocalCertificateDraft {
    pub(super) certificate: crate::storage::LocalCertificateUpsert,
    pub(super) secret: LocalCertificateSecretDraft,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSitesPullResponse {
    pub(crate) success: bool,
    pub(crate) imported_sites: u32,
    pub(crate) updated_sites: u32,
    pub(crate) imported_certificates: u32,
    pub(crate) updated_certificates: u32,
    pub(crate) linked_sites: u32,
    pub(crate) skipped_sites: u32,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSitesPushResponse {
    pub(crate) success: bool,
    pub(crate) created_sites: u32,
    pub(crate) updated_sites: u32,
    pub(crate) created_certificates: u32,
    pub(crate) reused_certificates: u32,
    pub(crate) skipped_sites: u32,
    pub(crate) failed_sites: u32,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineEventSyncResponse {
    pub(crate) success: bool,
    pub(crate) imported: u32,
    pub(crate) skipped: u32,
    pub(crate) last_cursor: Option<i64>,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSyncStateResponse {
    pub(crate) resource: String,
    pub(crate) last_cursor: Option<i64>,
    pub(crate) last_success_at: Option<i64>,
    pub(crate) last_imported_count: u32,
    pub(crate) last_skipped_count: u32,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct SafeLineSyncOverviewResponse {
    pub(crate) events: Option<SafeLineSyncStateResponse>,
    pub(crate) blocked_ips_push: Option<SafeLineSyncStateResponse>,
    pub(crate) blocked_ips_pull: Option<SafeLineSyncStateResponse>,
    pub(crate) blocked_ips_delete: Option<SafeLineSyncStateResponse>,
}

#[derive(Debug, Serialize)]
pub struct SafeLineBlocklistSyncResponse {
    pub(crate) success: bool,
    pub(crate) synced: u32,
    pub(crate) skipped: u32,
    pub(crate) failed: u32,
    pub(crate) last_cursor: Option<i64>,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub struct SafeLineBlocklistPullResponse {
    pub(crate) success: bool,
    pub(crate) imported: u32,
    pub(crate) skipped: u32,
    pub(crate) last_cursor: Option<i64>,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub(crate) total_packets: u64,
    pub(crate) blocked_packets: u64,
    pub(crate) blocked_l4: u64,
    pub(crate) blocked_l7: u64,
    pub(crate) total_bytes: u64,
    pub(crate) proxied_requests: u64,
    pub(crate) proxy_successes: u64,
    pub(crate) proxy_failures: u64,
    pub(crate) proxy_fail_close_rejections: u64,
    pub(crate) upstream_healthcheck_successes: u64,
    pub(crate) upstream_healthcheck_failures: u64,
    pub(crate) proxy_latency_micros_total: u64,
    pub(crate) average_proxy_latency_micros: u64,
    pub(crate) active_rules: u64,
    pub(crate) sqlite_enabled: bool,
    pub(crate) persisted_security_events: u64,
    pub(crate) persisted_blocked_ips: u64,
    pub(crate) persisted_rules: u64,
    pub(crate) last_persisted_event_at: Option<i64>,
    pub(crate) last_rule_update_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct L4StatsResponse {
    pub(crate) enabled: bool,
    pub(crate) connections: crate::l4::connection::ConnectionStats,
    pub(crate) ddos_events: u64,
    pub(crate) protocol_anomalies: u64,
    pub(crate) traffic: u64,
    pub(crate) defense_actions: u64,
    pub(crate) bloom_stats: Option<crate::l4::bloom_filter::L4BloomStats>,
    pub(crate) false_positive_stats: Option<crate::l4::bloom_filter::L4FalsePositiveStats>,
    pub(crate) per_port_stats: Vec<crate::l4::inspector::PortStats>,
}

#[derive(Debug, Serialize)]
pub struct L7StatsResponse {
    pub(crate) enabled: bool,
    pub(crate) blocked_requests: u64,
    pub(crate) proxied_requests: u64,
    pub(crate) proxy_successes: u64,
    pub(crate) proxy_failures: u64,
    pub(crate) proxy_fail_close_rejections: u64,
    pub(crate) average_proxy_latency_micros: u64,
    pub(crate) upstream_healthy: bool,
    pub(crate) upstream_last_check_at: Option<i64>,
    pub(crate) upstream_last_error: Option<String>,
    pub(crate) http3_feature_available: bool,
    pub(crate) http3_configured_enabled: bool,
    pub(crate) http3_tls13_enabled: bool,
    pub(crate) http3_certificate_configured: bool,
    pub(crate) http3_private_key_configured: bool,
    pub(crate) http3_listener_started: bool,
    pub(crate) http3_listener_addr: Option<String>,
    pub(crate) http3_status: String,
    pub(crate) http3_last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct RulesListResponse {
    pub(crate) rules: Vec<RuleResponse>,
}

#[derive(Debug, Serialize)]
pub struct RuleResponse {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) enabled: bool,
    pub(crate) layer: String,
    pub(crate) pattern: String,
    pub(crate) action: String,
    pub(crate) severity: String,
    pub(crate) plugin_template_id: Option<String>,
    pub(crate) response_template: Option<RuleResponseTemplatePayload>,
}

#[derive(Debug, Deserialize)]
pub struct RuleUpsertRequest {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) enabled: bool,
    pub(crate) layer: String,
    pub(crate) pattern: String,
    pub(crate) action: String,
    pub(crate) severity: String,
    pub(crate) plugin_template_id: Option<String>,
    pub(crate) response_template: Option<RuleResponseTemplatePayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResponseTemplatePayload {
    pub(crate) status_code: u16,
    pub(crate) content_type: String,
    pub(crate) body_source: String,
    pub(crate) gzip: bool,
    pub(crate) body_text: String,
    pub(crate) body_file_path: String,
    #[serde(default)]
    pub(crate) headers: Vec<RuleResponseHeaderPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResponseHeaderPayload {
    pub(crate) key: String,
    pub(crate) value: String,
}

#[derive(Debug, Serialize)]
pub struct RuleActionPluginsResponse {
    pub(crate) total: u32,
    pub(crate) plugins: Vec<RuleActionPluginResponse>,
}

#[derive(Debug, Serialize)]
pub struct RuleActionPluginResponse {
    pub(crate) plugin_id: String,
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) description: String,
    pub(crate) enabled: bool,
    pub(crate) installed_at: i64,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct RuleActionTemplatesResponse {
    pub(crate) total: u32,
    pub(crate) templates: Vec<RuleActionTemplateResponse>,
}

#[derive(Debug, Serialize)]
pub struct RuleActionTemplateResponse {
    pub(crate) template_id: String,
    pub(crate) plugin_id: String,
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) layer: String,
    pub(crate) action: String,
    pub(crate) pattern: String,
    pub(crate) severity: String,
    pub(crate) response_template: RuleResponseTemplatePayload,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Serialize)]
pub struct RuleActionTemplatePreviewResponse {
    pub(crate) template_id: String,
    pub(crate) name: String,
    pub(crate) content_type: String,
    pub(crate) status_code: u16,
    pub(crate) gzip: bool,
    pub(crate) body_source: String,
    pub(crate) body_preview: String,
    pub(crate) truncated: bool,
}

#[derive(Debug, Deserialize)]
pub struct InstallRuleActionPluginRequest {
    pub(crate) package_url: String,
    #[serde(default)]
    pub(crate) sha256: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRuleActionPluginRequest {
    pub(crate) enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct WriteStatusResponse {
    pub(crate) success: bool,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub struct SecurityEventsResponse {
    pub(crate) total: u64,
    pub(crate) limit: u32,
    pub(crate) offset: u32,
    pub(crate) events: Vec<SecurityEventResponse>,
}

#[derive(Debug, Serialize)]
pub struct SecurityEventResponse {
    pub(crate) id: i64,
    pub(crate) layer: String,
    pub(crate) provider: Option<String>,
    pub(crate) provider_site_id: Option<String>,
    pub(crate) provider_site_name: Option<String>,
    pub(crate) provider_site_domain: Option<String>,
    pub(crate) action: String,
    pub(crate) reason: String,
    pub(crate) source_ip: String,
    pub(crate) dest_ip: String,
    pub(crate) source_port: i64,
    pub(crate) dest_port: i64,
    pub(crate) protocol: String,
    pub(crate) http_method: Option<String>,
    pub(crate) uri: Option<String>,
    pub(crate) http_version: Option<String>,
    pub(crate) created_at: i64,
    pub(crate) handled: bool,
    pub(crate) handled_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct EventUpdateRequest {
    pub(crate) handled: bool,
}

#[derive(Debug, Serialize)]
pub struct BlockedIpsResponse {
    pub(crate) total: u64,
    pub(crate) limit: u32,
    pub(crate) offset: u32,
    pub(crate) blocked_ips: Vec<BlockedIpResponse>,
}

#[derive(Debug, Serialize)]
pub struct BlockedIpResponse {
    pub(crate) id: i64,
    pub(crate) provider: Option<String>,
    pub(crate) provider_remote_id: Option<String>,
    pub(crate) ip: String,
    pub(crate) reason: String,
    pub(crate) blocked_at: i64,
    pub(crate) expires_at: i64,
}

#[derive(Debug, Deserialize, Default)]
pub struct EventsQueryParams {
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u32>,
    pub(crate) layer: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) provider_site_id: Option<String>,
    pub(crate) source_ip: Option<String>,
    pub(crate) action: Option<String>,
    pub(crate) blocked_only: Option<bool>,
    pub(crate) handled_only: Option<bool>,
    pub(crate) created_from: Option<i64>,
    pub(crate) created_to: Option<i64>,
    pub(crate) sort_by: Option<String>,
    pub(crate) sort_direction: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct BlockedIpsQueryParams {
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u32>,
    pub(crate) source_scope: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) ip: Option<String>,
    pub(crate) keyword: Option<String>,
    pub(crate) active_only: Option<bool>,
    pub(crate) blocked_from: Option<i64>,
    pub(crate) blocked_to: Option<i64>,
    pub(crate) sort_by: Option<String>,
    pub(crate) sort_direction: Option<String>,
}

#[derive(Debug, Serialize)]
pub(super) struct ErrorResponse {
    pub(super) error: String,
}
