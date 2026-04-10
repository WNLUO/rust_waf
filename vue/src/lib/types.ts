export interface HealthResponse {
  status: string;
  version: string;
  upstream_healthy: boolean;
  upstream_last_check_at: number | null;
  upstream_last_error: string | null;
}

export interface MetricsResponse {
  total_packets: number;
  blocked_packets: number;
  blocked_l4: number;
  blocked_l7: number;
  total_bytes: number;
  proxied_requests: number;
  proxy_successes: number;
  proxy_failures: number;
  proxy_fail_close_rejections: number;
  upstream_healthcheck_successes: number;
  upstream_healthcheck_failures: number;
  proxy_latency_micros_total: number;
  average_proxy_latency_micros: number;
  active_rules: number;
  sqlite_enabled: boolean;
  persisted_security_events: number;
  persisted_blocked_ips: number;
  persisted_rules: number;
  last_persisted_event_at: number | null;
  last_rule_update_at: number | null;
}

export interface RuleItem {
  id: string;
  name: string;
  enabled: boolean;
  layer: string;
  pattern: string;
  action: string;
  severity: string;
}

export interface RuleDraft {
  id: string;
  name: string;
  enabled: boolean;
  layer: string;
  pattern: string;
  action: string;
  severity: string;
}

export interface RulesResponse {
  rules: RuleItem[];
}

export type ApiQueryValue = string | number | boolean | null | undefined;

export interface SecurityEventItem {
  id: number;
  layer: string;
  provider: string | null;
  provider_site_id: string | null;
  provider_site_name: string | null;
  provider_site_domain: string | null;
  action: string;
  reason: string;
  source_ip: string;
  dest_ip: string;
  source_port: number;
  dest_port: number;
  protocol: string;
  http_method: string | null;
  uri: string | null;
  http_version: string | null;
  created_at: number;
  handled: boolean;
  handled_at: number | null;
}

export interface SecurityEventsResponse {
  total: number;
  limit: number;
  offset: number;
  events: SecurityEventItem[];
}

export interface EventsQuery extends Record<string, ApiQueryValue> {
  limit?: number;
  offset?: number;
  layer?: string;
  provider?: string;
  provider_site_id?: string;
  source_ip?: string;
  action?: string;
  blocked_only?: boolean;
  handled_only?: boolean;
  sort_by?: string;
  sort_direction?: "asc" | "desc";
}

export interface BlockedIpItem {
  id: number;
  provider: string | null;
  provider_remote_id: string | null;
  ip: string;
  reason: string;
  blocked_at: number;
  expires_at: number;
}

export interface BlockedIpsResponse {
  total: number;
  limit: number;
  offset: number;
  blocked_ips: BlockedIpItem[];
}

export interface BlockedIpsQuery extends Record<string, ApiQueryValue> {
  limit?: number;
  offset?: number;
  source_scope?: "all" | "local" | "remote";
  provider?: string;
  ip?: string;
  keyword?: string;
  active_only?: boolean;
  blocked_from?: number;
  blocked_to?: number;
  sort_by?: string;
  sort_direction?: "asc" | "desc";
}

export interface WriteStatusResponse {
  success: boolean;
  message: string;
}

export interface SafeLineSettings {
  enabled: boolean;
  auto_sync_events: boolean;
  auto_sync_blocked_ips_push: boolean;
  auto_sync_blocked_ips_pull: boolean;
  auto_sync_interval_secs: number;
  base_url: string;
  api_token: string;
  username: string;
  password: string;
  verify_tls: boolean;
  openapi_doc_path: string;
  auth_probe_path: string;
  site_list_path: string;
  event_list_path: string;
  blocklist_sync_path: string;
  blocklist_delete_path: string;
  blocklist_ip_group_ids: string[];
}

export interface SettingsPayload {
  gateway_name: string;
  auto_refresh_seconds: number;
  upstream_endpoint: string;
  api_endpoint: string;
  emergency_mode: boolean;
  sqlite_persistence: boolean;
  notify_by_sound: boolean;
  notification_level: "all" | "critical" | "blocked_only";
  retain_days: number;
  notes: string;
  safeline: SafeLineSettings;
}

export interface L4ConfigPayload {
  ddos_protection_enabled: boolean;
  advanced_ddos_enabled: boolean;
  connection_rate_limit: number;
  syn_flood_threshold: number;
  max_tracked_ips: number;
  max_blocked_ips: number;
  state_ttl_secs: number;
  bloom_filter_scale: number;
  runtime_enabled: boolean;
  bloom_enabled: boolean;
  bloom_false_positive_verification: boolean;
  runtime_profile: "minimal" | "standard" | string;
}

export interface L4ConnectionStats {
  total_connections: number;
  active_connections: number;
  blocked_connections: number;
  rate_limit_hits: number;
}

export interface L4PortStatItem {
  port: string;
  connections: number;
  blocks: number;
  bytes_processed: number;
  ddos_events: number;
}

export interface L4BloomFilterCounters {
  filter_size: number;
  hash_functions: number;
  insert_count: number;
  hit_count: number;
  hit_rate: number;
}

export interface L4BloomStats {
  ipv4_filter: L4BloomFilterCounters;
  ipv6_filter: L4BloomFilterCounters;
  ip_port_filter: L4BloomFilterCounters;
  enabled: boolean;
  false_positive_verification: boolean;
}

export interface L4FalsePositiveStats {
  ipv4_exact_size: number;
  ipv6_exact_size: number;
  ip_port_exact_size: number;
}

export interface L4StatsPayload {
  enabled: boolean;
  connections: L4ConnectionStats;
  ddos_events: number;
  protocol_anomalies: number;
  traffic: number;
  defense_actions: number;
  bloom_stats: L4BloomStats | null;
  false_positive_stats: L4FalsePositiveStats | null;
  per_port_stats: L4PortStatItem[];
}

export interface L7ConfigPayload {
  http_inspection_enabled: boolean;
  max_request_size: number;
  real_ip_headers: string[];
  trusted_proxy_cidrs: string[];
  first_byte_timeout_ms: number;
  read_idle_timeout_ms: number;
  tls_handshake_timeout_ms: number;
  proxy_connect_timeout_ms: number;
  proxy_write_timeout_ms: number;
  proxy_read_timeout_ms: number;
  upstream_healthcheck_enabled: boolean;
  upstream_healthcheck_interval_secs: number;
  upstream_healthcheck_timeout_ms: number;
  upstream_failure_mode: "fail_open" | "fail_close" | string;
  bloom_filter_scale: number;
  http2_enabled: boolean;
  http2_max_concurrent_streams: number;
  http2_max_frame_size: number;
  http2_enable_priorities: boolean;
  http2_initial_window_size: number;
  runtime_enabled: boolean;
  bloom_enabled: boolean;
  bloom_false_positive_verification: boolean;
  runtime_profile: "minimal" | "standard" | string;
  listen_addrs: string[];
  upstream_endpoint: string;
  http3_enabled: boolean;
  http3_listen_addr: string;
  http3_max_concurrent_streams: number;
  http3_idle_timeout_secs: number;
  http3_mtu: number;
  http3_max_frame_size: number;
  http3_enable_connection_migration: boolean;
  http3_qpack_table_size: number;
  http3_certificate_path: string;
  http3_private_key_path: string;
  http3_enable_tls13: boolean;
}

export interface L7StatsPayload {
  enabled: boolean;
  blocked_requests: number;
  proxied_requests: number;
  proxy_successes: number;
  proxy_failures: number;
  proxy_fail_close_rejections: number;
  average_proxy_latency_micros: number;
  upstream_healthy: boolean;
  upstream_last_check_at: number | null;
  upstream_last_error: string | null;
  http3_feature_available: boolean;
  http3_configured_enabled: boolean;
  http3_tls13_enabled: boolean;
  http3_certificate_configured: boolean;
  http3_private_key_configured: boolean;
  http3_listener_started: boolean;
  http3_listener_addr: string | null;
  http3_status: string;
  http3_last_error: string | null;
}

export interface SafeLineTestResponse {
  status: string;
  message: string;
  openapi_doc_reachable: boolean;
  openapi_doc_status: number | null;
  authenticated: boolean;
  auth_probe_status: number | null;
}

export interface SafeLineSiteItem {
  id: string;
  name: string;
  domain: string;
  status: string;
  enabled: boolean | null;
  server_names: string[];
  ports: string[];
  ssl_ports: string[];
  upstreams: string[];
  ssl_enabled: boolean;
  cert_id: number | null;
  cert_type: number | null;
  cert_filename: string | null;
  key_filename: string | null;
  health_check: boolean | null;
  raw: Record<string, unknown>;
}

export interface SafeLineSitesResponse {
  total: number;
  sites: SafeLineSiteItem[];
}

export interface SafeLineMappingItem {
  id: number;
  safeline_site_id: string;
  safeline_site_name: string;
  safeline_site_domain: string;
  local_alias: string;
  enabled: boolean;
  is_primary: boolean;
  notes: string;
  updated_at: number;
}

export interface SafeLineMappingsResponse {
  total: number;
  mappings: SafeLineMappingItem[];
}

export interface SafeLineMappingsUpdateRequest {
  mappings: Array<{
    safeline_site_id: string;
    safeline_site_name: string;
    safeline_site_domain: string;
    local_alias: string;
    enabled: boolean;
    is_primary: boolean;
    notes: string;
  }>;
}

export interface LocalSiteItem {
  id: number;
  name: string;
  primary_hostname: string;
  hostnames: string[];
  listen_ports: string[];
  upstreams: string[];
  enabled: boolean;
  tls_enabled: boolean;
  local_certificate_id: number | null;
  source: string;
  sync_mode: string;
  notes: string;
  last_synced_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface LocalSitesResponse {
  total: number;
  sites: LocalSiteItem[];
}

export interface LocalSiteDraft {
  name: string;
  primary_hostname: string;
  hostnames: string[];
  listen_ports: string[];
  upstreams: string[];
  enabled: boolean;
  tls_enabled: boolean;
  local_certificate_id: number | null;
  source: string;
  sync_mode: string;
  notes: string;
  last_synced_at: number | null;
}

export interface LocalCertificateItem {
  id: number;
  name: string;
  domains: string[];
  issuer: string;
  valid_from: number | null;
  valid_to: number | null;
  source_type: string;
  provider_remote_id: string | null;
  trusted: boolean;
  expired: boolean;
  notes: string;
  last_synced_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface LocalCertificatesResponse {
  total: number;
  certificates: LocalCertificateItem[];
}

export interface LocalCertificateDraft {
  name: string;
  domains: string[];
  issuer: string;
  valid_from: number | null;
  valid_to: number | null;
  source_type: string;
  provider_remote_id: string | null;
  trusted: boolean;
  expired: boolean;
  notes: string;
  last_synced_at: number | null;
}

export interface SiteSyncLinkItem {
  id: number;
  local_site_id: number;
  provider: string;
  remote_site_id: string;
  remote_site_name: string;
  remote_cert_id: string | null;
  sync_mode: string;
  last_local_hash: string | null;
  last_remote_hash: string | null;
  last_error: string | null;
  last_synced_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface SiteSyncLinksResponse {
  total: number;
  links: SiteSyncLinkItem[];
}

export interface SiteSyncLinkDraft {
  local_site_id: number;
  provider: string;
  remote_site_id: string;
  remote_site_name: string;
  remote_cert_id: string | null;
  sync_mode: string;
  last_local_hash: string | null;
  last_remote_hash: string | null;
  last_error: string | null;
  last_synced_at: number | null;
}

export interface SafeLineEventSyncResponse {
  success: boolean;
  imported: number;
  skipped: number;
  last_cursor: number | null;
  message: string;
}

export interface SafeLineSyncStateResponse {
  resource: string;
  last_cursor: number | null;
  last_success_at: number | null;
  last_imported_count: number;
  last_skipped_count: number;
  updated_at: number;
}

export interface SafeLineSyncOverviewResponse {
  events: SafeLineSyncStateResponse | null;
  blocked_ips_push: SafeLineSyncStateResponse | null;
  blocked_ips_pull: SafeLineSyncStateResponse | null;
  blocked_ips_delete: SafeLineSyncStateResponse | null;
}

export interface SafeLineBlocklistSyncResponse {
  success: boolean;
  synced: number;
  skipped: number;
  failed: number;
  last_cursor: number | null;
  message: string;
}

export interface SafeLineBlocklistPullResponse {
  success: boolean;
  imported: number;
  skipped: number;
  last_cursor: number | null;
  message: string;
}

export interface DashboardPayload {
  health: HealthResponse;
  metrics: MetricsResponse;
  events: SecurityEventsResponse;
  blockedIps: BlockedIpsResponse;
  rules: RulesResponse;
}

export interface DashboardQueryOptions {
  events?: EventsQuery;
  blockedIps?: BlockedIpsQuery;
}
