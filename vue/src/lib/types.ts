export interface HealthResponse {
  status: string
  version: string
  upstream_healthy: boolean
  upstream_last_check_at: number | null
  upstream_last_error: string | null
}

export interface MetricsResponse {
  total_packets: number
  blocked_packets: number
  blocked_l4: number
  blocked_l7: number
  total_bytes: number
  proxied_requests: number
  proxy_successes: number
  proxy_failures: number
  proxy_fail_close_rejections: number
  upstream_healthcheck_successes: number
  upstream_healthcheck_failures: number
  proxy_latency_micros_total: number
  average_proxy_latency_micros: number
  active_rules: number
  sqlite_enabled: boolean
  persisted_security_events: number
  persisted_blocked_ips: number
  persisted_rules: number
  last_persisted_event_at: number | null
  last_rule_update_at: number | null
}

export interface RuleItem {
  id: string
  name: string
  enabled: boolean
  layer: string
  pattern: string
  action: string
  severity: string
}

export interface RuleDraft {
  id: string
  name: string
  enabled: boolean
  layer: string
  pattern: string
  action: string
  severity: string
}

export interface RulesResponse {
  rules: RuleItem[]
}

export type ApiQueryValue = string | number | boolean | null | undefined

export interface SecurityEventItem {
  id: number
  layer: string
  provider: string | null
  provider_site_id: string | null
  provider_site_name: string | null
  provider_site_domain: string | null
  action: string
  reason: string
  source_ip: string
  dest_ip: string
  source_port: number
  dest_port: number
  protocol: string
  http_method: string | null
  uri: string | null
  http_version: string | null
  created_at: number
  handled: boolean
  handled_at: number | null
}

export interface SecurityEventsResponse {
  total: number
  limit: number
  offset: number
  events: SecurityEventItem[]
}

export interface EventsQuery extends Record<string, ApiQueryValue> {
  limit?: number
  offset?: number
  layer?: string
  provider?: string
  provider_site_id?: string
  source_ip?: string
  action?: string
  blocked_only?: boolean
  handled_only?: boolean
  sort_by?: string
  sort_direction?: 'asc' | 'desc'
}

export interface BlockedIpItem {
  id: number
  provider: string | null
  provider_remote_id: string | null
  ip: string
  reason: string
  blocked_at: number
  expires_at: number
}

export interface BlockedIpsResponse {
  total: number
  limit: number
  offset: number
  blocked_ips: BlockedIpItem[]
}

export interface BlockedIpsQuery extends Record<string, ApiQueryValue> {
  limit?: number
  offset?: number
  provider?: string
  ip?: string
  active_only?: boolean
  blocked_from?: number
  blocked_to?: number
  sort_by?: string
  sort_direction?: 'asc' | 'desc'
}

export interface WriteStatusResponse {
  success: boolean
  message: string
}

export interface SafeLineSettings {
  enabled: boolean
  base_url: string
  api_token: string
  verify_tls: boolean
  openapi_doc_path: string
  auth_probe_path: string
  site_list_path: string
  event_list_path: string
  blocklist_sync_path: string
  blocklist_delete_path: string
}

export interface SettingsPayload {
  gateway_name: string
  auto_refresh_seconds: number
  upstream_endpoint: string
  api_endpoint: string
  emergency_mode: boolean
  sqlite_persistence: boolean
  notify_by_sound: boolean
  notification_level: 'all' | 'critical' | 'blocked_only'
  retain_days: number
  notes: string
  safeline: SafeLineSettings
}

export interface SafeLineTestResponse {
  status: string
  message: string
  openapi_doc_reachable: boolean
  openapi_doc_status: number | null
  authenticated: boolean
  auth_probe_status: number | null
}

export interface SafeLineSiteItem {
  id: string
  name: string
  domain: string
  status: string
  raw: Record<string, unknown>
}

export interface SafeLineSitesResponse {
  total: number
  sites: SafeLineSiteItem[]
}

export interface SafeLineMappingItem {
  id: number
  safeline_site_id: string
  safeline_site_name: string
  safeline_site_domain: string
  local_alias: string
  enabled: boolean
  is_primary: boolean
  notes: string
  updated_at: number
}

export interface SafeLineMappingsResponse {
  total: number
  mappings: SafeLineMappingItem[]
}

export interface SafeLineMappingsUpdateRequest {
  mappings: Array<{
    safeline_site_id: string
    safeline_site_name: string
    safeline_site_domain: string
    local_alias: string
    enabled: boolean
    is_primary: boolean
    notes: string
  }>
}

export interface SafeLineEventSyncResponse {
  success: boolean
  imported: number
  skipped: number
  last_cursor: number | null
  message: string
}

export interface SafeLineSyncStateResponse {
  resource: string
  last_cursor: number | null
  last_success_at: number | null
  last_imported_count: number
  last_skipped_count: number
  updated_at: number
}

export interface SafeLineBlocklistSyncResponse {
  success: boolean
  synced: number
  skipped: number
  failed: number
  last_cursor: number | null
  message: string
}

export interface SafeLineBlocklistPullResponse {
  success: boolean
  imported: number
  skipped: number
  last_cursor: number | null
  message: string
}

export interface DashboardPayload {
  health: HealthResponse
  metrics: MetricsResponse
  events: SecurityEventsResponse
  blockedIps: BlockedIpsResponse
  rules: RulesResponse
}

export interface DashboardQueryOptions {
  events?: EventsQuery
  blockedIps?: BlockedIpsQuery
}
