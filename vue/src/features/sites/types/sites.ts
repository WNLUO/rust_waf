import type { SafeLineInterceptConfigPayload } from '@/features/l7/types/l7'

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
  enabled: boolean | null
  server_names: string[]
  ports: string[]
  ssl_ports: string[]
  upstreams: string[]
  ssl_enabled: boolean
  cert_id: number | null
  cert_type: number | null
  cert_filename: string | null
  key_filename: string | null
  health_check: boolean | null
  raw: Record<string, unknown>
}

export interface SafeLineSitesResponse {
  total: number
  cached_at: number | null
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

export interface SafeLineSyncOverviewResponse {
  events: SafeLineSyncStateResponse | null
  blocked_ips_push: SafeLineSyncStateResponse | null
  blocked_ips_pull: SafeLineSyncStateResponse | null
  blocked_ips_delete: SafeLineSyncStateResponse | null
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

export interface LocalSiteItem {
  id: number
  name: string
  primary_hostname: string
  hostnames: string[]
  listen_ports: string[]
  upstreams: string[]
  safeline_intercept: SafeLineInterceptConfigPayload | null
  enabled: boolean
  tls_enabled: boolean
  local_certificate_id: number | null
  source: string
  sync_mode: string
  notes: string
  last_synced_at: number | null
  created_at: number
  updated_at: number
}

export interface LocalSitesResponse {
  total: number
  sites: LocalSiteItem[]
}

export interface GlobalEntryConfigPayload {
  http_port: string
  https_port: string
}

export interface HeaderOperationItem {
  scope: 'request' | 'response'
  action: 'set' | 'add' | 'remove'
  header: string
  value: string
}

export interface AiAuditSettingsPayload {
  enabled: boolean
  provider: 'local_rules' | 'stub_model' | 'openai_compatible' | 'xiaomi_mimo'
  model: string
  base_url: string
  api_key: string
  timeout_ms: number
  fallback_to_rules: boolean
  event_sample_limit: number
  recent_event_limit: number
  include_raw_event_samples: boolean
  auto_apply_temp_policies: boolean
  temp_policy_ttl_secs: number
  temp_block_ttl_secs: number
  auto_apply_min_confidence: number
  max_active_temp_policies: number
  allow_auto_temp_block: boolean
  allow_auto_extend_effective_policies: boolean
  auto_revoke_warmup_secs: number
  auto_audit_enabled: boolean
  auto_audit_interval_secs: number
  auto_audit_cooldown_secs: number
  auto_audit_on_pressure_high: boolean
  auto_audit_on_attack_mode: boolean
  auto_audit_on_hotspot_shift: boolean
  auto_audit_force_local_rules_under_attack: boolean
}

export interface GlobalSettingsPayload {
  enable_http1_0: boolean
  http2_enabled: boolean
  http3_enabled: boolean
  source_ip_strategy:
    | 'connection'
    | 'x_forwarded_for_first'
    | 'x_forwarded_for_last'
    | 'x_forwarded_for_last_but_one'
    | 'x_forwarded_for_last_but_two'
    | 'header'
    | 'proxy_protocol'
  custom_source_ip_header: string
  custom_source_ip_header_auth_enabled: boolean
  custom_source_ip_header_auth_header: string
  custom_source_ip_header_auth_secret: string
  http_to_https_redirect: boolean
  enable_hsts: boolean
  rewrite_host_enabled: boolean
  rewrite_host_value: string
  add_x_forwarded_headers: boolean
  rewrite_x_forwarded_for: boolean
  support_gzip: boolean
  support_brotli: boolean
  support_sse: boolean
  enable_ntlm: boolean
  fallback_self_signed_certificate: boolean
  ssl_protocols: string[]
  ssl_ciphers: string
  header_operations: HeaderOperationItem[]
  ai_audit: AiAuditSettingsPayload
}

export interface LocalSiteDraft {
  name: string
  primary_hostname: string
  hostnames: string[]
  listen_ports: string[]
  upstreams: string[]
  safeline_intercept: SafeLineInterceptConfigPayload | null
  enabled: boolean
  tls_enabled: boolean
  local_certificate_id: number | null
  source: string
  sync_mode: string
  notes: string
  last_synced_at: number | null
}

export interface LocalCertificateItem {
  id: number
  name: string
  domains: string[]
  issuer: string
  valid_from: number | null
  valid_to: number | null
  source_type: string
  provider_remote_id: string | null
  provider_remote_domains: string[]
  last_remote_fingerprint: string | null
  sync_status: string
  sync_message: string
  auto_sync_enabled: boolean
  trusted: boolean
  expired: boolean
  notes: string
  last_synced_at: number | null
  created_at: number
  updated_at: number
  certificate_pem?: string | null
  private_key_pem?: string | null
}

export interface LocalCertificatesResponse {
  total: number
  certificates: LocalCertificateItem[]
}

export interface LocalCertificateDraft {
  name: string
  domains: string[]
  issuer: string
  valid_from: number | null
  valid_to: number | null
  source_type: string
  provider_remote_id: string | null
  provider_remote_domains: string[]
  last_remote_fingerprint: string | null
  sync_status: string
  sync_message: string
  auto_sync_enabled: boolean
  trusted: boolean
  expired: boolean
  notes: string
  last_synced_at: number | null
  certificate_pem?: string | null
  private_key_pem?: string | null
}

export interface LocalCertificateRemoteBindRequest {
  remote_certificate_id: string
  remote_domains: string[]
}

export interface SafeLineCertificatesPullResponse {
  success: boolean
  imported_certificates: number
  updated_certificates: number
  skipped_certificates: number
  message: string
}

export interface SafeLineCertificateMatchCandidate {
  id: string
  domains: string[]
  issuer: string
  valid_to: number | null
  related_sites: string[]
}

export interface SafeLineCertificateMatchPreviewResponse {
  success: boolean
  status: string
  strategy: string
  local_certificate_id: number
  local_domains: string[]
  linked_remote_id: string | null
  matched_remote_id: string | null
  message: string
  candidates: SafeLineCertificateMatchCandidate[]
}

export interface GeneratedLocalCertificateRequest {
  name?: string | null
  domains: string[]
  notes?: string | null
}

export interface SiteSyncLinkItem {
  id: number
  local_site_id: number
  provider: string
  remote_site_id: string
  remote_site_name: string
  remote_cert_id: string | null
  sync_mode: string
  last_local_hash: string | null
  last_remote_hash: string | null
  last_error: string | null
  last_synced_at: number | null
  created_at: number
  updated_at: number
}

export interface SiteSyncLinksResponse {
  total: number
  links: SiteSyncLinkItem[]
}

export interface SiteSyncLinkDraft {
  local_site_id: number
  provider: string
  remote_site_id: string
  remote_site_name: string
  remote_cert_id: string | null
  sync_mode: string
  last_local_hash: string | null
  last_remote_hash: string | null
  last_error: string | null
  last_synced_at: number | null
}

export interface SafeLineSitesPullResponse {
  success: boolean
  imported_sites: number
  updated_sites: number
  imported_certificates: number
  updated_certificates: number
  linked_sites: number
  skipped_sites: number
  message: string
}

export interface SafeLineSitesPushResponse {
  success: boolean
  created_sites: number
  updated_sites: number
  created_certificates: number
  reused_certificates: number
  skipped_sites: number
  failed_sites: number
  message: string
}

export interface SafeLineSitePullOptions {
  name: boolean
  primary_hostname: boolean
  hostnames: boolean
  listen_ports: boolean
  upstreams: boolean
  enabled: boolean
}

export interface SafeLineSitePullRequest {
  options: SafeLineSitePullOptions
}
