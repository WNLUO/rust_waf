export interface SafeLineSettingsForm {
  enabled: boolean
  auto_sync_events: boolean
  auto_sync_blocked_ips_push: boolean
  auto_sync_blocked_ips_pull: boolean
  auto_sync_interval_secs: number
  base_url: string
  api_token: string
  username: string
  password: string
  verify_tls: boolean
  openapi_doc_path: string
  auth_probe_path: string
  site_list_path: string
  event_list_path: string
  blocklist_sync_path: string
  blocklist_delete_path: string
  blocklist_ip_group_ids: string[]
}

export interface SafeLineSettingsUpdatePayload {
  auto_sync_events: boolean
  auto_sync_blocked_ips_push: boolean
  auto_sync_blocked_ips_pull: boolean
  auto_sync_interval_secs: number
  base_url: string
  api_token: string
  username: string
  password: string
  verify_tls: boolean
}

export interface SafeLineTestPayload {
  base_url: string
  api_token: string
  username: string
  password: string
  verify_tls: boolean
  openapi_doc_path: string
  auth_probe_path: string
  site_list_path: string
  event_list_path: string
  blocklist_sync_path: string
  blocklist_delete_path: string
  blocklist_ip_group_ids: string[]
}

export interface SettingsPayload {
  gateway_name: string
  drop_unmatched_requests: boolean
  cdn_525_diagnostic_mode: boolean
  client_identity_debug_enabled: boolean
  adaptive_protection: AdaptiveProtectionSettingsPayload
  https_listen_addr: string
  default_certificate_id: number | null
  api_endpoint: string
  notes: string
  safeline: SafeLineSettingsForm
}

export interface SettingsUpdatePayload {
  gateway_name: string
  drop_unmatched_requests: boolean
  cdn_525_diagnostic_mode: boolean
  client_identity_debug_enabled: boolean
  adaptive_protection: AdaptiveProtectionSettingsPayload
  https_listen_addr: string
  default_certificate_id: number | null
  api_endpoint: string
  notes: string
  safeline: SafeLineSettingsUpdatePayload
}

export interface AdaptiveProtectionSettingsPayload {
  enabled: boolean
  mode: 'relaxed' | 'balanced' | 'strict' | string
  goal: 'availability_first' | 'balanced' | 'security_first' | string
  cdn_fronted: boolean
  allow_emergency_reject: boolean
}
