export interface SafeLineSettingsForm {
  enabled: boolean
  auto_sync_events: boolean
  auto_sync_blocked_ips_push: boolean
  auto_sync_blocked_ips_pull: boolean
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
  adaptive_protection: AdaptiveProtectionSettingsPayload
  https_listen_addr: string
  default_certificate_id: number | null
  api_endpoint: string
  notes: string
  safeline: SafeLineSettingsForm
  bot_detection: BotDetectionSettings
}

export interface SettingsUpdatePayload {
  gateway_name: string
  drop_unmatched_requests: boolean
  adaptive_protection: AdaptiveProtectionSettingsPayload
  https_listen_addr: string
  default_certificate_id: number | null
  api_endpoint: string
  notes: string
  safeline: SafeLineSettingsUpdatePayload
  bot_detection: BotDetectionSettings
}

export type AdaptiveProtectionSettingsPayload = Record<string, never>

export interface BotDetectionSettings {
  enabled: boolean
  crawlers: BotCrawlerSettings[]
  providers: BotProviderSettings[]
}

export interface BotCrawlerSettings {
  enabled: boolean
  name: string
  provider: string | null
  category: string
  policy: string
  tokens: string[]
}

export interface BotProviderSettings {
  enabled: boolean
  id: string
  urls: string[]
  mirror_urls: string[]
  format: string
  reverse_dns_enabled: boolean
  reverse_dns_suffixes: string[]
}
