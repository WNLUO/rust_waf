import type { ApiQueryValue } from '@/shared/types/common'

export interface SecurityEventItem {
  id: number
  layer: string
  provider: string | null
  provider_event_id: string | null
  provider_site_id: string | null
  provider_site_name: string | null
  provider_site_domain: string | null
  action: string
  reason: string
  details_json: string | null
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
  decision_summary: SecurityEventDecisionSummary | null
}

export interface SecurityEventDecisionSummary {
  primary_signal: string
  identity_state: string | null
  client_ip_source: string | null
  forward_header_valid: boolean | null
  l4_overload_level: string | null
  l7_rule_inspection_mode: string | null
  cc_action: string | null
  behavior_action: string | null
  labels: string[]
}

export interface StoragePressureSummaryDetails {
  mode: string
  action: string | null
  original_reason: string | null
  count: number
  source_scope: string | null
  route: string | null
  time_window_start: number | null
  time_window_end: number | null
  first_created_at: number | null
  last_created_at: number | null
}

export interface SecurityEventsResponse {
  total: number
  limit: number
  offset: number
  events: SecurityEventItem[]
}

export interface SecurityEventsSummaryResponse {
  total_events: number
  sampled_events: number
  generated_at: number
  by_action: SecurityEventCountItem[]
  by_layer: SecurityEventCountItem[]
  by_provider: SecurityEventCountItem[]
  by_primary_signal: SecurityEventCountItem[]
  top_source_ips: SecurityEventCountItem[]
  top_routes: SecurityEventCountItem[]
  top_reasons: SecurityEventCountItem[]
  hourly: SecurityEventHourlyItem[]
  aggregated: SecurityEventsAggregatedSummary
  representative_events: SecurityEventItem[]
}

export interface SecurityEventCountItem {
  key: string
  count: number
}

export interface SecurityEventHourlyItem {
  bucket_start: number
  count: number
  blocked: number
  alerted: number
  challenged: number
  dropped: number
}

export interface SecurityEventsAggregatedSummary {
  summary_events: number
  represented_events: number
  hotspot_events: number
  long_tail_events: number
}

export interface BehaviorProfileItem {
  identity: string
  source_ip: string | null
  latest_seen_at: number
  score: number
  dominant_route: string | null
  focused_document_route: string | null
  focused_api_route: string | null
  distinct_routes: number
  repeated_ratio: number
  document_repeated_ratio: number
  api_repeated_ratio: number
  interval_jitter_ms: number | null
  document_requests: number
  api_requests: number
  non_document_requests: number
  challenge_count_window: number
  session_span_secs: number
  flags: string[]
  latest_route: string
  latest_kind: string
  blocked: boolean
  blocked_at: number | null
  blocked_expires_at: number | null
  blocked_reason: string | null
}

export interface BehaviorProfilesResponse {
  total: number
  profiles: BehaviorProfileItem[]
}

export interface FingerprintProfileItem {
  identity: string
  identity_kind: string
  source_ip: string | null
  first_seen_at: number
  last_seen_at: number
  first_site_domain: string | null
  last_site_domain: string | null
  first_user_agent: string | null
  last_user_agent: string | null
  total_security_events: number
  total_behavior_events: number
  total_challenges: number
  total_blocks: number
  latest_score: number | null
  max_score: number
  latest_action: string | null
  reputation_score: number
  notes: string
}

export interface FingerprintProfilesResponse {
  total: number
  profiles: FingerprintProfileItem[]
}

export interface BehaviorSessionItem {
  session_key: string
  identity: string
  source_ip: string | null
  site_domain: string | null
  opened_at: number
  last_seen_at: number
  event_count: number
  challenge_count: number
  block_count: number
  latest_action: string | null
  latest_uri: string | null
  latest_reason: string | null
  dominant_route: string | null
  focused_document_route: string | null
  focused_api_route: string | null
  distinct_routes: number
  repeated_ratio: number
  document_repeated_ratio: number
  api_repeated_ratio: number
  document_requests: number
  api_requests: number
  non_document_requests: number
  interval_jitter_ms: number | null
  session_span_secs: number
  flags: string[]
}

export interface BehaviorSessionsResponse {
  total: number
  sessions: BehaviorSessionItem[]
}

export interface EventsQuery extends Record<string, ApiQueryValue> {
  limit?: number
  offset?: number
  layer?: string
  provider?: string
  provider_site_id?: string
  source_ip?: string
  action?: string
  identity_state?: string
  primary_signal?: string
  labels?: string
  blocked_only?: boolean
  handled_only?: boolean
  created_from?: number
  created_to?: number
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
  source_scope?: 'all' | 'local' | 'remote'
  provider?: string
  ip?: string
  keyword?: string
  active_only?: boolean
  blocked_from?: number
  blocked_to?: number
  sort_by?: string
  sort_direction?: 'asc' | 'desc'
}

export interface BlockedIpCreatePayload {
  ip: string
  reason: string
  duration_secs?: number
}

export interface BlockedIpsBatchUnblockPayload {
  ids: number[]
}

export interface BlockedIpsBatchUnblockResponse {
  success: boolean
  requested: number
  unblocked: number
  failed: number
  failed_ids: number[]
  message: string
}

export interface BlockedIpsCleanupExpiredPayload {
  source_scope?: 'all' | 'local' | 'remote'
  provider?: string
  blocked_from?: number
  blocked_to?: number
  expires_before?: number
}

export interface BlockedIpsCleanupExpiredResponse {
  success: boolean
  cleaned: number
  runtime_unblocked: number
  message: string
}
