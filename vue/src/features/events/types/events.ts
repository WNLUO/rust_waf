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
