import type { L4ConfigPayload, L4StatsPayload, WriteStatusResponse } from '@/shared/types'
import { apiRequest } from './core'

export interface L4TrustedCdnProviderUpdatePayload {
  enabled: boolean
}

export interface L4TrustedCdnAliyunEsaUpdatePayload
  extends L4TrustedCdnProviderUpdatePayload {
  site_id: string
  access_key_id: string
  access_key_secret: string
  endpoint: string
}

export interface L4TrustedCdnUpdatePayload {
  manual_cidrs: string[]
  sync_interval_value: number
  sync_interval_unit: string
  edgeone_overseas: L4TrustedCdnProviderUpdatePayload
  aliyun_esa: L4TrustedCdnAliyunEsaUpdatePayload
}

export interface L4ConfigUpdatePayload {
  ddos_protection_enabled: boolean
  advanced_ddos_enabled: boolean
  trusted_cdn: L4TrustedCdnUpdatePayload
}

export function fetchL4Config() {
  return apiRequest<L4ConfigPayload>('/l4/config')
}

export function updateL4Config(payload: L4ConfigUpdatePayload) {
  return apiRequest<WriteStatusResponse>('/l4/config', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function fetchL4Stats() {
  return apiRequest<L4StatsPayload>('/l4/stats')
}
