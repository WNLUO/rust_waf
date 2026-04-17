import type { L4ConfigPayload, L4StatsPayload, WriteStatusResponse } from '@/shared/types'
import { apiRequest } from './core'

export type L4ConfigUpdatePayload = Record<string, never>

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
