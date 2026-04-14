import type { L7ConfigPayload, L7StatsPayload, WriteStatusResponse } from '@/shared/types'
import { apiRequest } from './core'

export function fetchL7Config() {
  return apiRequest<L7ConfigPayload>('/l7/config')
}

export function updateL7Config(
  payload: Omit<L7ConfigPayload, 'runtime_enabled' | 'adaptive_runtime'>,
) {
  return apiRequest<WriteStatusResponse>('/l7/config', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function fetchL7Stats() {
  return apiRequest<L7StatsPayload>('/l7/stats')
}
