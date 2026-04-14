import type { L4ConfigPayload, L4StatsPayload, WriteStatusResponse } from '@/shared/types'
import { apiRequest } from './core'

export function fetchL4Config() {
  return apiRequest<L4ConfigPayload>('/l4/config')
}

export function updateL4Config(
  payload: Omit<
    L4ConfigPayload,
    | 'runtime_enabled'
    | 'bloom_enabled'
    | 'bloom_false_positive_verification'
    | 'runtime_profile'
    | 'adaptive_managed_fields'
    | 'adaptive_runtime'
    | 'advanced_compatibility'
  >,
) {
  return apiRequest<WriteStatusResponse>('/l4/config', {
    method: 'PUT',
    body: JSON.stringify(payload),
  })
}

export function updateL4CompatibilityConfig(
  payload: Omit<
    L4ConfigPayload,
    | 'runtime_enabled'
    | 'bloom_enabled'
    | 'bloom_false_positive_verification'
    | 'runtime_profile'
    | 'adaptive_managed_fields'
    | 'adaptive_runtime'
    | 'advanced_compatibility'
  >,
) {
  return apiRequest<WriteStatusResponse>('/l4/config/compatibility', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export function fetchL4Stats() {
  return apiRequest<L4StatsPayload>('/l4/stats')
}
