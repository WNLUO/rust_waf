import type { HealthResponse, MetricsResponse } from '@/shared/types'
import { apiRequest } from './core'

export function fetchHealth() {
  return apiRequest<HealthResponse>('/health')
}

export function fetchMetrics() {
  return apiRequest<MetricsResponse>('/metrics')
}
