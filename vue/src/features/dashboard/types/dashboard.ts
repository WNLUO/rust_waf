import type {
  BlockedIpsResponse,
  EventsQuery,
  SecurityEventsResponse,
  BlockedIpsQuery,
} from '@/features/events/types/events'
import type { RulesResponse } from '@/features/rules/types/rules'
import type { HealthResponse, MetricsResponse } from '@/shared/types/system'

export interface DashboardPayload {
  health: HealthResponse
  metrics: MetricsResponse
  events: SecurityEventsResponse
  blockedIps: BlockedIpsResponse
  rules: RulesResponse
}

export interface DashboardQueryOptions {
  events?: EventsQuery
  blockedIps?: BlockedIpsQuery
}
