import type {
  BlockedIpsResponse,
  EventsQuery,
  SecurityEventsResponse,
  BlockedIpsQuery,
} from './events'
import type { HealthResponse, MetricsResponse } from './system'
import type { RulesResponse } from './rules'

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
