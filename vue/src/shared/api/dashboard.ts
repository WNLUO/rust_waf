import type {
  BlockedIpsQuery,
  BlockedIpsResponse,
  DashboardPayload,
  DashboardQueryOptions,
  EventsQuery,
  HealthResponse,
  MetricsResponse,
  RulesResponse,
  SecurityEventsResponse,
  AiAuditSummaryQuery,
  AiAuditSummaryResponse,
  AiAuditReportResponse,
  TrafficMapQuery,
  TrafficMapResponse,
} from '@/shared/types'
import { apiRequest, buildQuery, withDefaults } from './core'

export async function fetchDashboardPayload(
  options: DashboardQueryOptions = {},
): Promise<DashboardPayload> {
  const eventsQuery = withDefaults<EventsQuery>(
    { limit: 8, sort_direction: 'desc', sort_by: 'created_at' },
    options.events,
  )
  const blockedQuery = withDefaults<BlockedIpsQuery>(
    {
      limit: 8,
      active_only: true,
      sort_direction: 'desc',
      sort_by: 'blocked_at',
    },
    options.blockedIps,
  )
  const eventsPath = `/events${buildQuery(eventsQuery)}`
  const blockedPath = `/blocked-ips${buildQuery(blockedQuery)}`

  const [health, metrics, events, blockedIps, rules] = await Promise.all([
    apiRequest<HealthResponse>('/health'),
    apiRequest<MetricsResponse>('/metrics'),
    apiRequest<SecurityEventsResponse>(eventsPath),
    apiRequest<BlockedIpsResponse>(blockedPath),
    apiRequest<RulesResponse>('/rules'),
  ])

  return { health, metrics, events, blockedIps, rules }
}

export async function fetchTrafficMap(
  options: TrafficMapQuery = {},
): Promise<TrafficMapResponse> {
  return apiRequest<TrafficMapResponse>(
    `/dashboard/traffic-map${buildQuery(options)}`,
  )
}

export async function fetchAiAuditSummary(
  options: AiAuditSummaryQuery = {},
): Promise<AiAuditSummaryResponse> {
  return apiRequest<AiAuditSummaryResponse>(
    `/dashboard/ai-audit-summary${buildQuery(options)}`,
  )
}

export async function fetchAiAuditReport(
  options: AiAuditSummaryQuery = {},
): Promise<AiAuditReportResponse> {
  return apiRequest<AiAuditReportResponse>(
    `/dashboard/ai-audit-report${buildQuery(options)}`,
  )
}
