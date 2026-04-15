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
  AiAuditRunPayload,
  AiAuditReportsQuery,
  AiAuditReportsResponse,
  AiAutoAuditStatus,
  AiAuditFeedbackUpdatePayload,
  AiTempPoliciesResponse,
  TrafficMapQuery,
  TrafficMapResponse,
  WriteStatusResponse,
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

export async function fetchAiAuditReport(): Promise<AiAuditReportResponse> {
  return apiRequest<AiAuditReportResponse>('/dashboard/ai-audit-report')
}

export async function runAiAuditReport(
  payload: AiAuditRunPayload = {},
): Promise<AiAuditReportResponse> {
  return apiRequest<AiAuditReportResponse>('/dashboard/ai-audit-report/run', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function fetchAiAuditReports(
  options: AiAuditReportsQuery = {},
): Promise<AiAuditReportsResponse> {
  return apiRequest<AiAuditReportsResponse>(
    `/dashboard/ai-audit-reports${buildQuery(options)}`,
  )
}

export async function fetchAiAutoAuditStatus(): Promise<AiAutoAuditStatus> {
  return apiRequest<AiAutoAuditStatus>('/dashboard/ai-auto-audit-status')
}

export async function updateAiAuditReportFeedback(
  id: number,
  payload: AiAuditFeedbackUpdatePayload,
): Promise<WriteStatusResponse> {
  return apiRequest<WriteStatusResponse>(
    `/dashboard/ai-audit-reports/${id}/feedback`,
    {
      method: 'PATCH',
      body: JSON.stringify(payload),
    },
  )
}

export async function fetchAiTempPolicies(): Promise<AiTempPoliciesResponse> {
  return apiRequest<AiTempPoliciesResponse>('/dashboard/ai-temp-policies')
}

export async function deleteAiTempPolicy(
  id: number,
): Promise<WriteStatusResponse> {
  return apiRequest<WriteStatusResponse>(`/dashboard/ai-temp-policies/${id}`, {
    method: 'DELETE',
  })
}
