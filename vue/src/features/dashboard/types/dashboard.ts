import type {
  BlockedIpsResponse,
  EventsQuery,
  SecurityEventsResponse,
  BlockedIpsQuery,
} from '@/features/events/types/events'
import type { RulesResponse } from '@/features/rules/types/rules'
import type { ApiQueryValue } from '@/shared/types/common'
import type { HealthResponse, MetricsResponse } from '@/shared/types/system'
import type { SecurityEventItem } from '@/features/events/types/events'
import type { SecurityEventDecisionSummary } from '@/features/events/types/events'

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

export type EventMapScope = 'china' | 'global'

export interface TrafficMapQuery extends Record<string, ApiQueryValue> {
  window_seconds?: number
}

export interface AiAuditSummaryQuery extends Record<string, ApiQueryValue> {
  window_seconds?: number
  sample_limit?: number
  recent_limit?: number
}

export interface AiAuditCountItem {
  key: string
  count: number
}

export interface AiAuditEventSample {
  id: number
  created_at: number
  layer: string
  action: string
  reason: string
  source_ip: string
  uri: string | null
  provider: string | null
  decision_summary: SecurityEventDecisionSummary | null
}

export interface AiAuditCurrentState {
  adaptive_system_pressure: string
  adaptive_reasons: string[]
  l4_overload_level: string
  auto_tuning_controller_state: string
  auto_tuning_last_adjust_reason: string | null
  auto_tuning_last_adjust_diff: string[]
  identity_pressure_percent: number
  l7_friction_pressure_percent: number
  slow_attack_pressure_percent: number
}

export interface AiAuditCounters {
  proxied_requests: number
  blocked_packets: number
  blocked_l4: number
  blocked_l7: number
  l7_cc_challenges: number
  l7_cc_blocks: number
  l7_cc_delays: number
  l7_behavior_challenges: number
  l7_behavior_blocks: number
  l7_behavior_delays: number
  trusted_proxy_permit_drops: number
  trusted_proxy_l4_degrade_actions: number
  slow_attack_hits: number
  average_proxy_latency_micros: number
}

export interface AiAuditSummaryResponse {
  generated_at: number
  window_seconds: number
  sampled_events: number
  total_events: number
  active_rules: number
  current: AiAuditCurrentState
  counters: AiAuditCounters
  identity_states: AiAuditCountItem[]
  primary_signals: AiAuditCountItem[]
  labels: AiAuditCountItem[]
  top_source_ips: AiAuditCountItem[]
  top_routes: AiAuditCountItem[]
  top_hosts: AiAuditCountItem[]
  recent_events: AiAuditEventSample[]
}

export interface AiAuditReportFinding {
  key: string
  severity: string
  title: string
  detail: string
  evidence: string[]
}

export interface AiAuditReportRecommendation {
  key: string
  priority: string
  title: string
  action: string
  rationale: string
}

export interface AiAuditReportResponse {
  generated_at: number
  risk_level: string
  headline: string
  executive_summary: string[]
  findings: AiAuditReportFinding[]
  recommendations: AiAuditReportRecommendation[]
  summary: AiAuditSummaryResponse
}

export interface EventMapNode {
  id: string
  name: string
  region: string
  role: 'cdn' | 'origin'
  lat?: number
  lng?: number
  trafficWeight: number
  requestCount?: number
  blockedCount?: number
  bandwidthMbps?: number
  lastSeenAt?: number
}

export interface EventMapFlow {
  id: string
  nodeId: string
  direction: 'ingress' | 'egress'
  decision: 'allow' | 'block'
  intensity: number
  bandwidthMbps: number
  requestsPerSecond: number
  startedAt: number
  durationMs: number
  reason: string
  event?: SecurityEventItem
  requestCount?: number
  bytes?: number
  averageLatencyMs?: number
}

export interface EventMapSnapshot {
  scope: EventMapScope
  nodes: EventMapNode[]
  flows: EventMapFlow[]
  originNode: EventMapNode
  liveTrafficScore: number
  activeNodeCount: number
  peakBandwidthMbps: number
  allowedFlowCount: number
  blockedFlowCount: number
  hottestNode: EventMapNode | null
}

export interface TrafficMapNodeResponse {
  id: string
  name: string
  region: string
  role: 'cdn' | 'origin' | string
  lat?: number
  lng?: number
  traffic_weight: number
  request_count: number
  blocked_count: number
  bandwidth_mbps: number
  last_seen_at: number
}

export interface TrafficMapFlowResponse {
  id: string
  node_id: string
  direction: 'ingress' | 'egress'
  decision: 'allow' | 'block'
  request_count: number
  bytes: number
  bandwidth_mbps: number
  average_latency_ms: number
  last_seen_at: number
}

export interface TrafficMapResponse {
  scope: EventMapScope
  window_seconds: number
  generated_at: number
  origin_node: TrafficMapNodeResponse
  nodes: TrafficMapNodeResponse[]
  flows: TrafficMapFlowResponse[]
  active_node_count: number
  peak_bandwidth_mbps: number
  allowed_flow_count: number
  blocked_flow_count: number
  live_traffic_score: number
}

export interface TrafficEventDeltaNode {
  id: string
  name: string
  region: string
  role: 'cdn' | 'origin' | string
  lat?: number
  lng?: number
}

export interface TrafficEventDelta {
  timestamp_ms: number
  direction: 'ingress' | 'egress'
  decision: 'allow' | 'block'
  bytes: number
  latency_ms?: number | null
  source_ip: string
  node: TrafficEventDeltaNode
}
