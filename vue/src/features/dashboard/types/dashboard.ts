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
