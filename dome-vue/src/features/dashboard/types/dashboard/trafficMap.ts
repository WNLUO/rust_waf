import type { SecurityEventItem } from '@/features/events/types/events'
import type { ApiQueryValue } from '@/shared/types/common'

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
  countryCode?: string | null
  countryName?: string | null
  geoScope?: 'domestic' | 'global' | 'internal' | 'unknown' | string
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
  country_code?: string | null
  country_name?: string | null
  geo_scope?: 'domestic' | 'global' | 'internal' | 'unknown' | string
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
  country_code?: string | null
  country_name?: string | null
  geo_scope?: 'domestic' | 'global' | 'internal' | 'unknown' | string
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
