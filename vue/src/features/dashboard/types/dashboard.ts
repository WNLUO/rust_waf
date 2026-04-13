import type {
  BlockedIpsResponse,
  EventsQuery,
  SecurityEventsResponse,
  BlockedIpsQuery,
} from '@/features/events/types/events'
import type { RulesResponse } from '@/features/rules/types/rules'
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

export interface EventMapNode {
  id: string
  name: string
  region: string
  role: 'cdn' | 'origin'
  x: number
  y: number
  lat?: number
  lng?: number
  trafficWeight: number
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
