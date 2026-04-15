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

export interface AiAuditRunPayload {
  window_seconds?: number
  sample_limit?: number
  recent_limit?: number
  provider?: string
  fallback_to_rules?: boolean
}

export interface AiAuditReportsQuery extends Record<string, ApiQueryValue> {
  limit?: number
  offset?: number
  feedback_status?: string
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
  l4_bucket_budget_rejections: number
  trusted_proxy_permit_drops: number
  trusted_proxy_l4_degrade_actions: number
  l4_request_budget_softened: number
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
  safeline_correlation: AiAuditSafeLineCorrelation
  recent_events: AiAuditEventSample[]
}

export interface AiAuditSafeLineCorrelation {
  safeline_events: number
  rust_events: number
  rust_persistence_percent: number
  safeline_top_hosts: AiAuditCountItem[]
  rust_top_hosts: AiAuditCountItem[]
  overlap_hosts: AiAuditCountItem[]
  overlap_routes: AiAuditCountItem[]
  overlap_source_ips: AiAuditCountItem[]
  persistent_overlap_hosts: AiAuditCountItem[]
  persistent_overlap_routes: AiAuditCountItem[]
  persistent_overlap_source_ips: AiAuditCountItem[]
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
  action_type: string
  rule_suggestion_key?: string | null
}

export interface AiAuditInputProfile {
  source: string
  sampled_events: number
  included_recent_events: number
  raw_samples_included: boolean
}

export interface AiAuditSuggestedRule {
  key: string
  title: string
  policy_type: string
  layer: string
  scope_type: string
  scope_value: string
  target: string
  action: string
  operator: string
  suggested_value: string
  ttl_secs: number
  auto_apply: boolean
  rationale: string
}

export interface AiAuditReportResponse {
  report_id?: number | null
  generated_at: number
  provider_used: string
  fallback_used: boolean
  analysis_mode: string
  execution_notes: string[]
  risk_level: string
  headline: string
  executive_summary: string[]
  input_profile: AiAuditInputProfile
  findings: AiAuditReportFinding[]
  recommendations: AiAuditReportRecommendation[]
  suggested_local_rules: AiAuditSuggestedRule[]
  summary: AiAuditSummaryResponse
}

export interface AiAuditReportHistoryItem {
  id: number
  generated_at: number
  provider_used: string
  fallback_used: boolean
  risk_level: string
  headline: string
  feedback_status: string | null
  feedback_notes: string | null
  feedback_updated_at: number | null
  report: AiAuditReportResponse
}

export interface AiAuditReportsResponse {
  total: number
  limit: number
  offset: number
  reports: AiAuditReportHistoryItem[]
}

export interface AiTempPolicyItem {
  id: number
  created_at: number
  updated_at: number
  expires_at: number
  policy_key: string
  title: string
  policy_type: string
  layer: string
  scope_type: string
  scope_value: string
  action: string
  operator: string
  suggested_value: string
  rationale: string
  confidence: number
  auto_applied: boolean
  hit_count: number
  last_hit_at: number | null
  effect: AiTempPolicyEffect
  effectiveness: AiTempPolicyEffectiveness
}

export interface AiTempPolicyEffect {
  baseline_l7_friction_percent: number | null
  baseline_identity_pressure_percent: number | null
  baseline_rust_persistence_percent: number | null
  auto_extensions: number
  auto_revoked: boolean
  auto_revoke_reason: string | null
  last_effectiveness_check_at: number | null
  total_hits: number
  first_hit_at: number | null
  last_hit_at: number | null
  last_scope_type: string | null
  last_scope_value: string | null
  last_matched_value: string | null
  last_match_mode: string | null
  action_hits: Record<string, number>
  match_modes: Record<string, number>
  scope_hits: Record<string, number>
}

export interface AiTempPolicyEffectiveness {
  current_l7_friction_percent: number
  current_identity_pressure_percent: number
  current_rust_persistence_percent: number
  l7_friction_delta: number | null
  identity_pressure_delta: number | null
  rust_persistence_delta: number | null
  action_status: string
  action_reason: string
  governance_hint: string
}

export interface AiTempPoliciesResponse {
  total: number
  policies: AiTempPolicyItem[]
}

export interface AiAuditFeedbackUpdatePayload {
  feedback_status?: 'confirmed' | 'false_positive' | 'follow_up' | null
  feedback_notes?: string | null
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
