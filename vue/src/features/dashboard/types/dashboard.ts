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
  host: string | null
  site_domain: string | null
  http_method: string | null
  uri: string | null
  provider: string | null
  provider_site_name: string | null
  provider_site_domain: string | null
  details_available: boolean
  details_slimmed: boolean
  decision_summary: SecurityEventDecisionSummary | null
}

export interface AiAuditDataQuality {
  persisted_security_events: number
  dropped_security_events: number
  sqlite_queue_depth: number
  sqlite_queue_capacity: number
  sqlite_queue_usage_percent: number
  detail_slimming_active: boolean
  sample_coverage_ratio: number
  persistence_coverage_ratio: number
  raw_samples_included: boolean
  recent_events_count: number
  analysis_confidence: string
}

export interface AiAuditTrendWindow {
  label: string
  window_seconds: number
  total_events: number
  sampled_events: number
  blocked_events: number
  challenged_events: number
  delayed_events: number
  action_breakdown: AiAuditCountItem[]
  top_source_ips: AiAuditCountItem[]
  top_routes: AiAuditCountItem[]
  top_hosts: AiAuditCountItem[]
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
  runtime_pressure_level: string
  degraded_reasons: string[]
  data_quality: AiAuditDataQuality
  current: AiAuditCurrentState
  counters: AiAuditCounters
  action_breakdown: AiAuditCountItem[]
  provider_breakdown: AiAuditCountItem[]
  identity_states: AiAuditCountItem[]
  primary_signals: AiAuditCountItem[]
  labels: AiAuditCountItem[]
  top_source_ips: AiAuditCountItem[]
  top_routes: AiAuditCountItem[]
  top_hosts: AiAuditCountItem[]
  safeline_correlation: AiAuditSafeLineCorrelation
  trend_windows: AiAuditTrendWindow[]
  recent_policy_feedback: AiAuditPolicyFeedback[]
  recent_events: AiAuditEventSample[]
}

export interface AiAuditPolicyFeedback {
  policy_key: string
  title: string
  action: string
  scope_type: string
  scope_value: string
  action_status: string
  action_reason: string
  primary_object: string | null
  primary_object_hits: number
  hit_count: number
  updated_at: number
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
  recent_policy_feedback_count: number
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
  runtime_pressure_level: string
  degraded_reasons: string[]
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
  auto_generated: boolean
  auto_trigger_reason: string | null
  report: AiAuditReportResponse
}

export interface AiAuditReportsResponse {
  total: number
  limit: number
  offset: number
  reports: AiAuditReportHistoryItem[]
}

export interface AiAutoAuditStatus {
  enabled: boolean
  interval_secs: number
  cooldown_secs: number
  on_pressure_high: boolean
  on_attack_mode: boolean
  on_hotspot_shift: boolean
  force_local_rules_under_attack: boolean
  last_run_at: number | null
  last_completed_at: number | null
  last_trigger_signature: string | null
  last_observed_signature: string | null
  last_trigger_reason: string | null
  last_report_id: number | null
}

export interface AiAutomationOverviewResponse {
  generated_at: number
  available: boolean
  unavailable_reason: string | null
  provider: string
  fallback_to_rules: boolean
  auto_apply_temp_policies: boolean
  active_policy_count: number
  max_active_policy_count: number
  status: AiAutoAuditStatus
  window_seconds: number
  sampled_events: number
  total_events: number
  active_rules: number
  runtime_pressure_level: string
  degraded_reasons: string[]
  data_quality: AiAuditDataQuality
  current: AiAuditCurrentState
  counters: AiAuditCounters
  trend_windows: AiAuditTrendWindow[]
  top_signals: AiAuditCountItem[]
  top_routes: AiAuditCountItem[]
  recent_policy_feedback: AiAuditPolicyFeedback[]
}

export interface BotVerifierStatusResponse {
  generated_at: number
  providers: BotVerifierProviderStatus[]
}

export interface BotVerifierProviderStatus {
  provider: string
  range_count: number
  last_refresh_at: number | null
  last_success_at: number | null
  last_error: string | null
  status: string
}

export interface BotInsightsResponse {
  generated_at: number
  window_start: number
  total_bot_events: number
  by_trust_class: AiAuditCountItem[]
  top_bot_names: AiAuditCountItem[]
  top_mismatch_ips: AiAuditCountItem[]
  top_routes: AiAuditCountItem[]
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
  matched_value_hits: Record<string, number>
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
  primary_object: string | null
  primary_object_hits: number
}

export interface AiTempPoliciesResponse {
  total: number
  policies: AiTempPolicyItem[]
}

export interface AiVisitorRouteSummary {
  route: string
  count: number
}

export interface AiVisitorProfileSignal {
  identity_key: string
  identity_source: string
  site_id: string
  client_ip: string
  user_agent: string
  state: string
  first_seen_at: number
  last_seen_at: number
  request_count: number
  document_count: number
  api_count: number
  static_count: number
  admin_count: number
  challenge_count: number
  challenge_verified_count: number
  challenge_page_report_count: number
  challenge_js_report_count: number
  fingerprint_seen: boolean
  upstream_success_count: number
  upstream_redirect_count: number
  upstream_client_error_count: number
  upstream_error_count: number
  auth_required_route_count: number
  auth_success_count: number
  auth_rejected_count: number
  human_confidence: number
  automation_risk: number
  probe_risk: number
  abuse_risk: number
  false_positive_risk: string
  tracking_priority: string
  route_summary: AiVisitorRouteSummary[]
  business_route_types: Record<string, number>
  status_codes: Record<string, number>
  flags: string[]
  ai_rationale: string
}

export interface AiVisitorDecisionSignal {
  decision_key: string
  identity_key: string
  site_id: string
  action: string
  confidence: number
  ttl_secs: number
  rationale: string
  applied: boolean
  effect_status: string
}

export interface AiVisitorIntelligenceResponse {
  generated_at: number
  enabled: boolean
  degraded_reason: string | null
  active_profile_count: number
  profiles: AiVisitorProfileSignal[]
  recommendations: AiVisitorDecisionSignal[]
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
