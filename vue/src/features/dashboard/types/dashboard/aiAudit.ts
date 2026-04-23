import type { SecurityEventDecisionSummary } from '@/features/events/types/events'
import type { ApiQueryValue } from '@/shared/types/common'

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
  runtime_defense_depth: string
  runtime_defense_base_stage: string
  runtime_defense_stage: string
  runtime_defense_stage_score: number
  runtime_defense_stage_reason: string
  auto_tuning_controller_state: string
  auto_tuning_last_adjust_reason: string | null
  auto_tuning_last_adjust_diff: string[]
  auto_tuning_recovery_windows: number
  auto_tuning_pressure_memory_windows: number
  identity_pressure_percent: number
  l7_friction_pressure_percent: number
  slow_attack_pressure_percent: number
  challenge_issued: number
  challenge_verified: number
  challenge_verify_rate_percent: number
  challenge_block_rate_percent: number
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
  l7_ip_access_allows: number
  l7_ip_access_alerts: number
  l7_ip_access_challenges: number
  l7_ip_access_blocks: number
  l7_ip_access_verified_passes: number
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
