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
