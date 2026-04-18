use serde::{Deserialize, Serialize};

use super::{SecurityEventDecisionSummary, SecurityEventResponse};

#[derive(Debug, Serialize)]
pub struct TrafficMapNodeResponse {
    pub(crate) id: String,
    pub(crate) name: String,
    pub(crate) region: String,
    pub(crate) role: String,
    pub(crate) lat: Option<f64>,
    pub(crate) lng: Option<f64>,
    pub(crate) country_code: Option<String>,
    pub(crate) country_name: Option<String>,
    pub(crate) geo_scope: String,
    pub(crate) traffic_weight: f64,
    pub(crate) request_count: u64,
    pub(crate) blocked_count: u64,
    pub(crate) bandwidth_mbps: f64,
    pub(crate) last_seen_at: i64,
}

#[derive(Debug, Serialize)]
pub struct TrafficMapFlowResponse {
    pub(crate) id: String,
    pub(crate) node_id: String,
    pub(crate) direction: String,
    pub(crate) decision: String,
    pub(crate) request_count: u64,
    pub(crate) bytes: u64,
    pub(crate) bandwidth_mbps: f64,
    pub(crate) average_latency_ms: u64,
    pub(crate) last_seen_at: i64,
}

#[derive(Debug, Serialize)]
pub struct TrafficMapResponse {
    pub(crate) scope: String,
    pub(crate) window_seconds: u32,
    pub(crate) generated_at: i64,
    pub(crate) runtime_pressure_level: String,
    pub(crate) degraded_reasons: Vec<String>,
    pub(crate) origin_node: TrafficMapNodeResponse,
    pub(crate) nodes: Vec<TrafficMapNodeResponse>,
    pub(crate) flows: Vec<TrafficMapFlowResponse>,
    pub(crate) active_node_count: u32,
    pub(crate) peak_bandwidth_mbps: f64,
    pub(crate) allowed_flow_count: u32,
    pub(crate) blocked_flow_count: u32,
    pub(crate) live_traffic_score: f64,
}

#[derive(Debug, Deserialize, Default)]
pub struct TrafficMapQueryParams {
    pub(crate) window_seconds: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AiAuditSummaryQueryParams {
    pub(crate) window_seconds: Option<u32>,
    pub(crate) sample_limit: Option<u32>,
    pub(crate) recent_limit: Option<u32>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AiAuditReportQueryParams {
    pub(crate) window_seconds: Option<u32>,
    pub(crate) sample_limit: Option<u32>,
    pub(crate) recent_limit: Option<u32>,
    pub(crate) provider: Option<String>,
    pub(crate) fallback_to_rules: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AiAuditRunRequest {
    pub(crate) window_seconds: Option<u32>,
    pub(crate) sample_limit: Option<u32>,
    pub(crate) recent_limit: Option<u32>,
    pub(crate) provider: Option<String>,
    pub(crate) fallback_to_rules: Option<bool>,
}

#[derive(Debug, Deserialize, Default)]
pub struct AiAuditReportsQueryParams {
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u32>,
    pub(crate) feedback_status: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditSummaryResponse {
    #[serde(default)]
    pub(crate) generated_at: i64,
    #[serde(default)]
    pub(crate) window_seconds: u32,
    #[serde(default)]
    pub(crate) sampled_events: u32,
    #[serde(default)]
    pub(crate) total_events: u64,
    #[serde(default)]
    pub(crate) active_rules: u64,
    #[serde(default)]
    pub(crate) runtime_pressure_level: String,
    #[serde(default)]
    pub(crate) degraded_reasons: Vec<String>,
    #[serde(default)]
    pub(crate) data_quality: AiAuditDataQualityResponse,
    #[serde(default)]
    pub(crate) current: AiAuditCurrentStateResponse,
    #[serde(default)]
    pub(crate) counters: AiAuditCountersResponse,
    #[serde(default)]
    pub(crate) action_breakdown: Vec<AiAuditCountItem>,
    #[serde(default)]
    pub(crate) provider_breakdown: Vec<AiAuditCountItem>,
    #[serde(default)]
    pub(crate) identity_states: Vec<AiAuditCountItem>,
    #[serde(default)]
    pub(crate) primary_signals: Vec<AiAuditCountItem>,
    #[serde(default)]
    pub(crate) labels: Vec<AiAuditCountItem>,
    #[serde(default)]
    pub(crate) top_source_ips: Vec<AiAuditCountItem>,
    #[serde(default)]
    pub(crate) top_routes: Vec<AiAuditCountItem>,
    #[serde(default)]
    pub(crate) top_hosts: Vec<AiAuditCountItem>,
    #[serde(default)]
    pub(crate) safeline_correlation: AiAuditSafeLineCorrelationResponse,
    #[serde(default)]
    pub(crate) trend_windows: Vec<AiAuditTrendWindowResponse>,
    #[serde(default)]
    pub(crate) recent_policy_feedback: Vec<AiAuditPolicyFeedbackResponse>,
    #[serde(default)]
    pub(crate) recent_events: Vec<AiAuditEventSampleResponse>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditDataQualityResponse {
    #[serde(default)]
    pub(crate) persisted_security_events: u64,
    #[serde(default)]
    pub(crate) dropped_security_events: u64,
    #[serde(default)]
    pub(crate) sqlite_queue_depth: u64,
    #[serde(default)]
    pub(crate) sqlite_queue_capacity: u64,
    #[serde(default)]
    pub(crate) sqlite_queue_usage_percent: f64,
    #[serde(default)]
    pub(crate) detail_slimming_active: bool,
    #[serde(default)]
    pub(crate) sample_coverage_ratio: f64,
    #[serde(default)]
    pub(crate) persistence_coverage_ratio: f64,
    #[serde(default)]
    pub(crate) raw_samples_included: bool,
    #[serde(default)]
    pub(crate) recent_events_count: u32,
    #[serde(default)]
    pub(crate) analysis_confidence: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditTrendWindowResponse {
    #[serde(default)]
    pub(crate) label: String,
    #[serde(default)]
    pub(crate) window_seconds: u32,
    #[serde(default)]
    pub(crate) total_events: u64,
    #[serde(default)]
    pub(crate) sampled_events: u32,
    #[serde(default)]
    pub(crate) blocked_events: u64,
    #[serde(default)]
    pub(crate) challenged_events: u64,
    #[serde(default)]
    pub(crate) delayed_events: u64,
    #[serde(default)]
    pub(crate) action_breakdown: Vec<AiAuditCountItem>,
    #[serde(default)]
    pub(crate) top_source_ips: Vec<AiAuditCountItem>,
    #[serde(default)]
    pub(crate) top_routes: Vec<AiAuditCountItem>,
    #[serde(default)]
    pub(crate) top_hosts: Vec<AiAuditCountItem>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditPolicyFeedbackResponse {
    pub(crate) policy_key: String,
    pub(crate) title: String,
    pub(crate) action: String,
    pub(crate) scope_type: String,
    pub(crate) scope_value: String,
    pub(crate) action_status: String,
    pub(crate) action_reason: String,
    pub(crate) primary_object: Option<String>,
    pub(crate) primary_object_hits: i64,
    pub(crate) hit_count: i64,
    pub(crate) updated_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditSafeLineCorrelationResponse {
    pub(crate) safeline_events: u64,
    pub(crate) rust_events: u64,
    pub(crate) rust_persistence_percent: f64,
    pub(crate) safeline_top_hosts: Vec<AiAuditCountItem>,
    pub(crate) rust_top_hosts: Vec<AiAuditCountItem>,
    pub(crate) overlap_hosts: Vec<AiAuditCountItem>,
    pub(crate) overlap_routes: Vec<AiAuditCountItem>,
    pub(crate) overlap_source_ips: Vec<AiAuditCountItem>,
    pub(crate) persistent_overlap_hosts: Vec<AiAuditCountItem>,
    pub(crate) persistent_overlap_routes: Vec<AiAuditCountItem>,
    pub(crate) persistent_overlap_source_ips: Vec<AiAuditCountItem>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditReportResponse {
    #[serde(default)]
    pub(crate) report_id: Option<i64>,
    #[serde(default)]
    pub(crate) generated_at: i64,
    #[serde(default)]
    pub(crate) runtime_pressure_level: String,
    #[serde(default)]
    pub(crate) degraded_reasons: Vec<String>,
    #[serde(default)]
    pub(crate) provider_used: String,
    #[serde(default)]
    pub(crate) fallback_used: bool,
    #[serde(default)]
    pub(crate) analysis_mode: String,
    #[serde(default)]
    pub(crate) execution_notes: Vec<String>,
    #[serde(default)]
    pub(crate) risk_level: String,
    #[serde(default)]
    pub(crate) headline: String,
    #[serde(default)]
    pub(crate) executive_summary: Vec<String>,
    #[serde(default)]
    pub(crate) input_profile: AiAuditInputProfileResponse,
    #[serde(default)]
    pub(crate) findings: Vec<AiAuditReportFinding>,
    #[serde(default)]
    pub(crate) recommendations: Vec<AiAuditReportRecommendation>,
    #[serde(default)]
    pub(crate) suggested_local_rules: Vec<AiAuditSuggestedRuleResponse>,
    #[serde(default)]
    pub(crate) summary: AiAuditSummaryResponse,
}

#[derive(Debug, Serialize)]
pub struct AiAuditReportsResponse {
    pub(crate) total: u64,
    pub(crate) limit: u32,
    pub(crate) offset: u32,
    pub(crate) reports: Vec<AiAuditReportHistoryItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiAutoAuditStatusResponse {
    pub(crate) enabled: bool,
    pub(crate) interval_secs: u64,
    pub(crate) cooldown_secs: u64,
    pub(crate) on_pressure_high: bool,
    pub(crate) on_attack_mode: bool,
    pub(crate) on_hotspot_shift: bool,
    pub(crate) force_local_rules_under_attack: bool,
    pub(crate) last_run_at: Option<i64>,
    pub(crate) last_completed_at: Option<i64>,
    pub(crate) last_trigger_signature: Option<String>,
    pub(crate) last_observed_signature: Option<String>,
    pub(crate) last_trigger_reason: Option<String>,
    pub(crate) last_report_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct AiAutomationOverviewResponse {
    pub(crate) generated_at: i64,
    pub(crate) available: bool,
    pub(crate) unavailable_reason: Option<String>,
    pub(crate) provider: String,
    pub(crate) fallback_to_rules: bool,
    pub(crate) auto_apply_temp_policies: bool,
    pub(crate) active_policy_count: u32,
    pub(crate) max_active_policy_count: u32,
    pub(crate) status: AiAutoAuditStatusResponse,
    pub(crate) window_seconds: u32,
    pub(crate) sampled_events: u32,
    pub(crate) total_events: u64,
    pub(crate) active_rules: u64,
    pub(crate) runtime_pressure_level: String,
    pub(crate) degraded_reasons: Vec<String>,
    pub(crate) data_quality: AiAuditDataQualityResponse,
    pub(crate) current: AiAuditCurrentStateResponse,
    pub(crate) counters: AiAuditCountersResponse,
    pub(crate) trend_windows: Vec<AiAuditTrendWindowResponse>,
    pub(crate) top_signals: Vec<AiAuditCountItem>,
    pub(crate) top_routes: Vec<AiAuditCountItem>,
    pub(crate) recent_policy_feedback: Vec<AiAuditPolicyFeedbackResponse>,
}

#[derive(Debug, Serialize)]
pub struct AiTempPoliciesResponse {
    pub(crate) total: u32,
    pub(crate) policies: Vec<AiTempPolicyResponse>,
}

#[derive(Debug, Serialize)]
pub struct AiDefenseSnapshotResponse {
    pub(crate) generated_at: i64,
    pub(crate) enabled: bool,
    pub(crate) auto_apply: bool,
    pub(crate) trigger_reason: Option<String>,
    pub(crate) trigger_pending_secs: u64,
    pub(crate) runtime_pressure: AiDefenseRuntimePressureResponse,
    pub(crate) l4_pressure: Option<AiDefenseL4PressureResponse>,
    pub(crate) upstream_health: AiDefenseUpstreamHealthResponse,
    pub(crate) active_temp_policy_count: u32,
    pub(crate) max_active_temp_policy_count: u32,
    pub(crate) active_policies: Vec<AiTempPolicyResponse>,
    pub(crate) route_effects: Vec<AiDefenseRouteEffectResponse>,
    pub(crate) policy_effects: Vec<AiDefensePolicyEffectResponse>,
    pub(crate) identity_summaries: Vec<AiDefenseIdentityResponse>,
    pub(crate) route_profiles: Vec<AiDefenseRouteProfileSignalResponse>,
    pub(crate) local_recommendations: Vec<LocalDefenseRecommendationResponse>,
    pub(crate) server_public_ips: ServerPublicIpSnapshotResponse,
    pub(crate) visitor_intelligence: AiVisitorIntelligenceResponse,
}

#[derive(Debug, Serialize)]
pub struct BotVerifierStatusResponse {
    pub(crate) generated_at: i64,
    pub(crate) providers: Vec<BotVerifierProviderStatusResponse>,
}

#[derive(Debug, Serialize)]
pub struct BotVerifierProviderStatusResponse {
    pub(crate) provider: String,
    pub(crate) range_count: usize,
    pub(crate) last_refresh_at: Option<i64>,
    pub(crate) last_success_at: Option<i64>,
    pub(crate) last_error: Option<String>,
    pub(crate) status: String,
}

#[derive(Debug, Serialize)]
pub struct BotInsightsResponse {
    pub(crate) generated_at: i64,
    pub(crate) window_start: i64,
    pub(crate) total_bot_events: u64,
    pub(crate) by_trust_class: Vec<AiAuditCountItem>,
    pub(crate) top_bot_names: Vec<AiAuditCountItem>,
    pub(crate) top_mismatch_ips: Vec<AiAuditCountItem>,
    pub(crate) top_routes: Vec<AiAuditCountItem>,
}

#[derive(Debug, Serialize)]
pub struct ServerPublicIpSnapshotResponse {
    pub(crate) ips: Vec<String>,
    pub(crate) last_refresh_at: Option<i64>,
    pub(crate) last_success_at: Option<i64>,
    pub(crate) last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AiVisitorIntelligenceResponse {
    pub(crate) generated_at: i64,
    pub(crate) enabled: bool,
    pub(crate) degraded_reason: Option<String>,
    pub(crate) active_profile_count: usize,
    pub(crate) profiles: Vec<AiVisitorProfileSignalResponse>,
    pub(crate) recommendations: Vec<AiVisitorDecisionSignalResponse>,
}

#[derive(Debug, Serialize)]
pub struct AiVisitorProfileSignalResponse {
    pub(crate) identity_key: String,
    pub(crate) identity_source: String,
    pub(crate) site_id: String,
    pub(crate) client_ip: String,
    pub(crate) user_agent: String,
    pub(crate) state: String,
    pub(crate) first_seen_at: i64,
    pub(crate) last_seen_at: i64,
    pub(crate) request_count: u64,
    pub(crate) document_count: u64,
    pub(crate) api_count: u64,
    pub(crate) static_count: u64,
    pub(crate) admin_count: u64,
    pub(crate) challenge_count: u64,
    pub(crate) challenge_verified_count: u64,
    pub(crate) challenge_page_report_count: u64,
    pub(crate) challenge_js_report_count: u64,
    pub(crate) fingerprint_seen: bool,
    pub(crate) upstream_success_count: u64,
    pub(crate) upstream_redirect_count: u64,
    pub(crate) upstream_client_error_count: u64,
    pub(crate) upstream_error_count: u64,
    pub(crate) auth_required_route_count: u64,
    pub(crate) auth_success_count: u64,
    pub(crate) auth_rejected_count: u64,
    pub(crate) human_confidence: u8,
    pub(crate) automation_risk: u8,
    pub(crate) probe_risk: u8,
    pub(crate) abuse_risk: u8,
    pub(crate) false_positive_risk: String,
    pub(crate) tracking_priority: String,
    pub(crate) route_summary: Vec<AiVisitorRouteSummaryResponse>,
    pub(crate) business_route_types: std::collections::BTreeMap<String, u64>,
    pub(crate) status_codes: std::collections::BTreeMap<String, u64>,
    pub(crate) flags: Vec<String>,
    pub(crate) ai_rationale: String,
}

#[derive(Debug, Serialize)]
pub struct AiVisitorRouteSummaryResponse {
    pub(crate) route: String,
    pub(crate) count: u64,
}

#[derive(Debug, Serialize)]
pub struct AiVisitorDecisionSignalResponse {
    pub(crate) decision_key: String,
    pub(crate) identity_key: String,
    pub(crate) site_id: String,
    pub(crate) action: String,
    pub(crate) confidence: u8,
    pub(crate) ttl_secs: u64,
    pub(crate) rationale: String,
    pub(crate) applied: bool,
    pub(crate) effect_status: String,
}

#[derive(Debug, Serialize)]
pub struct AiDefenseRuntimePressureResponse {
    pub(crate) level: String,
    pub(crate) defense_depth: String,
    pub(crate) prefer_drop: bool,
    pub(crate) trim_event_persistence: bool,
    pub(crate) l7_friction_pressure_percent: f64,
    pub(crate) identity_pressure_percent: f64,
    pub(crate) avg_proxy_latency_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct AiDefenseL4PressureResponse {
    pub(crate) active_connections: u64,
    pub(crate) blocked_connections: u64,
    pub(crate) rate_limit_hits: u64,
    pub(crate) ddos_events: u64,
    pub(crate) protocol_anomalies: u64,
    pub(crate) defense_actions: u64,
    pub(crate) top_ports: Vec<AiDefensePortResponse>,
}

#[derive(Debug, Serialize)]
pub struct AiDefensePortResponse {
    pub(crate) port: String,
    pub(crate) connections: u64,
    pub(crate) blocks: u64,
    pub(crate) ddos_events: u64,
}

#[derive(Debug, Serialize)]
pub struct AiDefenseUpstreamHealthResponse {
    pub(crate) healthy: bool,
    pub(crate) last_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AiDefenseRouteEffectResponse {
    pub(crate) site_id: String,
    pub(crate) route: String,
    pub(crate) total_responses: u64,
    pub(crate) upstream_successes: u64,
    pub(crate) upstream_errors: u64,
    pub(crate) local_responses: u64,
    pub(crate) blocked_responses: u64,
    pub(crate) challenge_issued: u64,
    pub(crate) challenge_verified: u64,
    pub(crate) interactive_sessions: u64,
    pub(crate) policy_matched_responses: u64,
    pub(crate) suspected_false_positive_events: u64,
    pub(crate) status_families: std::collections::BTreeMap<String, u64>,
    pub(crate) status_codes: std::collections::BTreeMap<String, u64>,
    pub(crate) policy_actions: std::collections::BTreeMap<String, u64>,
    pub(crate) avg_latency_ms: Option<u64>,
    pub(crate) slow_responses: u64,
    pub(crate) false_positive_risk: String,
    pub(crate) effectiveness_hint: String,
}

#[derive(Debug, Serialize)]
pub struct AiDefensePolicyEffectResponse {
    pub(crate) policy_key: String,
    pub(crate) scope_type: String,
    pub(crate) scope_value: String,
    pub(crate) action: String,
    pub(crate) hit_count: i64,
    pub(crate) outcome_status: String,
    pub(crate) outcome_score: i64,
    pub(crate) observations: i64,
    pub(crate) upstream_errors: i64,
    pub(crate) suspected_false_positive_events: i64,
    pub(crate) challenge_verified: i64,
    pub(crate) pressure_after_observations: i64,
}

#[derive(Debug, Serialize)]
pub struct AiDefenseIdentityResponse {
    pub(crate) site_id: String,
    pub(crate) route: String,
    pub(crate) total_events: u64,
    pub(crate) distinct_client_count: usize,
    pub(crate) unresolved_events: u64,
    pub(crate) trusted_proxy_events: u64,
    pub(crate) verified_challenge_events: u64,
    pub(crate) interactive_session_events: u64,
    pub(crate) spoofed_forward_header_events: u64,
    pub(crate) top_user_agents: Vec<AiDefenseUserAgentResponse>,
}

#[derive(Debug, Serialize)]
pub struct AiDefenseUserAgentResponse {
    pub(crate) value: String,
    pub(crate) count: u64,
}

#[derive(Debug, Serialize)]
pub struct AiDefenseRouteProfileSignalResponse {
    pub(crate) site_id: String,
    pub(crate) route_pattern: String,
    pub(crate) match_mode: String,
    pub(crate) route_type: String,
    pub(crate) sensitivity: String,
    pub(crate) auth_required: String,
    pub(crate) normal_traffic_pattern: String,
    pub(crate) recommended_actions: Vec<String>,
    pub(crate) avoid_actions: Vec<String>,
    pub(crate) evidence: serde_json::Value,
    pub(crate) raw_confidence: i64,
    pub(crate) staleness_secs: Option<u64>,
    pub(crate) confidence: i64,
    pub(crate) source: String,
    pub(crate) status: String,
    pub(crate) rationale: String,
}

#[derive(Debug, Serialize)]
pub struct LocalDefenseRecommendationsResponse {
    pub(crate) total: u32,
    pub(crate) recommendations: Vec<LocalDefenseRecommendationResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LocalDefenseRecommendationResponse {
    pub(crate) key: String,
    pub(crate) title: String,
    pub(crate) site_id: String,
    pub(crate) route: String,
    pub(crate) defense_depth: String,
    pub(crate) soft_events: u64,
    pub(crate) hard_events: u64,
    pub(crate) total_events: u64,
    pub(crate) confidence: u8,
    pub(crate) suggested_rule: AiAuditSuggestedRuleResponse,
}

#[derive(Debug, Deserialize)]
pub struct AiRouteProfilesQueryParams {
    pub(crate) site_id: Option<String>,
    pub(crate) status: Option<String>,
    pub(crate) limit: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct AiRouteProfilesResponse {
    pub(crate) total: u32,
    pub(crate) profiles: Vec<AiRouteProfileResponse>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiRouteProfileResponse {
    pub(crate) id: i64,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) last_observed_at: Option<i64>,
    pub(crate) site_id: String,
    pub(crate) route_pattern: String,
    pub(crate) match_mode: String,
    pub(crate) route_type: String,
    pub(crate) sensitivity: String,
    pub(crate) auth_required: String,
    pub(crate) normal_traffic_pattern: String,
    pub(crate) recommended_actions: Vec<String>,
    pub(crate) avoid_actions: Vec<String>,
    pub(crate) evidence: serde_json::Value,
    pub(crate) confidence: i64,
    pub(crate) source: String,
    pub(crate) status: String,
    pub(crate) rationale: String,
    pub(crate) reviewed_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AiRouteProfileUpsertRequest {
    pub(crate) site_id: String,
    pub(crate) route_pattern: String,
    #[serde(default = "default_ai_route_profile_match_mode")]
    pub(crate) match_mode: String,
    #[serde(default = "default_ai_route_profile_unknown")]
    pub(crate) route_type: String,
    #[serde(default = "default_ai_route_profile_unknown")]
    pub(crate) sensitivity: String,
    #[serde(default = "default_ai_route_profile_unknown")]
    pub(crate) auth_required: String,
    #[serde(default = "default_ai_route_profile_unknown")]
    pub(crate) normal_traffic_pattern: String,
    #[serde(default)]
    pub(crate) recommended_actions: Vec<String>,
    #[serde(default)]
    pub(crate) avoid_actions: Vec<String>,
    #[serde(default)]
    pub(crate) evidence: serde_json::Value,
    #[serde(default)]
    pub(crate) confidence: i64,
    #[serde(default = "default_ai_route_profile_source")]
    pub(crate) source: String,
    #[serde(default = "default_ai_route_profile_status")]
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) rationale: String,
    pub(crate) last_observed_at: Option<i64>,
    pub(crate) reviewed_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct AiRouteProfileStatusUpdateRequest {
    pub(crate) status: String,
    pub(crate) reviewed_at: Option<i64>,
}

fn default_ai_route_profile_match_mode() -> String {
    "exact".to_string()
}

fn default_ai_route_profile_unknown() -> String {
    "unknown".to_string()
}

fn default_ai_route_profile_source() -> String {
    "ai_observed".to_string()
}

fn default_ai_route_profile_status() -> String {
    "candidate".to_string()
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AiTempPolicyEffectResponse {
    pub(crate) baseline_l7_friction_percent: Option<f64>,
    pub(crate) baseline_identity_pressure_percent: Option<f64>,
    pub(crate) baseline_rust_persistence_percent: Option<f64>,
    pub(crate) auto_extensions: i64,
    pub(crate) auto_revoked: bool,
    pub(crate) auto_revoke_reason: Option<String>,
    pub(crate) last_effectiveness_check_at: Option<i64>,
    pub(crate) total_hits: i64,
    pub(crate) first_hit_at: Option<i64>,
    pub(crate) last_hit_at: Option<i64>,
    pub(crate) last_scope_type: Option<String>,
    pub(crate) last_scope_value: Option<String>,
    pub(crate) last_matched_value: Option<String>,
    pub(crate) last_match_mode: Option<String>,
    pub(crate) action_hits: std::collections::BTreeMap<String, i64>,
    pub(crate) match_modes: std::collections::BTreeMap<String, i64>,
    pub(crate) scope_hits: std::collections::BTreeMap<String, i64>,
    pub(crate) matched_value_hits: std::collections::BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AiTempPolicyEffectivenessResponse {
    pub(crate) current_l7_friction_percent: f64,
    pub(crate) current_identity_pressure_percent: f64,
    pub(crate) current_rust_persistence_percent: f64,
    pub(crate) l7_friction_delta: Option<f64>,
    pub(crate) identity_pressure_delta: Option<f64>,
    pub(crate) rust_persistence_delta: Option<f64>,
    pub(crate) action_status: String,
    pub(crate) action_reason: String,
    pub(crate) governance_hint: String,
    pub(crate) primary_object: Option<String>,
    pub(crate) primary_object_hits: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiTempPolicyResponse {
    pub(crate) id: i64,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) policy_key: String,
    pub(crate) title: String,
    pub(crate) policy_type: String,
    pub(crate) layer: String,
    pub(crate) scope_type: String,
    pub(crate) scope_value: String,
    pub(crate) action: String,
    pub(crate) operator: String,
    pub(crate) suggested_value: String,
    pub(crate) rationale: String,
    pub(crate) confidence: i64,
    pub(crate) auto_applied: bool,
    pub(crate) hit_count: i64,
    pub(crate) last_hit_at: Option<i64>,
    pub(crate) effect: AiTempPolicyEffectResponse,
    pub(crate) effectiveness: AiTempPolicyEffectivenessResponse,
}

#[derive(Debug, Clone, Serialize)]
pub struct AiAuditReportHistoryItem {
    pub(crate) id: i64,
    pub(crate) generated_at: i64,
    pub(crate) provider_used: String,
    pub(crate) fallback_used: bool,
    pub(crate) risk_level: String,
    pub(crate) headline: String,
    pub(crate) feedback_status: Option<String>,
    pub(crate) feedback_notes: Option<String>,
    pub(crate) feedback_updated_at: Option<i64>,
    pub(crate) auto_generated: bool,
    pub(crate) auto_trigger_reason: Option<String>,
    pub(crate) report: AiAuditReportResponse,
}

#[derive(Debug, Deserialize)]
pub struct AiAuditFeedbackUpdateRequest {
    pub(crate) feedback_status: Option<String>,
    pub(crate) feedback_notes: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditCurrentStateResponse {
    #[serde(default)]
    pub(crate) adaptive_system_pressure: String,
    #[serde(default)]
    pub(crate) adaptive_reasons: Vec<String>,
    #[serde(default)]
    pub(crate) l4_overload_level: String,
    #[serde(default)]
    pub(crate) auto_tuning_controller_state: String,
    #[serde(default)]
    pub(crate) auto_tuning_last_adjust_reason: Option<String>,
    #[serde(default)]
    pub(crate) auto_tuning_last_adjust_diff: Vec<String>,
    #[serde(default)]
    pub(crate) identity_pressure_percent: f64,
    #[serde(default)]
    pub(crate) l7_friction_pressure_percent: f64,
    #[serde(default)]
    pub(crate) slow_attack_pressure_percent: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditReportFinding {
    #[serde(default)]
    pub(crate) key: String,
    #[serde(default)]
    pub(crate) severity: String,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) detail: String,
    #[serde(default)]
    pub(crate) evidence: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditReportRecommendation {
    #[serde(default)]
    pub(crate) key: String,
    #[serde(default)]
    pub(crate) priority: String,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) action: String,
    #[serde(default)]
    pub(crate) rationale: String,
    #[serde(default)]
    pub(crate) action_type: String,
    #[serde(default)]
    pub(crate) rule_suggestion_key: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditInputProfileResponse {
    #[serde(default)]
    pub(crate) source: String,
    #[serde(default)]
    pub(crate) sampled_events: u32,
    #[serde(default)]
    pub(crate) included_recent_events: u32,
    #[serde(default)]
    pub(crate) raw_samples_included: bool,
    #[serde(default)]
    pub(crate) recent_policy_feedback_count: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditSuggestedRuleResponse {
    #[serde(default)]
    pub(crate) key: String,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) policy_type: String,
    #[serde(default)]
    pub(crate) layer: String,
    #[serde(default)]
    pub(crate) scope_type: String,
    #[serde(default)]
    pub(crate) scope_value: String,
    #[serde(default)]
    pub(crate) target: String,
    #[serde(default)]
    pub(crate) action: String,
    #[serde(default)]
    pub(crate) operator: String,
    #[serde(default)]
    pub(crate) suggested_value: String,
    #[serde(default)]
    pub(crate) ttl_secs: u64,
    #[serde(default)]
    pub(crate) auto_apply: bool,
    pub(crate) rationale: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditCountersResponse {
    #[serde(default)]
    pub(crate) proxied_requests: u64,
    #[serde(default)]
    pub(crate) blocked_packets: u64,
    #[serde(default)]
    pub(crate) blocked_l4: u64,
    #[serde(default)]
    pub(crate) blocked_l7: u64,
    #[serde(default)]
    pub(crate) l7_cc_challenges: u64,
    #[serde(default)]
    pub(crate) l7_cc_blocks: u64,
    #[serde(default)]
    pub(crate) l7_cc_delays: u64,
    #[serde(default)]
    pub(crate) l7_behavior_challenges: u64,
    #[serde(default)]
    pub(crate) l7_behavior_blocks: u64,
    #[serde(default)]
    pub(crate) l7_behavior_delays: u64,
    #[serde(default)]
    pub(crate) l7_ip_access_allows: u64,
    #[serde(default)]
    pub(crate) l7_ip_access_alerts: u64,
    #[serde(default)]
    pub(crate) l7_ip_access_challenges: u64,
    #[serde(default)]
    pub(crate) l7_ip_access_blocks: u64,
    #[serde(default)]
    pub(crate) l7_ip_access_verified_passes: u64,
    #[serde(default)]
    pub(crate) l4_bucket_budget_rejections: u64,
    #[serde(default)]
    pub(crate) trusted_proxy_permit_drops: u64,
    #[serde(default)]
    pub(crate) trusted_proxy_l4_degrade_actions: u64,
    #[serde(default)]
    pub(crate) l4_request_budget_softened: u64,
    #[serde(default)]
    pub(crate) slow_attack_hits: u64,
    #[serde(default)]
    pub(crate) average_proxy_latency_micros: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditCountItem {
    #[serde(default)]
    pub(crate) key: String,
    #[serde(default)]
    pub(crate) count: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiAuditEventSampleResponse {
    #[serde(default)]
    pub(crate) id: i64,
    #[serde(default)]
    pub(crate) created_at: i64,
    #[serde(default)]
    pub(crate) layer: String,
    #[serde(default)]
    pub(crate) action: String,
    #[serde(default)]
    pub(crate) reason: String,
    #[serde(default)]
    pub(crate) source_ip: String,
    #[serde(default)]
    pub(crate) host: Option<String>,
    #[serde(default)]
    pub(crate) site_domain: Option<String>,
    #[serde(default)]
    pub(crate) http_method: Option<String>,
    #[serde(default)]
    pub(crate) uri: Option<String>,
    #[serde(default)]
    pub(crate) provider: Option<String>,
    #[serde(default)]
    pub(crate) provider_site_name: Option<String>,
    #[serde(default)]
    pub(crate) provider_site_domain: Option<String>,
    #[serde(default)]
    pub(crate) details_available: bool,
    #[serde(default)]
    pub(crate) details_slimmed: bool,
    #[serde(default)]
    pub(crate) decision_summary: Option<SecurityEventDecisionSummary>,
}

impl From<SecurityEventResponse> for AiAuditEventSampleResponse {
    fn from(value: SecurityEventResponse) -> Self {
        let details_slimmed = value
            .details_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok())
            .and_then(|details| {
                details
                    .get("storage_pressure")
                    .and_then(|value| value.get("mode"))
                    .and_then(|value| value.as_str())
                    .map(|mode| mode == "slimmed")
            })
            .unwrap_or(false);
        Self {
            id: value.id,
            created_at: value.created_at,
            layer: value.layer,
            action: value.action,
            reason: value.reason,
            source_ip: value.source_ip,
            host: value.provider_site_domain.clone(),
            site_domain: value.provider_site_domain.clone(),
            http_method: value.http_method,
            uri: value.uri,
            provider: value.provider,
            provider_site_name: value.provider_site_name,
            provider_site_domain: value.provider_site_domain,
            details_available: value.details_json.is_some(),
            details_slimmed,
            decision_summary: value.decision_summary,
        }
    }
}
