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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAuditSummaryResponse {
    pub(crate) generated_at: i64,
    pub(crate) window_seconds: u32,
    pub(crate) sampled_events: u32,
    pub(crate) total_events: u64,
    pub(crate) active_rules: u64,
    pub(crate) current: AiAuditCurrentStateResponse,
    pub(crate) counters: AiAuditCountersResponse,
    pub(crate) identity_states: Vec<AiAuditCountItem>,
    pub(crate) primary_signals: Vec<AiAuditCountItem>,
    pub(crate) labels: Vec<AiAuditCountItem>,
    pub(crate) top_source_ips: Vec<AiAuditCountItem>,
    pub(crate) top_routes: Vec<AiAuditCountItem>,
    pub(crate) top_hosts: Vec<AiAuditCountItem>,
    #[serde(default)]
    pub(crate) safeline_correlation: AiAuditSafeLineCorrelationResponse,
    pub(crate) recent_events: Vec<AiAuditEventSampleResponse>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAuditReportResponse {
    pub(crate) report_id: Option<i64>,
    pub(crate) generated_at: i64,
    pub(crate) provider_used: String,
    pub(crate) fallback_used: bool,
    #[serde(default)]
    pub(crate) analysis_mode: String,
    pub(crate) execution_notes: Vec<String>,
    pub(crate) risk_level: String,
    pub(crate) headline: String,
    pub(crate) executive_summary: Vec<String>,
    #[serde(default)]
    pub(crate) input_profile: AiAuditInputProfileResponse,
    pub(crate) findings: Vec<AiAuditReportFinding>,
    pub(crate) recommendations: Vec<AiAuditReportRecommendation>,
    #[serde(default)]
    pub(crate) suggested_local_rules: Vec<AiAuditSuggestedRuleResponse>,
    pub(crate) summary: AiAuditSummaryResponse,
}

#[derive(Debug, Serialize)]
pub struct AiAuditReportsResponse {
    pub(crate) total: u64,
    pub(crate) limit: u32,
    pub(crate) offset: u32,
    pub(crate) reports: Vec<AiAuditReportHistoryItem>,
}

#[derive(Debug, Serialize)]
pub struct AiTempPoliciesResponse {
    pub(crate) total: u32,
    pub(crate) policies: Vec<AiTempPolicyResponse>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AiTempPolicyEffectResponse {
    pub(crate) baseline_l7_friction_percent: Option<f64>,
    pub(crate) baseline_identity_pressure_percent: Option<f64>,
    pub(crate) baseline_rust_persistence_percent: Option<f64>,
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
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AiTempPolicyEffectivenessResponse {
    pub(crate) current_l7_friction_percent: f64,
    pub(crate) current_identity_pressure_percent: f64,
    pub(crate) current_rust_persistence_percent: f64,
    pub(crate) l7_friction_delta: Option<f64>,
    pub(crate) identity_pressure_delta: Option<f64>,
    pub(crate) rust_persistence_delta: Option<f64>,
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
    pub(crate) report: AiAuditReportResponse,
}

#[derive(Debug, Deserialize)]
pub struct AiAuditFeedbackUpdateRequest {
    pub(crate) feedback_status: Option<String>,
    pub(crate) feedback_notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAuditCurrentStateResponse {
    pub(crate) adaptive_system_pressure: String,
    pub(crate) adaptive_reasons: Vec<String>,
    pub(crate) l4_overload_level: String,
    pub(crate) auto_tuning_controller_state: String,
    pub(crate) auto_tuning_last_adjust_reason: Option<String>,
    pub(crate) auto_tuning_last_adjust_diff: Vec<String>,
    pub(crate) identity_pressure_percent: f64,
    pub(crate) l7_friction_pressure_percent: f64,
    pub(crate) slow_attack_pressure_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAuditReportFinding {
    pub(crate) key: String,
    pub(crate) severity: String,
    pub(crate) title: String,
    pub(crate) detail: String,
    pub(crate) evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAuditReportRecommendation {
    pub(crate) key: String,
    pub(crate) priority: String,
    pub(crate) title: String,
    pub(crate) action: String,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAuditSuggestedRuleResponse {
    pub(crate) key: String,
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) policy_type: String,
    pub(crate) layer: String,
    #[serde(default)]
    pub(crate) scope_type: String,
    #[serde(default)]
    pub(crate) scope_value: String,
    pub(crate) target: String,
    #[serde(default)]
    pub(crate) action: String,
    pub(crate) operator: String,
    pub(crate) suggested_value: String,
    #[serde(default)]
    pub(crate) ttl_secs: u64,
    #[serde(default)]
    pub(crate) auto_apply: bool,
    pub(crate) rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAuditCountersResponse {
    pub(crate) proxied_requests: u64,
    pub(crate) blocked_packets: u64,
    pub(crate) blocked_l4: u64,
    pub(crate) blocked_l7: u64,
    pub(crate) l7_cc_challenges: u64,
    pub(crate) l7_cc_blocks: u64,
    pub(crate) l7_cc_delays: u64,
    pub(crate) l7_behavior_challenges: u64,
    pub(crate) l7_behavior_blocks: u64,
    pub(crate) l7_behavior_delays: u64,
    pub(crate) l4_bucket_budget_rejections: u64,
    pub(crate) trusted_proxy_permit_drops: u64,
    pub(crate) trusted_proxy_l4_degrade_actions: u64,
    pub(crate) l4_request_budget_softened: u64,
    pub(crate) slow_attack_hits: u64,
    pub(crate) average_proxy_latency_micros: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAuditCountItem {
    pub(crate) key: String,
    pub(crate) count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAuditEventSampleResponse {
    pub(crate) id: i64,
    pub(crate) created_at: i64,
    pub(crate) layer: String,
    pub(crate) action: String,
    pub(crate) reason: String,
    pub(crate) source_ip: String,
    pub(crate) uri: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) decision_summary: Option<SecurityEventDecisionSummary>,
}

impl From<SecurityEventResponse> for AiAuditEventSampleResponse {
    fn from(value: SecurityEventResponse) -> Self {
        Self {
            id: value.id,
            created_at: value.created_at,
            layer: value.layer,
            action: value.action,
            reason: value.reason,
            source_ip: value.source_ip,
            uri: value.uri,
            provider: value.provider,
            decision_summary: value.decision_summary,
        }
    }
}
