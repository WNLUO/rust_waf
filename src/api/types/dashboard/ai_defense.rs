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
use serde::Serialize;

use super::{
    AiAuditSuggestedRuleResponse, AiTempPolicyResponse, AiVisitorIntelligenceResponse,
    ServerPublicIpSnapshotResponse,
};
