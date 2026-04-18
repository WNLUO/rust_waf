use serde::{Deserialize, Serialize};

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AiAuditReportEntry {
    pub id: i64,
    pub generated_at: i64,
    pub provider_used: String,
    pub fallback_used: bool,
    pub risk_level: String,
    pub headline: String,
    pub report_json: String,
    pub feedback_status: Option<String>,
    pub feedback_notes: Option<String>,
    pub feedback_updated_at: Option<i64>,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AiTempPolicyEntry {
    pub id: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub expires_at: i64,
    pub status: String,
    pub source_report_id: Option<i64>,
    pub policy_key: String,
    pub title: String,
    pub policy_type: String,
    pub layer: String,
    pub scope_type: String,
    pub scope_value: String,
    pub action: String,
    pub operator: String,
    pub suggested_value: String,
    pub rationale: String,
    pub confidence: i64,
    pub auto_applied: bool,
    pub hit_count: i64,
    pub last_hit_at: Option<i64>,
    pub effect_json: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AiTempPolicyEffectStats {
    #[serde(default)]
    pub baseline_l7_friction_percent: Option<f64>,
    #[serde(default)]
    pub baseline_identity_pressure_percent: Option<f64>,
    #[serde(default)]
    pub baseline_rust_persistence_percent: Option<f64>,
    #[serde(default)]
    pub auto_extensions: i64,
    #[serde(default)]
    pub auto_revoked: bool,
    #[serde(default)]
    pub auto_revoke_reason: Option<String>,
    #[serde(default)]
    pub last_effectiveness_check_at: Option<i64>,
    #[serde(default)]
    pub outcome_status: Option<String>,
    #[serde(default)]
    pub outcome_score: i64,
    #[serde(default)]
    pub total_hits: i64,
    #[serde(default)]
    pub first_hit_at: Option<i64>,
    #[serde(default)]
    pub last_hit_at: Option<i64>,
    #[serde(default)]
    pub last_scope_type: Option<String>,
    #[serde(default)]
    pub last_scope_value: Option<String>,
    #[serde(default)]
    pub last_matched_value: Option<String>,
    #[serde(default)]
    pub last_match_mode: Option<String>,
    #[serde(default)]
    pub action_hits: std::collections::BTreeMap<String, i64>,
    #[serde(default)]
    pub match_modes: std::collections::BTreeMap<String, i64>,
    #[serde(default)]
    pub scope_hits: std::collections::BTreeMap<String, i64>,
    #[serde(default)]
    pub matched_value_hits: std::collections::BTreeMap<String, i64>,
    #[serde(default)]
    pub post_policy_observations: i64,
    #[serde(default)]
    pub post_policy_upstream_errors: i64,
    #[serde(default)]
    pub post_policy_status_families: std::collections::BTreeMap<String, i64>,
    #[serde(default)]
    pub post_policy_status_codes: std::collections::BTreeMap<String, i64>,
    #[serde(default)]
    pub post_policy_latency_samples: i64,
    #[serde(default)]
    pub post_policy_latency_ms_total: i64,
    #[serde(default)]
    pub post_policy_slow_responses: i64,
    #[serde(default)]
    pub post_policy_challenge_issued: i64,
    #[serde(default)]
    pub post_policy_challenge_verified: i64,
    #[serde(default)]
    pub post_policy_interactive_sessions: i64,
    #[serde(default)]
    pub suspected_false_positive_events: i64,
    #[serde(default)]
    pub pressure_after_observations: i64,
}

#[derive(Debug, Clone)]
pub struct AiTempPolicyHitRecord {
    pub id: i64,
    pub action: String,
    pub scope_type: String,
    pub scope_value: String,
    pub matched_value: String,
    pub match_mode: String,
}

#[derive(Debug, Clone)]
pub struct AiTempPolicyOutcomeRecord {
    pub id: i64,
    pub status_code: u16,
    pub latency_ms: Option<u64>,
    pub upstream_error: bool,
    pub challenge_issued: bool,
    pub challenge_verified: bool,
    pub interactive_session: bool,
    pub suspected_false_positive: bool,
    pub route_still_under_pressure: bool,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AiVisitorProfileEntry {
    pub id: i64,
    pub identity_key: String,
    pub identity_source: String,
    pub site_id: String,
    pub client_ip: String,
    pub user_agent: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub request_count: i64,
    pub document_count: i64,
    pub api_count: i64,
    pub static_count: i64,
    pub admin_count: i64,
    pub challenge_count: i64,
    pub challenge_verified_count: i64,
    pub fingerprint_seen: bool,
    pub human_confidence: i64,
    pub automation_risk: i64,
    pub probe_risk: i64,
    pub abuse_risk: i64,
    pub false_positive_risk: String,
    pub state: String,
    pub summary_json: String,
    pub last_ai_review_at: Option<i64>,
    pub ai_rationale: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct AiVisitorProfileUpsert {
    pub identity_key: String,
    pub identity_source: String,
    pub site_id: String,
    pub client_ip: String,
    pub user_agent: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub request_count: i64,
    pub document_count: i64,
    pub api_count: i64,
    pub static_count: i64,
    pub admin_count: i64,
    pub challenge_count: i64,
    pub challenge_verified_count: i64,
    pub fingerprint_seen: bool,
    pub human_confidence: i64,
    pub automation_risk: i64,
    pub probe_risk: i64,
    pub abuse_risk: i64,
    pub false_positive_risk: String,
    pub state: String,
    pub summary_json: String,
    pub last_ai_review_at: Option<i64>,
    pub ai_rationale: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AiVisitorDecisionEntry {
    pub id: i64,
    pub decision_key: String,
    pub identity_key: String,
    pub site_id: String,
    pub created_at: i64,
    pub action: String,
    pub confidence: i64,
    pub ttl_secs: i64,
    pub rationale: String,
    pub applied: bool,
    pub effect_json: String,
}

#[derive(Debug, Clone)]
pub struct AiVisitorDecisionUpsert {
    pub decision_key: String,
    pub identity_key: String,
    pub site_id: String,
    pub created_at: i64,
    pub action: String,
    pub confidence: i64,
    pub ttl_secs: i64,
    pub rationale: String,
    pub applied: bool,
    pub effect_json: String,
}

#[derive(Debug, Clone)]
pub struct AiTempPolicyUpsert {
    pub source_report_id: Option<i64>,
    pub policy_key: String,
    pub title: String,
    pub policy_type: String,
    pub layer: String,
    pub scope_type: String,
    pub scope_value: String,
    pub action: String,
    pub operator: String,
    pub suggested_value: String,
    pub rationale: String,
    pub confidence: i64,
    pub auto_applied: bool,
    pub expires_at: i64,
    pub effect_stats: Option<AiTempPolicyEffectStats>,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct AiRouteProfileEntry {
    pub id: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub last_observed_at: Option<i64>,
    pub site_id: String,
    pub route_pattern: String,
    pub match_mode: String,
    pub route_type: String,
    pub sensitivity: String,
    pub auth_required: String,
    pub normal_traffic_pattern: String,
    pub recommended_actions_json: String,
    pub avoid_actions_json: String,
    pub evidence_json: String,
    pub confidence: i64,
    pub source: String,
    pub status: String,
    pub rationale: String,
    pub reviewed_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct AiRouteProfileUpsert {
    pub site_id: String,
    pub route_pattern: String,
    pub match_mode: String,
    pub route_type: String,
    pub sensitivity: String,
    pub auth_required: String,
    pub normal_traffic_pattern: String,
    pub recommended_actions: Vec<String>,
    pub avoid_actions: Vec<String>,
    pub evidence_json: String,
    pub confidence: i64,
    pub source: String,
    pub status: String,
    pub rationale: String,
    pub last_observed_at: Option<i64>,
    pub reviewed_at: Option<i64>,
}
