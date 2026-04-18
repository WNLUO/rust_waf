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
use serde::Serialize;
