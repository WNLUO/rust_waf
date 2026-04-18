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
use serde::{Deserialize, Serialize};
