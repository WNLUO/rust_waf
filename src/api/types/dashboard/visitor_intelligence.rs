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
use serde::Serialize;
