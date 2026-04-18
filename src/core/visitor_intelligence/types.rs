use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};

pub(super) const VISITOR_WINDOW_SECS: i64 = 15 * 60;
pub(super) const MAX_VISITOR_BUCKETS: usize = 16_384;
pub(super) const MAX_VISITOR_ROUTES: usize = 24;
pub(super) const MAX_VISITOR_RECENT_ROUTES: usize = 16;

#[derive(Debug, Clone, Default)]
pub(crate) struct VisitorIntelligenceBucket {
    pub window_start: i64,
    pub identity_key: String,
    pub identity_source: String,
    pub site_id: String,
    pub client_ip: String,
    pub user_agent: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub request_count: u64,
    pub document_count: u64,
    pub api_count: u64,
    pub static_count: u64,
    pub admin_count: u64,
    pub challenge_count: u64,
    pub challenge_verified_count: u64,
    pub challenge_page_report_count: u64,
    pub challenge_js_report_count: u64,
    pub local_response_count: u64,
    pub blocked_response_count: u64,
    pub upstream_error_count: u64,
    pub upstream_success_count: u64,
    pub upstream_redirect_count: u64,
    pub upstream_client_error_count: u64,
    pub auth_required_route_count: u64,
    pub auth_success_count: u64,
    pub auth_rejected_count: u64,
    pub same_site_referer_count: u64,
    pub no_referer_document_count: u64,
    pub fingerprint_seen: bool,
    pub route_counts: BTreeMap<String, u64>,
    pub business_route_types: BTreeMap<String, u64>,
    pub status_codes: BTreeMap<String, u64>,
    pub recent_routes: VecDeque<String>,
    pub flags: HashSet<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VisitorIntelligenceSnapshot {
    pub generated_at: i64,
    pub enabled: bool,
    pub degraded_reason: Option<String>,
    pub active_profile_count: usize,
    pub profiles: Vec<VisitorProfileSignal>,
    pub recommendations: Vec<VisitorDecisionSignal>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisitorProfileSignal {
    pub identity_key: String,
    pub identity_source: String,
    pub site_id: String,
    pub client_ip: String,
    pub user_agent: String,
    pub state: String,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub request_count: u64,
    pub document_count: u64,
    pub api_count: u64,
    pub static_count: u64,
    pub admin_count: u64,
    pub challenge_count: u64,
    pub challenge_verified_count: u64,
    pub challenge_page_report_count: u64,
    pub challenge_js_report_count: u64,
    pub fingerprint_seen: bool,
    pub upstream_success_count: u64,
    pub upstream_redirect_count: u64,
    pub upstream_client_error_count: u64,
    pub upstream_error_count: u64,
    pub auth_required_route_count: u64,
    pub auth_success_count: u64,
    pub auth_rejected_count: u64,
    pub human_confidence: u8,
    pub automation_risk: u8,
    pub probe_risk: u8,
    pub abuse_risk: u8,
    pub false_positive_risk: String,
    pub tracking_priority: String,
    pub route_summary: Vec<VisitorRouteSummary>,
    pub business_route_types: BTreeMap<String, u64>,
    pub status_codes: BTreeMap<String, u64>,
    pub flags: Vec<String>,
    pub ai_rationale: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisitorRouteSummary {
    pub route: String,
    pub count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisitorDecisionSignal {
    pub decision_key: String,
    pub identity_key: String,
    pub site_id: String,
    pub action: String,
    pub confidence: u8,
    pub ttl_secs: u64,
    pub rationale: String,
    pub applied: bool,
    pub effect_status: String,
}
