use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct SecurityEventsResponse {
    pub(crate) total: u64,
    pub(crate) limit: u32,
    pub(crate) offset: u32,
    pub(crate) events: Vec<SecurityEventResponse>,
}

#[derive(Debug, Serialize)]
pub struct BehaviorProfilesResponse {
    pub(crate) total: u64,
    pub(crate) profiles: Vec<BehaviorProfileResponse>,
}

#[derive(Debug, Serialize)]
pub struct FingerprintProfilesResponse {
    pub(crate) total: u64,
    pub(crate) profiles: Vec<FingerprintProfileResponse>,
}

#[derive(Debug, Serialize)]
pub struct FingerprintProfileResponse {
    pub(crate) identity: String,
    pub(crate) identity_kind: String,
    pub(crate) source_ip: Option<String>,
    pub(crate) first_seen_at: i64,
    pub(crate) last_seen_at: i64,
    pub(crate) first_site_domain: Option<String>,
    pub(crate) last_site_domain: Option<String>,
    pub(crate) first_user_agent: Option<String>,
    pub(crate) last_user_agent: Option<String>,
    pub(crate) total_security_events: i64,
    pub(crate) total_behavior_events: i64,
    pub(crate) total_challenges: i64,
    pub(crate) total_blocks: i64,
    pub(crate) latest_score: Option<i64>,
    pub(crate) max_score: i64,
    pub(crate) latest_action: Option<String>,
    pub(crate) reputation_score: i64,
    pub(crate) notes: String,
}

#[derive(Debug, Serialize)]
pub struct BehaviorSessionsResponse {
    pub(crate) total: u64,
    pub(crate) sessions: Vec<BehaviorSessionResponse>,
}

#[derive(Debug, Serialize)]
pub struct BehaviorSessionResponse {
    pub(crate) session_key: String,
    pub(crate) identity: String,
    pub(crate) source_ip: Option<String>,
    pub(crate) site_domain: Option<String>,
    pub(crate) opened_at: i64,
    pub(crate) last_seen_at: i64,
    pub(crate) event_count: i64,
    pub(crate) challenge_count: i64,
    pub(crate) block_count: i64,
    pub(crate) latest_action: Option<String>,
    pub(crate) latest_uri: Option<String>,
    pub(crate) latest_reason: Option<String>,
    pub(crate) dominant_route: Option<String>,
    pub(crate) focused_document_route: Option<String>,
    pub(crate) focused_api_route: Option<String>,
    pub(crate) distinct_routes: i64,
    pub(crate) repeated_ratio: i64,
    pub(crate) document_repeated_ratio: i64,
    pub(crate) api_repeated_ratio: i64,
    pub(crate) document_requests: i64,
    pub(crate) api_requests: i64,
    pub(crate) non_document_requests: i64,
    pub(crate) interval_jitter_ms: Option<i64>,
    pub(crate) session_span_secs: i64,
    pub(crate) flags: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct BehaviorProfileResponse {
    pub(crate) identity: String,
    pub(crate) source_ip: Option<String>,
    pub(crate) latest_seen_at: i64,
    pub(crate) score: u32,
    pub(crate) dominant_route: Option<String>,
    pub(crate) focused_document_route: Option<String>,
    pub(crate) focused_api_route: Option<String>,
    pub(crate) distinct_routes: usize,
    pub(crate) repeated_ratio: u32,
    pub(crate) document_repeated_ratio: u32,
    pub(crate) api_repeated_ratio: u32,
    pub(crate) interval_jitter_ms: Option<u64>,
    pub(crate) document_requests: usize,
    pub(crate) api_requests: usize,
    pub(crate) non_document_requests: usize,
    pub(crate) challenge_count_window: usize,
    pub(crate) session_span_secs: u64,
    pub(crate) flags: Vec<String>,
    pub(crate) latest_route: String,
    pub(crate) latest_kind: String,
    pub(crate) blocked: bool,
    pub(crate) blocked_at: Option<i64>,
    pub(crate) blocked_expires_at: Option<i64>,
    pub(crate) blocked_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventResponse {
    pub(crate) id: i64,
    pub(crate) layer: String,
    pub(crate) provider: Option<String>,
    pub(crate) provider_event_id: Option<String>,
    pub(crate) provider_site_id: Option<String>,
    pub(crate) provider_site_name: Option<String>,
    pub(crate) provider_site_domain: Option<String>,
    pub(crate) action: String,
    pub(crate) reason: String,
    pub(crate) details_json: Option<String>,
    pub(crate) source_ip: String,
    pub(crate) dest_ip: String,
    pub(crate) source_port: i64,
    pub(crate) dest_port: i64,
    pub(crate) protocol: String,
    pub(crate) http_method: Option<String>,
    pub(crate) uri: Option<String>,
    pub(crate) http_version: Option<String>,
    pub(crate) created_at: i64,
    pub(crate) handled: bool,
    pub(crate) handled_at: Option<i64>,
    pub(crate) decision_summary: Option<SecurityEventDecisionSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEventDecisionSummary {
    pub(crate) primary_signal: String,
    pub(crate) identity_state: Option<String>,
    pub(crate) client_ip_source: Option<String>,
    pub(crate) forward_header_valid: Option<bool>,
    pub(crate) l4_overload_level: Option<String>,
    pub(crate) l7_rule_inspection_mode: Option<String>,
    pub(crate) cc_action: Option<String>,
    pub(crate) behavior_action: Option<String>,
    pub(crate) labels: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct EventUpdateRequest {
    pub(crate) handled: bool,
}

#[derive(Debug, Serialize)]
pub struct BlockedIpsResponse {
    pub(crate) total: u64,
    pub(crate) limit: u32,
    pub(crate) offset: u32,
    pub(crate) blocked_ips: Vec<BlockedIpResponse>,
}

#[derive(Debug, Serialize)]
pub struct BlockedIpResponse {
    pub(crate) id: i64,
    pub(crate) provider: Option<String>,
    pub(crate) provider_remote_id: Option<String>,
    pub(crate) ip: String,
    pub(crate) reason: String,
    pub(crate) blocked_at: i64,
    pub(crate) expires_at: i64,
}

#[derive(Debug, Deserialize)]
pub struct BlockedIpCreateRequest {
    pub(crate) ip: String,
    pub(crate) reason: String,
    pub(crate) duration_secs: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct BlockedIpsBatchUnblockRequest {
    pub(crate) ids: Vec<i64>,
}

#[derive(Debug, Serialize)]
pub struct BlockedIpsBatchUnblockResponse {
    pub(crate) success: bool,
    pub(crate) requested: u32,
    pub(crate) unblocked: u32,
    pub(crate) failed: u32,
    pub(crate) failed_ids: Vec<i64>,
    pub(crate) message: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct BlockedIpsCleanupExpiredRequest {
    pub(crate) source_scope: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) blocked_from: Option<i64>,
    pub(crate) blocked_to: Option<i64>,
    pub(crate) expires_before: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct BlockedIpsCleanupExpiredResponse {
    pub(crate) success: bool,
    pub(crate) cleaned: u32,
    pub(crate) runtime_unblocked: u32,
    pub(crate) message: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct EventsQueryParams {
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u32>,
    pub(crate) layer: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) provider_site_id: Option<String>,
    pub(crate) source_ip: Option<String>,
    pub(crate) action: Option<String>,
    pub(crate) identity_state: Option<String>,
    pub(crate) primary_signal: Option<String>,
    pub(crate) labels: Option<String>,
    pub(crate) blocked_only: Option<bool>,
    pub(crate) handled_only: Option<bool>,
    pub(crate) created_from: Option<i64>,
    pub(crate) created_to: Option<i64>,
    pub(crate) sort_by: Option<String>,
    pub(crate) sort_direction: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct BlockedIpsQueryParams {
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u32>,
    pub(crate) source_scope: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) ip: Option<String>,
    pub(crate) keyword: Option<String>,
    pub(crate) active_only: Option<bool>,
    pub(crate) blocked_from: Option<i64>,
    pub(crate) blocked_to: Option<i64>,
    pub(crate) sort_by: Option<String>,
    pub(crate) sort_direction: Option<String>,
}
