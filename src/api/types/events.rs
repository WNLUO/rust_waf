use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct SecurityEventsResponse {
    pub(crate) total: u64,
    pub(crate) limit: u32,
    pub(crate) offset: u32,
    pub(crate) events: Vec<SecurityEventResponse>,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Deserialize, Default)]
pub struct EventsQueryParams {
    pub(crate) limit: Option<u32>,
    pub(crate) offset: Option<u32>,
    pub(crate) layer: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) provider_site_id: Option<String>,
    pub(crate) source_ip: Option<String>,
    pub(crate) action: Option<String>,
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
