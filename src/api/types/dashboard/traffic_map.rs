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
use serde::{Deserialize, Serialize};
