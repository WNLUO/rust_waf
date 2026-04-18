use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficDirection {
    Ingress,
    Egress,
}

impl TrafficDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficDecision {
    Allow,
    Block,
}

impl TrafficDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone)]
pub struct TrafficMapNodeSnapshot {
    pub id: String,
    pub name: String,
    pub region: String,
    pub role: String,
    pub lat: Option<f64>,
    pub lng: Option<f64>,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub geo_scope: String,
    pub traffic_weight: f64,
    pub request_count: u64,
    pub blocked_count: u64,
    pub bandwidth_mbps: f64,
    pub last_seen_at: i64,
}

#[derive(Debug, Clone)]
pub struct TrafficMapFlowSnapshot {
    pub id: String,
    pub node_id: String,
    pub direction: String,
    pub decision: String,
    pub request_count: u64,
    pub bytes: u64,
    pub bandwidth_mbps: f64,
    pub average_latency_ms: u64,
    pub last_seen_at: i64,
}

#[derive(Debug, Clone)]
pub struct TrafficMapSnapshot {
    pub scope: String,
    pub window_seconds: u32,
    pub generated_at: i64,
    pub origin_node: TrafficMapNodeSnapshot,
    pub nodes: Vec<TrafficMapNodeSnapshot>,
    pub flows: Vec<TrafficMapFlowSnapshot>,
    pub active_node_count: u32,
    pub peak_bandwidth_mbps: f64,
    pub allowed_flow_count: u32,
    pub blocked_flow_count: u32,
    pub live_traffic_score: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficRealtimeEventRaw {
    pub timestamp_ms: i64,
    pub source_ip: String,
    pub direction: String,
    pub decision: String,
    pub bytes: u64,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficRealtimeNode {
    pub id: String,
    pub name: String,
    pub region: String,
    pub role: String,
    pub lat: Option<f64>,
    pub lng: Option<f64>,
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub geo_scope: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct TrafficRealtimeEvent {
    pub timestamp_ms: i64,
    pub direction: String,
    pub decision: String,
    pub bytes: u64,
    pub latency_ms: Option<u64>,
    pub source_ip: String,
    pub node: TrafficRealtimeNode,
}

#[derive(Debug, Clone)]
pub(super) struct TrafficObservation {
    pub(super) timestamp_ms: i64,
    pub(super) source_ip: String,
    pub(super) direction: TrafficDirection,
    pub(super) decision: TrafficDecision,
    pub(super) bytes: u64,
    pub(super) latency_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub(super) struct GeoNode {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) region: String,
    pub(super) lat: f64,
    pub(super) lng: f64,
    pub(super) country_code: Option<String>,
    pub(super) country_name: Option<String>,
    pub(super) geo_scope: String,
    pub(super) traffic_weight: f64,
}

#[derive(Debug, Clone)]
pub(super) struct CachedOriginNode {
    pub(super) node: TrafficMapNodeSnapshot,
    pub(super) refreshed_at_ms: i64,
    pub(super) resolved: bool,
}

#[derive(Debug, Deserialize)]
pub(super) struct IpWhoisResponse {
    pub(super) success: bool,
    pub(super) country_code: Option<String>,
    pub(super) country: Option<String>,
    pub(super) region: Option<String>,
    pub(super) city: Option<String>,
    pub(super) latitude: Option<f64>,
    pub(super) longitude: Option<f64>,
}

#[derive(Debug, Deserialize)]
pub(super) struct PublicIpResponse {
    pub(super) ip: String,
}

pub(super) type IpipRegionResponse = Vec<String>;

#[derive(Debug, Deserialize)]
pub(super) struct IpSbGeoResponse {
    pub(super) country_code: Option<String>,
    pub(super) country: Option<String>,
    pub(super) region: Option<String>,
    pub(super) city: Option<String>,
    pub(super) latitude: Option<f64>,
    pub(super) longitude: Option<f64>,
}
