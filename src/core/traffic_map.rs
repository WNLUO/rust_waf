use dashmap::DashMap;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

const ORIGIN_CACHE_TTL_SUCCESS_MS: i64 = 10 * 60 * 1_000;
const ORIGIN_CACHE_TTL_PENDING_MS: i64 = 15 * 1_000;
const EXTERNAL_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

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
struct TrafficObservation {
    timestamp_ms: i64,
    source_ip: String,
    direction: TrafficDirection,
    decision: TrafficDecision,
    bytes: u64,
    latency_ms: Option<u64>,
}

#[derive(Debug, Clone)]
struct GeoNode {
    id: &'static str,
    name: &'static str,
    region: &'static str,
    lat: f64,
    lng: f64,
    traffic_weight: f64,
}

#[derive(Debug)]
pub struct TrafficMapCollector {
    observations: Mutex<VecDeque<TrafficObservation>>,
    geo_cache: DashMap<String, GeoNode>,
    origin_cache: Mutex<Option<CachedOriginNode>>,
    http_client: Client,
    max_window_seconds: u32,
    realtime_tx: broadcast::Sender<TrafficRealtimeEventRaw>,
}

#[derive(Debug, Clone)]
struct CachedOriginNode {
    node: TrafficMapNodeSnapshot,
    refreshed_at_ms: i64,
    resolved: bool,
}

impl Default for TrafficMapCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl TrafficMapCollector {
    pub fn new() -> Self {
        Self {
            observations: Mutex::new(VecDeque::new()),
            geo_cache: DashMap::new(),
            origin_cache: Mutex::new(None),
            http_client: Client::new(),
            max_window_seconds: 300,
            realtime_tx: broadcast::channel(512).0,
        }
    }

    pub fn record_ingress(&self, source_ip: impl Into<String>, bytes: usize, blocked: bool) {
        let timestamp_ms = unix_timestamp_ms();
        let source_ip = source_ip.into();
        let decision = if blocked {
            TrafficDecision::Block
        } else {
            TrafficDecision::Allow
        };
        self.record(TrafficObservation {
            timestamp_ms,
            source_ip: source_ip.clone(),
            direction: TrafficDirection::Ingress,
            decision,
            bytes: bytes as u64,
            latency_ms: None,
        });
        let _ = self.realtime_tx.send(TrafficRealtimeEventRaw {
            timestamp_ms,
            source_ip,
            direction: TrafficDirection::Ingress.as_str().to_string(),
            decision: decision.as_str().to_string(),
            bytes: bytes as u64,
            latency_ms: None,
        });
    }

    pub fn record_egress(
        &self,
        source_ip: impl Into<String>,
        bytes: usize,
        latency: std::time::Duration,
    ) {
        let timestamp_ms = unix_timestamp_ms();
        let source_ip = source_ip.into();
        let latency_ms = latency.as_millis() as u64;
        self.record(TrafficObservation {
            timestamp_ms,
            source_ip: source_ip.clone(),
            direction: TrafficDirection::Egress,
            decision: TrafficDecision::Allow,
            bytes: bytes as u64,
            latency_ms: Some(latency_ms),
        });
        let _ = self.realtime_tx.send(TrafficRealtimeEventRaw {
            timestamp_ms,
            source_ip,
            direction: TrafficDirection::Egress.as_str().to_string(),
            decision: TrafficDecision::Allow.as_str().to_string(),
            bytes: bytes as u64,
            latency_ms: Some(latency_ms),
        });
    }

    pub fn subscribe_realtime(&self) -> broadcast::Receiver<TrafficRealtimeEventRaw> {
        self.realtime_tx.subscribe()
    }

    pub async fn enrich_realtime_event(
        &self,
        event: TrafficRealtimeEventRaw,
    ) -> TrafficRealtimeEvent {
        if !self.geo_cache.contains_key(&event.source_ip) {
            let resolved = self.resolve_geo_node(&event.source_ip).await;
            self.geo_cache.insert(event.source_ip.clone(), resolved);
        }

        let node = self
            .geo_cache
            .get(&event.source_ip)
            .map(|entry| TrafficRealtimeNode {
                id: entry.id.to_string(),
                name: entry.name.to_string(),
                region: entry.region.to_string(),
                role: "cdn".to_string(),
                lat: Some(entry.lat),
                lng: Some(entry.lng),
            })
            .unwrap_or_else(|| {
                let fallback = fallback_node(&event.source_ip);
                TrafficRealtimeNode {
                    id: fallback.id.to_string(),
                    name: fallback.name.to_string(),
                    region: fallback.region.to_string(),
                    role: "cdn".to_string(),
                    lat: Some(fallback.lat),
                    lng: Some(fallback.lng),
                }
            });

        TrafficRealtimeEvent {
            timestamp_ms: event.timestamp_ms,
            direction: event.direction,
            decision: event.decision,
            bytes: event.bytes,
            latency_ms: event.latency_ms,
            source_ip: event.source_ip,
            node,
        }
    }

    fn record(&self, observation: TrafficObservation) {
        let mut guard = self
            .observations
            .lock()
            .expect("traffic map observation lock poisoned");
        guard.push_back(observation);
        let stale_before =
            unix_timestamp_ms() - i64::from(self.max_window_seconds).saturating_mul(1_000);
        while guard
            .front()
            .map(|item| item.timestamp_ms < stale_before)
            .unwrap_or(false)
        {
            guard.pop_front();
        }
    }

    pub async fn snapshot(&self, window_seconds: u32) -> TrafficMapSnapshot {
        let window_seconds = window_seconds.clamp(10, self.max_window_seconds);
        let now_ms = unix_timestamp_ms();
        let stale_before = now_ms - i64::from(window_seconds) * 1_000;

        let observations = {
            let mut guard = self
                .observations
                .lock()
                .expect("traffic map observation lock poisoned");
            while guard
                .front()
                .map(|item| item.timestamp_ms < now_ms - i64::from(self.max_window_seconds) * 1_000)
                .unwrap_or(false)
            {
                guard.pop_front();
            }
            guard
                .iter()
                .filter(|item| item.timestamp_ms >= stale_before)
                .cloned()
                .collect::<Vec<_>>()
        };

        let mut unique_ips = HashSet::new();
        for observation in &observations {
            unique_ips.insert(observation.source_ip.clone());
        }
        for ip in unique_ips {
            if self.geo_cache.contains_key(&ip) {
                continue;
            }
            let resolved = self.resolve_geo_node(&ip).await;
            self.geo_cache.insert(ip, resolved);
        }

        #[derive(Default)]
        struct NodeAggregate {
            ingress_requests: u64,
            blocked_requests: u64,
            total_bytes: u64,
            last_seen_at: i64,
        }

        #[derive(Default)]
        struct FlowAggregate {
            request_count: u64,
            bytes: u64,
            latency_sum_ms: u64,
            latency_samples: u64,
            last_seen_at: i64,
        }

        let mut node_aggregates: BTreeMap<String, NodeAggregate> = BTreeMap::new();
        let mut flow_aggregates: BTreeMap<(String, &'static str, &'static str), FlowAggregate> =
            BTreeMap::new();

        for observation in &observations {
            let Some(node) = self.geo_cache.get(&observation.source_ip) else {
                continue;
            };
            let node_key = node.id.to_string();
            let node_entry = node_aggregates.entry(node_key.clone()).or_default();
            if observation.direction == TrafficDirection::Ingress {
                node_entry.ingress_requests = node_entry.ingress_requests.saturating_add(1);
                if observation.decision == TrafficDecision::Block {
                    node_entry.blocked_requests = node_entry.blocked_requests.saturating_add(1);
                }
            }
            node_entry.total_bytes = node_entry.total_bytes.saturating_add(observation.bytes);
            node_entry.last_seen_at = node_entry.last_seen_at.max(observation.timestamp_ms);

            let flow_entry = flow_aggregates
                .entry((
                    node_key,
                    observation.direction.as_str(),
                    observation.decision.as_str(),
                ))
                .or_default();
            flow_entry.request_count = flow_entry.request_count.saturating_add(1);
            flow_entry.bytes = flow_entry.bytes.saturating_add(observation.bytes);
            if let Some(latency_ms) = observation.latency_ms {
                flow_entry.latency_sum_ms = flow_entry.latency_sum_ms.saturating_add(latency_ms);
                flow_entry.latency_samples = flow_entry.latency_samples.saturating_add(1);
            }
            flow_entry.last_seen_at = flow_entry.last_seen_at.max(observation.timestamp_ms);
        }

        let window_ms = f64::from(window_seconds) * 1_000.0;
        let mut nodes = Vec::new();
        let mut peak_bandwidth_mbps = 0.0_f64;

        for (node_id, aggregate) in &node_aggregates {
            let Some(node) = self
                .geo_cache
                .iter()
                .find(|item| item.value().id == node_id)
            else {
                continue;
            };
            let bandwidth_mbps =
                ((aggregate.total_bytes as f64) * 8.0 / 1_000_000.0) / (window_ms / 1_000.0);
            peak_bandwidth_mbps = peak_bandwidth_mbps.max(bandwidth_mbps);
            nodes.push(TrafficMapNodeSnapshot {
                id: node.value().id.to_string(),
                name: node.value().name.to_string(),
                region: node.value().region.to_string(),
                role: "cdn".to_string(),
                lat: Some(node.value().lat),
                lng: Some(node.value().lng),
                traffic_weight: clamp_f64(
                    node.value().traffic_weight
                        + (aggregate.ingress_requests as f64 / 12.0)
                        + (bandwidth_mbps / 25.0),
                    0.2,
                    1.6,
                ),
                request_count: aggregate.ingress_requests,
                blocked_count: aggregate.blocked_requests,
                bandwidth_mbps,
                last_seen_at: aggregate.last_seen_at,
            });
        }

        nodes.sort_by(|left, right| {
            right
                .bandwidth_mbps
                .partial_cmp(&left.bandwidth_mbps)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let mut flows = Vec::new();
        let mut allowed_flow_count = 0_u32;
        let mut blocked_flow_count = 0_u32;

        for ((node_id, direction, decision), aggregate) in flow_aggregates {
            if direction == "ingress" && decision == "allow" {
                allowed_flow_count = allowed_flow_count.saturating_add(1);
            }
            if direction == "ingress" && decision == "block" {
                blocked_flow_count = blocked_flow_count.saturating_add(1);
            }

            flows.push(TrafficMapFlowSnapshot {
                id: format!("{node_id}-{direction}-{decision}"),
                node_id,
                direction: direction.to_string(),
                decision: decision.to_string(),
                request_count: aggregate.request_count,
                bytes: aggregate.bytes,
                bandwidth_mbps: ((aggregate.bytes as f64) * 8.0 / 1_000_000.0)
                    / (window_ms / 1_000.0),
                average_latency_ms: if aggregate.latency_samples == 0 {
                    0
                } else {
                    aggregate.latency_sum_ms / aggregate.latency_samples
                },
                last_seen_at: aggregate.last_seen_at,
            });
        }

        flows.sort_by(|left, right| {
            right
                .bandwidth_mbps
                .partial_cmp(&left.bandwidth_mbps)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let total_ingress_requests = flows
            .iter()
            .filter(|flow| flow.direction == "ingress")
            .map(|flow| flow.request_count)
            .sum::<u64>();

        TrafficMapSnapshot {
            scope: "china".to_string(),
            window_seconds,
            generated_at: now_ms,
            origin_node: self.origin_node().await,
            nodes,
            flows,
            active_node_count: node_aggregates.len() as u32,
            peak_bandwidth_mbps,
            allowed_flow_count,
            blocked_flow_count,
            live_traffic_score: clamp_f64(
                (total_ingress_requests as f64 / 16.0) + (peak_bandwidth_mbps / 30.0),
                0.0,
                9.9,
            ),
        }
    }

    async fn resolve_geo_node(&self, source_ip: &str) -> GeoNode {
        let parsed_ip = source_ip.parse::<IpAddr>().ok();
        if parsed_ip.map(is_internal_ip).unwrap_or(false) {
            return internal_node();
        }

        if let Some(payload) = self.lookup_remote_region(source_ip).await {
            if let Some(node) = map_remote_region_to_node(&payload) {
                return node;
            }
        }

        fallback_node(source_ip)
    }

    async fn origin_node(&self) -> TrafficMapNodeSnapshot {
        let now_ms = unix_timestamp_ms();
        if let Some(cached) = self
            .origin_cache
            .lock()
            .expect("origin_cache lock poisoned")
            .clone()
            .filter(|cached| {
                let ttl_ms = if cached.resolved {
                    ORIGIN_CACHE_TTL_SUCCESS_MS
                } else {
                    ORIGIN_CACHE_TTL_PENDING_MS
                };
                now_ms - cached.refreshed_at_ms < ttl_ms
            })
        {
            return cached.node;
        }

        let cached_success = self
            .origin_cache
            .lock()
            .expect("origin_cache lock poisoned")
            .clone()
            .filter(|cached| cached.resolved);

        let (node, resolved) = match self.lookup_origin_node().await {
            Some(node) => (node, true),
            None => {
                if let Some(cached_success) = cached_success {
                    return cached_success.node;
                }
                (pending_origin_node(), false)
            }
        };

        let mut guard = self
            .origin_cache
            .lock()
            .expect("origin_cache lock poisoned");
        *guard = Some(CachedOriginNode {
            node: node.clone(),
            refreshed_at_ms: now_ms,
            resolved,
        });

        node
    }

    async fn lookup_origin_node(&self) -> Option<TrafficMapNodeSnapshot> {
        let public_ip = self.lookup_public_ip().await?;
        if let Some(payload) = self.lookup_ipip_region(&public_ip).await {
            if let Some(node) = origin_node_from_ipip_payload(&payload) {
                return Some(node);
            }
        }
        if let Some(payload) = self.lookup_ip_sb_region(&public_ip).await {
            if let Some(node) = origin_node_from_ip_sb_payload(&payload) {
                return Some(node);
            }
        }
        let payload = self.lookup_remote_region(&public_ip).await?;
        origin_node_from_geo_payload(&payload)
    }

    async fn lookup_public_ip(&self) -> Option<String> {
        let response = self
            .http_client
            .get("https://api.ip.sb/jsonip")
            .timeout(EXTERNAL_LOOKUP_TIMEOUT)
            .send()
            .await
            .ok()?;
        if response.status().is_success() {
            if let Ok(payload) = response.json::<PublicIpResponse>().await {
                let ip = payload.ip.trim();
                if !ip.is_empty() {
                    return Some(ip.to_string());
                }
            }
        }

        let response = self
            .http_client
            .get("https://api.ipify.org?format=json")
            .timeout(EXTERNAL_LOOKUP_TIMEOUT)
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let payload = response.json::<PublicIpResponse>().await.ok()?;
        let ip = payload.ip.trim();
        (!ip.is_empty()).then_some(ip.to_string())
    }

    async fn lookup_ipip_region(&self, source_ip: &str) -> Option<IpipRegionResponse> {
        let url = format!("http://freeapi.ipip.net/{source_ip}");
        let response = self
            .http_client
            .get(url)
            .timeout(EXTERNAL_LOOKUP_TIMEOUT)
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        response.json::<IpipRegionResponse>().await.ok()
    }

    async fn lookup_ip_sb_region(&self, source_ip: &str) -> Option<IpSbGeoResponse> {
        let url = format!("https://api.ip.sb/geoip/{source_ip}");
        let response = self
            .http_client
            .get(url)
            .timeout(EXTERNAL_LOOKUP_TIMEOUT)
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        response.json::<IpSbGeoResponse>().await.ok()
    }

    async fn lookup_remote_region(&self, source_ip: &str) -> Option<IpWhoisResponse> {
        let url = format!("https://ipwho.is/{source_ip}");
        let response = self
            .http_client
            .get(url)
            .timeout(EXTERNAL_LOOKUP_TIMEOUT)
            .send()
            .await
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        let payload = response.json::<IpWhoisResponse>().await.ok()?;
        payload.success.then_some(payload)
    }
}

#[derive(Debug, Deserialize)]
struct IpWhoisResponse {
    success: bool,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct PublicIpResponse {
    ip: String,
}

type IpipRegionResponse = Vec<String>;

#[derive(Debug, Deserialize)]
struct IpSbGeoResponse {
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    latitude: Option<f64>,
    longitude: Option<f64>,
}

fn is_internal_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private()
                || ipv4.is_loopback()
                || ipv4.is_link_local()
                || ipv4.is_broadcast()
                || ipv4.is_documentation()
                || ipv4.is_unspecified()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()
                || ipv6.is_unspecified()
                || ipv6.is_unique_local()
                || ipv6.is_unicast_link_local()
        }
    }
}

fn pending_origin_node() -> TrafficMapNodeSnapshot {
    TrafficMapNodeSnapshot {
        id: "origin-cn".to_string(),
        name: "本服务器".to_string(),
        region: "后端正在获取物理位置中".to_string(),
        role: "origin".to_string(),
        lat: None,
        lng: None,
        traffic_weight: 1.0,
        request_count: 0,
        blocked_count: 0,
        bandwidth_mbps: 0.0,
        last_seen_at: unix_timestamp_ms(),
    }
}

fn origin_node_from_geo_payload(payload: &IpWhoisResponse) -> Option<TrafficMapNodeSnapshot> {
    let country_code = payload
        .country_code
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if !country_code.eq_ignore_ascii_case("CN") {
        return None;
    }

    let region = payload
        .region
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("中国");
    let city = payload
        .city
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let label = city
        .map(|city| format!("{region} {city}"))
        .unwrap_or_else(|| region.to_string());

    origin_node_snapshot(
        label,
        payload.latitude?,
        payload.longitude?,
        unix_timestamp_ms(),
    )
}

fn origin_node_from_ipip_payload(payload: &IpipRegionResponse) -> Option<TrafficMapNodeSnapshot> {
    let country = payload
        .first()
        .map(String::as_str)
        .map(str::trim)
        .unwrap_or_default();
    if country != "中国" && !country.eq_ignore_ascii_case("CN") {
        return None;
    }

    let region = payload
        .get(1)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("中国");
    let city = payload
        .get(2)
        .map(String::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let normalized = city
        .map(|city| format!("{region} {city}"))
        .unwrap_or_else(|| region.to_string());
    let geo_node = find_china_node(&normalized)?;
    let label = city
        .map(|city| format!("{region} {city}"))
        .unwrap_or_else(|| region.to_string());

    origin_node_snapshot(label, geo_node.lat, geo_node.lng, unix_timestamp_ms())
}

fn origin_node_from_ip_sb_payload(payload: &IpSbGeoResponse) -> Option<TrafficMapNodeSnapshot> {
    let country_code = payload
        .country_code
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if !country_code.eq_ignore_ascii_case("CN") {
        return None;
    }

    let region = payload
        .region
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("中国");
    let city = payload
        .city
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let label = city
        .map(|city| format!("{region} {city}"))
        .unwrap_or_else(|| region.to_string());

    origin_node_snapshot(
        label,
        payload.latitude?,
        payload.longitude?,
        unix_timestamp_ms(),
    )
}

fn origin_node_snapshot(
    region: String,
    lat: f64,
    lng: f64,
    last_seen_at: i64,
) -> Option<TrafficMapNodeSnapshot> {
    Some(TrafficMapNodeSnapshot {
        id: "origin-cn".to_string(),
        name: "本服务器".to_string(),
        region,
        role: "origin".to_string(),
        lat: Some(lat),
        lng: Some(lng),
        traffic_weight: 1.0,
        request_count: 0,
        blocked_count: 0,
        bandwidth_mbps: 0.0,
        last_seen_at,
    })
}

fn find_china_node(normalized: &str) -> Option<GeoNode> {
    let normalized = normalized.to_ascii_lowercase();
    for node in china_nodes() {
        if node_matches_region(node, &normalized) {
            return Some(node.clone());
        }
    }
    Some(fallback_mainland_node(normalized.as_str(), ""))
}

fn internal_node() -> GeoNode {
    GeoNode {
        id: "cn-internal",
        name: "内网",
        region: "内网来源",
        lat: 30.95,
        lng: 121.22,
        traffic_weight: 0.48,
    }
}

fn overseas_node() -> GeoNode {
    GeoNode {
        id: "cn-overseas",
        name: "境外",
        region: "境外来源",
        lat: 43.8,
        lng: 82.1,
        traffic_weight: 0.62,
    }
}

fn map_remote_region_to_node(payload: &IpWhoisResponse) -> Option<GeoNode> {
    let country_code = payload
        .country_code
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if !country_code.eq_ignore_ascii_case("CN") {
        return Some(overseas_node());
    }

    let region = payload.region.as_deref().unwrap_or_default();
    let city = payload.city.as_deref().unwrap_or_default();
    let normalized = format!("{region} {city}").to_ascii_lowercase();

    for node in china_nodes() {
        if node_matches_region(node, &normalized) {
            return Some(node.clone());
        }
    }

    Some(fallback_mainland_node(region, city))
}

fn node_matches_region(node: &GeoNode, normalized: &str) -> bool {
    province_aliases(node.id)
        .iter()
        .any(|alias| normalized.contains(alias))
}

fn province_aliases(node_id: &str) -> &'static [&'static str] {
    match node_id {
        "cn-110000" => &["beijing", "北京"],
        "cn-120000" => &["tianjin", "天津"],
        "cn-130000" => &["hebei", "河北"],
        "cn-140000" => &["shanxi", "山西"],
        "cn-150000" => &["inner mongolia", "neimenggu", "内蒙古"],
        "cn-210000" => &["liaoning", "辽宁"],
        "cn-220000" => &["jilin", "吉林"],
        "cn-230000" => &["heilongjiang", "黑龙江"],
        "cn-310000" => &["shanghai", "上海"],
        "cn-320000" => &["jiangsu", "江苏"],
        "cn-330000" => &["zhejiang", "浙江"],
        "cn-340000" => &["anhui", "安徽"],
        "cn-350000" => &["fujian", "福建"],
        "cn-360000" => &["jiangxi", "江西"],
        "cn-370000" => &["shandong", "山东"],
        "cn-410000" => &["henan", "河南"],
        "cn-420000" => &["hubei", "湖北"],
        "cn-430000" => &["hunan", "湖南"],
        "cn-440000" => &["guangdong", "广东"],
        "cn-450000" => &["guangxi", "广西"],
        "cn-460000" => &["hainan", "海南"],
        "cn-500000" => &["chongqing", "重庆"],
        "cn-510000" => &["sichuan", "四川"],
        "cn-520000" => &["guizhou", "贵州"],
        "cn-530000" => &["yunnan", "云南"],
        "cn-540000" => &["tibet", "xizang", "西藏"],
        "cn-610000" => &["shaanxi", "陕西"],
        "cn-620000" => &["gansu", "甘肃"],
        "cn-630000" => &["qinghai", "青海"],
        "cn-640000" => &["ningxia", "宁夏"],
        "cn-650000" => &["xinjiang", "新疆"],
        "cn-710000" => &["taiwan", "台湾"],
        "cn-810000" => &["hong kong", "香港"],
        "cn-820000" => &["macau", "macao", "澳门"],
        _ => &[],
    }
}

fn fallback_mainland_node(region: &str, city: &str) -> GeoNode {
    let key = format!("{region}:{city}");
    let fallback_pool = [
        "cn-310000",
        "cn-320000",
        "cn-330000",
        "cn-370000",
        "cn-440000",
        "cn-510000",
        "cn-110000",
        "cn-420000",
    ];
    let index = stable_index(&key, fallback_pool.len());
    china_nodes()
        .iter()
        .find(|node| node.id == fallback_pool[index])
        .cloned()
        .unwrap_or_else(|| china_nodes()[0].clone())
}

fn fallback_node(source_ip: &str) -> GeoNode {
    let parsed_ip = source_ip.parse::<IpAddr>().ok();
    if parsed_ip.map(is_internal_ip).unwrap_or(false) {
        return internal_node();
    }
    let pool = china_nodes();
    pool[stable_index(source_ip, pool.len())].clone()
}

fn stable_index(value: &str, len: usize) -> usize {
    use std::collections::hash_map::DefaultHasher;

    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    (hasher.finish() as usize) % len.max(1)
}

fn china_nodes() -> &'static [GeoNode] {
    &[
        GeoNode {
            id: "cn-110000",
            name: "北京",
            region: "北京市",
            lat: 40.18994,
            lng: 116.41995,
            traffic_weight: 0.90,
        },
        GeoNode {
            id: "cn-120000",
            name: "天津",
            region: "天津市",
            lat: 39.288036,
            lng: 117.347043,
            traffic_weight: 0.72,
        },
        GeoNode {
            id: "cn-130000",
            name: "河北",
            region: "河北省",
            lat: 38.045474,
            lng: 114.502461,
            traffic_weight: 0.64,
        },
        GeoNode {
            id: "cn-140000",
            name: "山西",
            region: "山西省",
            lat: 37.618179,
            lng: 112.304436,
            traffic_weight: 0.45,
        },
        GeoNode {
            id: "cn-150000",
            name: "内蒙古",
            region: "内蒙古自治区",
            lat: 44.331087,
            lng: 114.077429,
            traffic_weight: 0.34,
        },
        GeoNode {
            id: "cn-210000",
            name: "辽宁",
            region: "辽宁省",
            lat: 41.299712,
            lng: 122.604994,
            traffic_weight: 0.52,
        },
        GeoNode {
            id: "cn-220000",
            name: "吉林",
            region: "吉林省",
            lat: 43.703954,
            lng: 126.171208,
            traffic_weight: 0.31,
        },
        GeoNode {
            id: "cn-230000",
            name: "黑龙江",
            region: "黑龙江省",
            lat: 48.040465,
            lng: 127.693027,
            traffic_weight: 0.28,
        },
        GeoNode {
            id: "cn-310000",
            name: "上海",
            region: "上海市",
            lat: 31.072559,
            lng: 121.438737,
            traffic_weight: 1.0,
        },
        GeoNode {
            id: "cn-320000",
            name: "江苏",
            region: "江苏省",
            lat: 32.983991,
            lng: 119.486506,
            traffic_weight: 0.86,
        },
        GeoNode {
            id: "cn-330000",
            name: "浙江",
            region: "浙江省",
            lat: 29.181466,
            lng: 120.109913,
            traffic_weight: 0.84,
        },
        GeoNode {
            id: "cn-340000",
            name: "安徽",
            region: "安徽省",
            lat: 31.849254,
            lng: 117.226884,
            traffic_weight: 0.57,
        },
        GeoNode {
            id: "cn-350000",
            name: "福建",
            region: "福建省",
            lat: 26.069925,
            lng: 118.006468,
            traffic_weight: 0.67,
        },
        GeoNode {
            id: "cn-360000",
            name: "江西",
            region: "江西省",
            lat: 27.636112,
            lng: 115.732975,
            traffic_weight: 0.44,
        },
        GeoNode {
            id: "cn-370000",
            name: "山东",
            region: "山东省",
            lat: 36.376092,
            lng: 118.187759,
            traffic_weight: 0.76,
        },
        GeoNode {
            id: "cn-410000",
            name: "河南",
            region: "河南省",
            lat: 33.902648,
            lng: 113.619717,
            traffic_weight: 0.62,
        },
        GeoNode {
            id: "cn-420000",
            name: "湖北",
            region: "湖北省",
            lat: 30.987527,
            lng: 112.271301,
            traffic_weight: 0.59,
        },
        GeoNode {
            id: "cn-430000",
            name: "湖南",
            region: "湖南省",
            lat: 27.629216,
            lng: 111.711649,
            traffic_weight: 0.51,
        },
        GeoNode {
            id: "cn-440000",
            name: "广东",
            region: "广东省",
            lat: 23.334643,
            lng: 113.429919,
            traffic_weight: 0.92,
        },
        GeoNode {
            id: "cn-450000",
            name: "广西",
            region: "广西壮族自治区",
            lat: 23.833381,
            lng: 108.7944,
            traffic_weight: 0.38,
        },
        GeoNode {
            id: "cn-460000",
            name: "海南",
            region: "海南省",
            lat: 19.189767,
            lng: 109.754859,
            traffic_weight: 0.29,
        },
        GeoNode {
            id: "cn-500000",
            name: "重庆",
            region: "重庆市",
            lat: 30.067297,
            lng: 107.8839,
            traffic_weight: 0.50,
        },
        GeoNode {
            id: "cn-510000",
            name: "四川",
            region: "四川省",
            lat: 30.674545,
            lng: 102.693453,
            traffic_weight: 0.56,
        },
        GeoNode {
            id: "cn-520000",
            name: "贵州",
            region: "贵州省",
            lat: 26.826368,
            lng: 106.880455,
            traffic_weight: 0.36,
        },
        GeoNode {
            id: "cn-530000",
            name: "云南",
            region: "云南省",
            lat: 25.008643,
            lng: 101.485106,
            traffic_weight: 0.33,
        },
        GeoNode {
            id: "cn-540000",
            name: "西藏",
            region: "西藏自治区",
            lat: 31.56375,
            lng: 88.388277,
            traffic_weight: 0.16,
        },
        GeoNode {
            id: "cn-610000",
            name: "陕西",
            region: "陕西省",
            lat: 35.263661,
            lng: 108.887114,
            traffic_weight: 0.48,
        },
        GeoNode {
            id: "cn-620000",
            name: "甘肃",
            region: "甘肃省",
            lat: 36.058039,
            lng: 103.823557,
            traffic_weight: 0.24,
        },
        GeoNode {
            id: "cn-630000",
            name: "青海",
            region: "青海省",
            lat: 35.726403,
            lng: 96.043533,
            traffic_weight: 0.18,
        },
        GeoNode {
            id: "cn-640000",
            name: "宁夏",
            region: "宁夏回族自治区",
            lat: 37.291332,
            lng: 106.169866,
            traffic_weight: 0.22,
        },
        GeoNode {
            id: "cn-650000",
            name: "新疆",
            region: "新疆维吾尔自治区",
            lat: 41.371801,
            lng: 85.294711,
            traffic_weight: 0.20,
        },
        GeoNode {
            id: "cn-710000",
            name: "台湾",
            region: "台湾省",
            lat: 23.749452,
            lng: 120.971485,
            traffic_weight: 0.54,
        },
        GeoNode {
            id: "cn-810000",
            name: "香港",
            region: "香港特别行政区",
            lat: 22.377366,
            lng: 114.134357,
            traffic_weight: 0.60,
        },
        GeoNode {
            id: "cn-820000",
            name: "澳门",
            region: "澳门特别行政区",
            lat: 22.159307,
            lng: 113.566988,
            traffic_weight: 0.32,
        },
    ]
}

fn clamp_f64(value: f64, min: f64, max: f64) -> f64 {
    value.min(max).max(min)
}

fn unix_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
