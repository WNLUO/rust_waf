use dashmap::DashMap;
use reqwest::Client;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

mod geo;
mod snapshot;
mod types;

use geo::{
    fallback_node, internal_node, is_internal_ip, map_remote_region_to_node,
    origin_node_from_geo_payload, origin_node_from_ip_sb_payload, origin_node_from_ipip_payload,
    pending_origin_node,
};
use snapshot::build_snapshot_from_observations;
use types::{
    CachedOriginNode, GeoNode, IpSbGeoResponse, IpWhoisResponse, IpipRegionResponse,
    PublicIpResponse, TrafficObservation,
};
pub use types::{
    TrafficDecision, TrafficDirection, TrafficMapFlowSnapshot, TrafficMapNodeSnapshot,
    TrafficMapSnapshot, TrafficRealtimeEvent, TrafficRealtimeEventRaw, TrafficRealtimeNode,
};

const ORIGIN_CACHE_TTL_SUCCESS_MS: i64 = 10 * 60 * 1_000;
const ORIGIN_CACHE_TTL_PENDING_MS: i64 = 15 * 1_000;
const EXTERNAL_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const TRAFFIC_MAP_MAX_OBSERVATIONS: usize = 8_192;
const TRAFFIC_MAP_MAX_GEO_CACHE_ENTRIES: usize = 2_048;
const TRAFFIC_MAP_MAX_ACTIVE_IPS_PER_SNAPSHOT: usize = 512;

#[derive(Debug)]
pub struct TrafficMapCollector {
    observations: Mutex<VecDeque<TrafficObservation>>,
    geo_cache: DashMap<String, GeoNode>,
    origin_cache: Mutex<Option<CachedOriginNode>>,
    http_client: Client,
    max_window_seconds: u32,
    realtime_tx: broadcast::Sender<TrafficRealtimeEventRaw>,
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
            self.cache_geo_node(event.source_ip.clone(), resolved);
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
                country_code: entry.country_code.clone(),
                country_name: entry.country_name.clone(),
                geo_scope: entry.geo_scope.clone(),
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
                    country_code: fallback.country_code,
                    country_name: fallback.country_name,
                    geo_scope: fallback.geo_scope,
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
        while guard.len() > TRAFFIC_MAP_MAX_OBSERVATIONS {
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
        let mut unique_ips = unique_ips.into_iter().collect::<Vec<_>>();
        unique_ips.sort();
        if unique_ips.len() > TRAFFIC_MAP_MAX_ACTIVE_IPS_PER_SNAPSHOT {
            unique_ips.truncate(TRAFFIC_MAP_MAX_ACTIVE_IPS_PER_SNAPSHOT);
        }
        for ip in unique_ips {
            if self.geo_cache.contains_key(&ip) {
                continue;
            }
            let resolved = self.resolve_geo_node(&ip).await;
            self.cache_geo_node(ip, resolved);
        }

        build_snapshot_from_observations(
            window_seconds,
            now_ms,
            observations,
            &self.geo_cache,
            self.origin_node().await,
        )
    }

    async fn resolve_geo_node(&self, source_ip: &str) -> GeoNode {
        let parsed_ip = source_ip.parse::<IpAddr>().ok();
        if parsed_ip.map(is_internal_ip).unwrap_or(false) {
            return internal_node();
        }

        if let Some(payload) = self.lookup_remote_region(source_ip).await {
            if let Some(node) = map_remote_region_to_node(source_ip, &payload) {
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

    fn cache_geo_node(&self, source_ip: String, node: GeoNode) {
        if self.geo_cache.len() >= TRAFFIC_MAP_MAX_GEO_CACHE_ENTRIES
            && !self.geo_cache.contains_key(&source_ip)
        {
            self.evict_geo_cache_entries(TRAFFIC_MAP_MAX_GEO_CACHE_ENTRIES / 8);
        }
        if self.geo_cache.len() >= TRAFFIC_MAP_MAX_GEO_CACHE_ENTRIES
            && !self.geo_cache.contains_key(&source_ip)
        {
            return;
        }
        self.geo_cache.insert(source_ip, node);
    }

    fn evict_geo_cache_entries(&self, count: usize) {
        if count == 0 {
            return;
        }
        let mut keys = self
            .geo_cache
            .iter()
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        keys.sort();
        for key in keys.into_iter().take(count) {
            self.geo_cache.remove(&key);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_map_keeps_observation_count_bounded() {
        let collector = TrafficMapCollector::new();
        for index in 0..(TRAFFIC_MAP_MAX_OBSERVATIONS + 128) {
            collector.record_ingress(format!("203.0.113.{}", index % 200), 128, false);
        }

        let guard = collector
            .observations
            .lock()
            .expect("traffic map observation lock poisoned");
        assert!(guard.len() <= TRAFFIC_MAP_MAX_OBSERVATIONS);
    }

    #[test]
    fn traffic_map_geo_cache_is_capped() {
        let collector = TrafficMapCollector::new();
        for index in 0..(TRAFFIC_MAP_MAX_GEO_CACHE_ENTRIES + 128) {
            collector.cache_geo_node(format!("198.51.100.{index}"), fallback_node("198.51.100.1"));
        }

        assert!(collector.geo_cache.len() <= TRAFFIC_MAP_MAX_GEO_CACHE_ENTRIES);
    }
}
