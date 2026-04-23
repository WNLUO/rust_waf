use crate::config::l7::CcDefenseConfig;
use crate::protocol::UnifiedHttpRequest;
use dashmap::DashMap;
use rand::Rng;
use std::sync::atomic::AtomicU64;
use std::sync::RwLock;

mod challenge;
mod counters;
mod helpers;
mod runtime;
mod tracking;
mod types;

use crate::locks::{read_lock, write_lock};
use helpers::*;
use types::*;

#[derive(Debug)]
pub struct L7CcGuard {
    config: RwLock<CcDefenseConfig>,
    secret: String,
    ip_buckets: DashMap<String, SlidingWindowCounter>,
    host_buckets: DashMap<String, SlidingWindowCounter>,
    route_buckets: DashMap<String, SlidingWindowCounter>,
    hot_path_buckets: DashMap<String, SlidingWindowCounter>,
    hot_path_client_buckets: DashMap<String, DistinctSlidingWindowCounter>,
    ip_weighted_buckets: DashMap<String, WeightedSlidingWindowCounter>,
    host_weighted_buckets: DashMap<String, WeightedSlidingWindowCounter>,
    route_weighted_buckets: DashMap<String, WeightedSlidingWindowCounter>,
    hot_path_weighted_buckets: DashMap<String, WeightedSlidingWindowCounter>,
    fast_ip_buckets: DashMap<String, FastWindowCounter>,
    fast_route_buckets: DashMap<String, FastWindowCounter>,
    fast_hot_path_buckets: DashMap<String, FastWindowCounter>,
    hot_block_cache: DashMap<String, HotBlockEntry>,
    page_load_windows: DashMap<String, PageLoadWindowState>,
    page_load_host_windows: DashMap<String, PageLoadWindowState>,
    request_sequence: AtomicU64,
}

impl L7CcGuard {
    pub fn new(config: &CcDefenseConfig) -> Self {
        let secret = format!("{:032x}", rand::thread_rng().gen::<u128>());
        Self {
            config: RwLock::new(config.clone()),
            secret,
            ip_buckets: DashMap::new(),
            host_buckets: DashMap::new(),
            route_buckets: DashMap::new(),
            hot_path_buckets: DashMap::new(),
            hot_path_client_buckets: DashMap::new(),
            ip_weighted_buckets: DashMap::new(),
            host_weighted_buckets: DashMap::new(),
            route_weighted_buckets: DashMap::new(),
            hot_path_weighted_buckets: DashMap::new(),
            fast_ip_buckets: DashMap::new(),
            fast_route_buckets: DashMap::new(),
            fast_hot_path_buckets: DashMap::new(),
            hot_block_cache: DashMap::new(),
            page_load_windows: DashMap::new(),
            page_load_host_windows: DashMap::new(),
            request_sequence: AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> CcDefenseConfig {
        read_lock(&self.config, "l7 cc config").clone()
    }

    pub fn update_config(&self, config: &CcDefenseConfig) {
        let mut guard = write_lock(&self.config, "l7 cc config");
        *guard = config.clone();
    }

    pub fn allows_browser_fingerprint_report(
        &self,
        request: &UnifiedHttpRequest,
        fallback_client_ip: std::net::IpAddr,
    ) -> bool {
        let config = self.config();
        let client_ip = request_client_ip(request).unwrap_or(fallback_client_ip);
        let host = normalized_host(request);
        self.has_valid_challenge_cookie(request, client_ip, &host, &config)
    }

    pub fn has_valid_request_challenge(&self, request: &UnifiedHttpRequest) -> bool {
        let Some(client_ip) = request_client_ip(request) else {
            return false;
        };
        let config = self.config();
        let host = normalized_host(request);
        self.has_valid_challenge_cookie(request, client_ip, &host, &config)
    }

    pub fn build_request_challenge_result(
        &self,
        request: &UnifiedHttpRequest,
        reason: impl Into<String>,
    ) -> Option<crate::core::InspectionResult> {
        let client_ip = request_client_ip(request)?;
        let config = self.config();
        let host = normalized_host(request);
        let raw_path = request_path(&request.uri);
        let html_mode = challenge_mode(request, raw_path);
        let reason = reason.into();
        Some(crate::core::InspectionResult::respond(
            crate::core::InspectionLayer::L7,
            reason.clone(),
            self.build_challenge_response(request, client_ip, &host, &reason, html_mode, &config),
        ))
    }
}

#[cfg(test)]
mod tests;
