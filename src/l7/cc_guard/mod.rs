use crate::config::l7::CcDefenseConfig;
use crate::protocol::UnifiedHttpRequest;
use dashmap::DashMap;
use rand::Rng;
use std::sync::atomic::AtomicU64;
use std::sync::RwLock;

mod counters;
mod helpers;
mod runtime;
mod types;

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
            page_load_windows: DashMap::new(),
            page_load_host_windows: DashMap::new(),
            request_sequence: AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> CcDefenseConfig {
        self.config
            .read()
            .expect("l7 cc config lock poisoned")
            .clone()
    }

    pub fn update_config(&self, config: &CcDefenseConfig) {
        let mut guard = self.config.write().expect("l7 cc config lock poisoned");
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
}

#[cfg(test)]
mod tests;
