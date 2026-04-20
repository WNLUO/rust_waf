use super::counters::*;
use super::helpers::*;
use super::types::*;
use super::L7CcGuard;
use crate::config::l7::CcDefenseConfig;
use crate::protocol::UnifiedHttpRequest;
use dashmap::DashMap;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

impl L7CcGuard {
    pub(super) fn observe(
        &self,
        map: &DashMap<String, SlidingWindowCounter>,
        key: String,
        now: Instant,
        unix_now: i64,
        window: Duration,
        limit: usize,
    ) -> u32 {
        let key = bounded_dashmap_key(map, key, limit, "cc", OVERFLOW_SHARDS);
        let mut entry = map.entry(key).or_insert_with(SlidingWindowCounter::new);
        entry.observe(now, unix_now, window)
    }

    pub(super) fn observe_weighted(
        &self,
        map: &DashMap<String, WeightedSlidingWindowCounter>,
        key: String,
        now: Instant,
        unix_now: i64,
        window: Duration,
        weight_percent: u8,
        limit: usize,
    ) -> u32 {
        let key = bounded_dashmap_key(map, key, limit, "cc_weighted", OVERFLOW_SHARDS);
        let mut entry = map
            .entry(key)
            .or_insert_with(WeightedSlidingWindowCounter::new);
        entry.observe(now, unix_now, window, weight_percent)
    }

    pub(super) fn observe_distinct(
        &self,
        map: &DashMap<String, DistinctSlidingWindowCounter>,
        key: String,
        value: String,
        now: Instant,
        unix_now: i64,
        window: Duration,
        limit: usize,
    ) -> u32 {
        let key = bounded_dashmap_key(map, key, limit, "cc_distinct", OVERFLOW_SHARDS);
        let mut entry = map
            .entry(key)
            .or_insert_with(DistinctSlidingWindowCounter::new);
        entry.observe(value, now, unix_now, window)
    }

    pub(super) fn observe_fast(
        &self,
        map: &DashMap<String, FastWindowCounter>,
        key: String,
        unix_now: i64,
        window_secs: u64,
        limit: usize,
    ) -> FastWindowObservation {
        let key = bounded_dashmap_key(map, key, limit, "cc_fast", OVERFLOW_SHARDS);
        let entry = map
            .entry(key)
            .or_insert_with(|| FastWindowCounter::new(unix_now));
        entry.observe(unix_now, window_secs, 1)
    }

    pub(super) fn hot_block_cache_hit_and_extend(
        &self,
        key: &str,
        unix_now: i64,
        base_ttl_secs: u64,
    ) -> Option<bool> {
        let entry = self.hot_block_cache.get(key)?;
        if entry.record_hit_and_extend(unix_now, base_ttl_secs) {
            return Some(true);
        }
        drop(entry);
        self.hot_block_cache.remove(key);
        Some(false)
    }

    pub(super) fn insert_hot_block_cache(&self, key: String, unix_now: i64, ttl_secs: u64) {
        let expires_at = unix_now.saturating_add(ttl_secs.max(1) as i64);
        if let Some(entry) = self.hot_block_cache.get(&key) {
            entry.refresh(expires_at, unix_now);
            return;
        }
        self.hot_block_cache
            .insert(key, HotBlockEntry::new(expires_at, unix_now));
    }

    pub(super) fn request_weight_percent(
        &self,
        kind: RequestKind,
        is_page_subresource: bool,
        interactive_session: bool,
        config: &CcDefenseConfig,
    ) -> u8 {
        if is_page_subresource {
            return config.page_subresource_weight_percent;
        }
        if interactive_session {
            return match kind {
                RequestKind::StaticAsset => config.static_request_weight_percent.min(30),
                RequestKind::ApiLike => API_REQUEST_WEIGHT_PERCENT.min(90),
                RequestKind::Document => 80,
                RequestKind::Other => 70,
            };
        }
        match kind {
            RequestKind::ApiLike => API_REQUEST_WEIGHT_PERCENT,
            RequestKind::StaticAsset => config.static_request_weight_percent,
            _ => 100,
        }
    }

    pub(super) fn record_page_load_window(
        &self,
        client_ip: std::net::IpAddr,
        host: &str,
        document_path: &str,
        unix_now: i64,
        config: &CcDefenseConfig,
        limit: usize,
    ) {
        let key = bounded_dashmap_key(
            &self.page_load_windows,
            page_window_key(client_ip, host, document_path),
            limit,
            "cc_page_window",
            OVERFLOW_SHARDS,
        );
        let host_key = bounded_dashmap_key(
            &self.page_load_host_windows,
            page_host_window_key(client_ip, host),
            limit,
            "cc_page_host_window",
            OVERFLOW_SHARDS,
        );
        let expires_at = unix_now + effective_page_load_grace_secs(config) as i64;
        let mut entry = self
            .page_load_windows
            .entry(key)
            .or_insert_with(|| PageLoadWindowState::new(expires_at, unix_now));
        entry.refresh(expires_at, unix_now);
        let mut host_entry = self
            .page_load_host_windows
            .entry(host_key)
            .or_insert_with(|| PageLoadWindowState::new(expires_at, unix_now));
        host_entry.refresh(expires_at, unix_now);
    }

    pub(super) fn matches_page_load_window(
        &self,
        request: &UnifiedHttpRequest,
        client_ip: std::net::IpAddr,
        host: &str,
        raw_path: &str,
        unix_now: i64,
        limit: usize,
    ) -> bool {
        if !request.method.eq_ignore_ascii_case("GET")
            && !request.method.eq_ignore_ascii_case("HEAD")
        {
            return false;
        }

        if let Some((referer_host, referer_path)) = referer_host_path(request) {
            if referer_host.eq_ignore_ascii_case(host) {
                let key = bounded_dashmap_key(
                    &self.page_load_windows,
                    page_window_key(client_ip, host, &normalized_route_path(&referer_path)),
                    limit,
                    "cc_page_window",
                    OVERFLOW_SHARDS,
                );
                if self
                    .page_load_windows
                    .get(&key)
                    .map(|entry| entry.is_active(unix_now))
                    .unwrap_or(false)
                {
                    return true;
                }
            }
        }

        // Weak match path: when Referer/Sec-Fetch metadata is missing but path strongly
        // looks like a static asset, still trust a short host-level page-load window.
        if !looks_like_static_asset(raw_path) {
            return false;
        }
        let host_key = bounded_dashmap_key(
            &self.page_load_host_windows,
            page_host_window_key(client_ip, host),
            limit,
            "cc_page_host_window",
            OVERFLOW_SHARDS,
        );
        self.page_load_host_windows
            .get(&host_key)
            .map(|entry| entry.is_active(unix_now))
            .unwrap_or(false)
    }

    pub(super) fn maybe_cleanup(&self, unix_now: i64, config: &CcDefenseConfig) {
        let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        let largest_map_len = [
            self.ip_buckets.len(),
            self.host_buckets.len(),
            self.route_buckets.len(),
            self.hot_path_buckets.len(),
            self.hot_path_client_buckets.len(),
            self.ip_weighted_buckets.len(),
            self.host_weighted_buckets.len(),
            self.route_weighted_buckets.len(),
            self.hot_path_weighted_buckets.len(),
            self.fast_ip_buckets.len(),
            self.fast_route_buckets.len(),
            self.fast_hot_path_buckets.len(),
            self.hot_block_cache.len(),
            self.page_load_windows.len(),
            self.page_load_host_windows.len(),
        ]
        .into_iter()
        .max()
        .unwrap_or(0);
        let cleanup_interval = cleanup_interval_for_size(largest_map_len);
        if !sequence.is_multiple_of(cleanup_interval) {
            return;
        }

        let stale_before = unix_now - (config.request_window_secs as i64 * 6).max(30);
        let cleanup_batch = cleanup_batch_for_size(largest_map_len);
        cleanup_map(&self.ip_buckets, stale_before, cleanup_batch);
        cleanup_map(&self.host_buckets, stale_before, cleanup_batch);
        cleanup_map(&self.route_buckets, stale_before, cleanup_batch);
        cleanup_map(&self.hot_path_buckets, stale_before, cleanup_batch);
        cleanup_distinct_map(&self.hot_path_client_buckets, stale_before, cleanup_batch);
        cleanup_weighted_map(&self.ip_weighted_buckets, stale_before, cleanup_batch);
        cleanup_weighted_map(&self.host_weighted_buckets, stale_before, cleanup_batch);
        cleanup_weighted_map(&self.route_weighted_buckets, stale_before, cleanup_batch);
        cleanup_weighted_map(&self.hot_path_weighted_buckets, stale_before, cleanup_batch);
        cleanup_fast_window_map(&self.fast_ip_buckets, stale_before, cleanup_batch);
        cleanup_fast_window_map(&self.fast_route_buckets, stale_before, cleanup_batch);
        cleanup_fast_window_map(&self.fast_hot_path_buckets, stale_before, cleanup_batch);
        cleanup_hot_block_map(&self.hot_block_cache, unix_now, stale_before, cleanup_batch);
        cleanup_page_window_map(
            &self.page_load_windows,
            unix_now,
            stale_before,
            cleanup_batch,
        );
        cleanup_page_window_map(
            &self.page_load_host_windows,
            unix_now,
            stale_before,
            cleanup_batch,
        );
    }
}
