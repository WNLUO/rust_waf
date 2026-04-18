use super::*;

impl L7BehaviorGuard {
    pub(super) fn observe_and_assess(
        &self,
        identity: &str,
        route: String,
        kind: RequestKind,
        client_ip: Option<String>,
        user_agent: Option<String>,
        header_signature: Option<String>,
        now: Instant,
        unix_now: i64,
        window: Duration,
        bucket_limit: usize,
    ) -> BehaviorAssessment {
        let identity = bounded_dashmap_key(
            &self.buckets,
            compact_component("identity", &identity, MAX_BEHAVIOR_KEY_LEN),
            bucket_limit,
            "behavior",
            OVERFLOW_SHARDS,
        );
        let mut entry = self
            .buckets
            .entry(identity.clone())
            .or_insert_with(BehaviorWindow::new);
        entry.observe_and_assess(
            identity,
            route,
            kind,
            client_ip,
            user_agent,
            header_signature,
            now,
            unix_now,
            window,
        )
    }

    pub(super) fn observe_aggregate_and_assess(
        &self,
        identity: &str,
        route: String,
        kind: RequestKind,
        client_ip: Option<String>,
        user_agent: Option<String>,
        header_signature: Option<String>,
        now: Instant,
        unix_now: i64,
        window: Duration,
        bucket_limit: usize,
    ) -> BehaviorAssessment {
        let identity = bounded_dashmap_key(
            &self.aggregate_buckets,
            compact_component("aggregate", identity, MAX_BEHAVIOR_KEY_LEN),
            bucket_limit,
            "behavior-aggregate",
            OVERFLOW_SHARDS,
        );
        let mut entry = self
            .aggregate_buckets
            .entry(identity.clone())
            .or_insert_with(BehaviorWindow::new);
        entry.observe_and_assess(
            identity,
            route,
            kind,
            client_ip,
            user_agent,
            header_signature,
            now,
            unix_now,
            window,
        )
    }

    pub(super) fn maybe_cleanup(&self, unix_now: i64) {
        let sequence = self.request_sequence.fetch_add(1, Ordering::Relaxed) + 1;
        if !sequence.is_multiple_of(CLEANUP_EVERY_REQUESTS) {
            return;
        }

        let stale_before = unix_now - (BEHAVIOR_WINDOW_SECS as i64 * 3).max(180);
        let keys = self
            .buckets
            .iter()
            .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in keys {
            self.buckets.remove(&key);
        }

        let aggregate_keys = self
            .aggregate_buckets
            .iter()
            .filter(|entry| entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_before)
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in aggregate_keys {
            self.aggregate_buckets.remove(&key);
        }

        let stale_burst_before = unix_now - (ROUTE_BURST_WINDOW_SECS as i64 * 6).max(30);
        let route_burst_keys = self
            .route_burst_buckets
            .iter()
            .filter(|entry| {
                entry.value().last_seen_unix.load(Ordering::Relaxed) < stale_burst_before
            })
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in route_burst_keys {
            self.route_burst_buckets.remove(&key);
        }

        let expired_enforcements = self
            .aggregate_enforcements
            .iter()
            .filter(|entry| entry.value().expires_at <= Instant::now())
            .take(512)
            .map(|entry| entry.key().clone())
            .collect::<Vec<_>>();
        for key in expired_enforcements {
            self.aggregate_enforcements.remove(&key);
        }
    }

    pub(super) fn record_challenge(&self, identity: &str, now: Instant, window: Duration) {
        if let Some(mut entry) = self.buckets.get_mut(identity) {
            entry.record_challenge(now, window);
            return;
        }
        if let Some(mut entry) = self.aggregate_buckets.get_mut(identity) {
            entry.record_challenge(now, window);
        }
    }

    pub(super) fn record_block(&self, identity: &str, now: Instant, window: Duration) {
        if let Some(mut entry) = self.buckets.get_mut(identity) {
            entry.record_block(now, window);
            return;
        }
        if let Some(mut entry) = self.aggregate_buckets.get_mut(identity) {
            entry.record_block(now, window);
        }
    }
}
