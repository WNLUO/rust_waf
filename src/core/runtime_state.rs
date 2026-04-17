use super::{
    adaptive_protection, auto_tuning, resource_budget, traffic_map, unix_timestamp,
    AiAutoAuditRuntimeSnapshot, DefenseDepth, Http3RuntimeSnapshot, LocalDefenseRecommendation,
    RuntimePressureSnapshot, SiteDefenseBucket, UpstreamHealthSnapshot, WafContext,
};
use crate::core::InspectionResult;
use crate::l4::L4Inspector;
use crate::protocol::UnifiedHttpRequest;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::broadcast;

const MAX_ROUTE_DEFENSE_BUCKETS: usize = 8_192;

impl WafContext {
    pub fn runtime_pressure_snapshot(&self) -> RuntimePressureSnapshot {
        let auto = self.auto_tuning_snapshot();
        let storage_queue_usage_percent = self
            .sqlite_store
            .as_ref()
            .map(|store| store.queue_usage_percent())
            .unwrap_or(0);

        let mut score = 0u8;
        if storage_queue_usage_percent >= 75 {
            score += 1;
        }
        if storage_queue_usage_percent >= 90 {
            score += 2;
        }
        if auto.last_observed_avg_proxy_latency_ms >= 800 {
            score += 2;
        } else if auto.last_observed_avg_proxy_latency_ms >= 300 {
            score += 1;
        }
        if auto.last_observed_identity_resolution_pressure_percent >= 5.0 {
            score += 2;
        } else if auto.last_observed_identity_resolution_pressure_percent >= 1.0 {
            score += 1;
        }
        if auto.last_observed_l7_friction_pressure_percent >= 25.0 {
            score += 2;
        } else if auto.last_observed_l7_friction_pressure_percent >= 10.0 {
            score += 1;
        }
        if auto.last_observed_slow_attack_pressure_percent >= 2.0 {
            score += 2;
        } else if auto.last_observed_slow_attack_pressure_percent >= 0.5 {
            score += 1;
        }

        let level = match score {
            0..=1 => "normal",
            2..=3 => "elevated",
            4..=5 => "high",
            _ => "attack",
        };

        let budget =
            resource_budget::current_runtime_resource_budget(level, storage_queue_usage_percent);

        RuntimePressureSnapshot {
            level,
            capacity_class: budget.capacity_class.as_str(),
            defense_depth: budget.defense_depth.as_str(),
            storage_queue_usage_percent,
            drop_delay: matches!(level, "high" | "attack") || budget.prefer_drop,
            trim_event_persistence: storage_queue_usage_percent >= 75
                || matches!(level, "high" | "attack")
                || budget.aggregate_events,
            l7_bucket_limit: budget.l7_bucket_limit,
            l7_page_window_limit: budget.l7_page_window_limit,
            behavior_bucket_limit: budget.behavior_bucket_limit,
            behavior_sample_stride: budget.behavior_sample_stride,
            prefer_drop: budget.prefer_drop,
        }
    }

    pub fn annotate_runtime_pressure(&self, request: &mut UnifiedHttpRequest) {
        let pressure = self.runtime_pressure_snapshot();
        request.add_metadata(
            "runtime.pressure.level".to_string(),
            pressure.level.to_string(),
        );
        request.add_metadata(
            "runtime.pressure.storage_queue_percent".to_string(),
            pressure.storage_queue_usage_percent.to_string(),
        );
        request.add_metadata(
            "runtime.capacity.class".to_string(),
            pressure.capacity_class.to_string(),
        );
        request.add_metadata(
            "runtime.defense.depth".to_string(),
            pressure.defense_depth.to_string(),
        );
        request.add_metadata(
            "runtime.budget.l7_bucket_limit".to_string(),
            pressure.l7_bucket_limit.to_string(),
        );
        request.add_metadata(
            "runtime.budget.l7_page_window_limit".to_string(),
            pressure.l7_page_window_limit.to_string(),
        );
        request.add_metadata(
            "runtime.budget.behavior_bucket_limit".to_string(),
            pressure.behavior_bucket_limit.to_string(),
        );
        request.add_metadata(
            "runtime.budget.behavior_sample_stride".to_string(),
            pressure.behavior_sample_stride.to_string(),
        );
        if pressure.drop_delay {
            request.add_metadata(
                "runtime.pressure.drop_delay".to_string(),
                "true".to_string(),
            );
        }
        if pressure.prefer_drop {
            request.add_metadata("runtime.prefer_drop".to_string(), "true".to_string());
        }
        if pressure.trim_event_persistence {
            request.add_metadata(
                "runtime.pressure.trim_event_persistence".to_string(),
                "true".to_string(),
            );
            request.add_metadata("runtime.aggregate_events".to_string(), "true".to_string());
        }
    }

    pub fn annotate_site_runtime_budget(&self, request: &mut UnifiedHttpRequest) {
        let Some(site_id) = request.get_metadata("gateway.site_id").cloned() else {
            return;
        };
        let site_depth = self.site_defense_depth(&site_id);
        let route = runtime_route_path(&request.uri);
        let route_depth = self.route_defense_depth(&site_id, &route);
        let Some(site_depth) = select_strictest_depth(site_depth, route_depth) else {
            return;
        };
        let current_depth = request
            .get_metadata("runtime.defense.depth")
            .map(|value| DefenseDepth::from_str(value))
            .unwrap_or(DefenseDepth::Balanced);
        if !defense_depth_is_stricter(site_depth, current_depth) {
            return;
        }

        let pseudo_pressure = match site_depth {
            DefenseDepth::Survival => "attack",
            DefenseDepth::Lean => "high",
            _ => "elevated",
        };
        let current_queue = request
            .get_metadata("runtime.pressure.storage_queue_percent")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let budget =
            resource_budget::current_runtime_resource_budget(pseudo_pressure, current_queue);
        request.add_metadata(
            "runtime.defense.depth".to_string(),
            site_depth.as_str().to_string(),
        );
        request.add_metadata(
            "runtime.site.defense_depth".to_string(),
            site_depth.as_str().to_string(),
        );
        if let Some(route_depth) = route_depth {
            request.add_metadata(
                "runtime.route.defense_depth".to_string(),
                route_depth.as_str().to_string(),
            );
            request.add_metadata("runtime.route.defense_route".to_string(), route);
            apply_route_local_cc_tightening(request, route_depth);
        }
        request.add_metadata(
            "runtime.site.defense_reason".to_string(),
            "site_local_attack_pressure".to_string(),
        );
        request.add_metadata(
            "runtime.budget.l7_bucket_limit".to_string(),
            budget.l7_bucket_limit.to_string(),
        );
        request.add_metadata(
            "runtime.budget.l7_page_window_limit".to_string(),
            budget.l7_page_window_limit.to_string(),
        );
        request.add_metadata(
            "runtime.budget.behavior_bucket_limit".to_string(),
            budget.behavior_bucket_limit.to_string(),
        );
        request.add_metadata(
            "runtime.budget.behavior_sample_stride".to_string(),
            budget.behavior_sample_stride.to_string(),
        );
        if budget.prefer_drop {
            request.add_metadata("runtime.prefer_drop".to_string(), "true".to_string());
        }
        if budget.aggregate_events {
            request.add_metadata("runtime.aggregate_events".to_string(), "true".to_string());
        }
    }

    pub fn note_site_defense_signal(
        &self,
        request: &UnifiedHttpRequest,
        result: &InspectionResult,
    ) {
        let Some(site_id) = request.get_metadata("gateway.site_id").cloned() else {
            return;
        };
        let is_soft = matches!(
            result.action,
            crate::core::InspectionAction::Respond | crate::core::InspectionAction::Alert
        );
        let is_hard = result.blocked
            || result.persist_blocked_ip
            || matches!(
                result.action,
                crate::core::InspectionAction::Block | crate::core::InspectionAction::Drop
            );
        if !is_soft && !is_hard {
            return;
        }

        let route = runtime_route_path(&request.uri);
        self.note_ai_defense_identity_signal(&site_id, &route, request, unix_timestamp());
        self.note_site_defense_event(&site_id, Some(&route), is_soft, is_hard);
    }

    pub fn note_site_hard_defense_signal(&self, site_id: &str) {
        self.note_site_defense_event(site_id, None, false, true);
    }

    fn note_site_defense_event(
        &self,
        site_id: &str,
        route: Option<&str>,
        is_soft: bool,
        is_hard: bool,
    ) {
        let now = unix_timestamp();
        let window_start = now.div_euclid(60) * 60;
        let entry = self
            .site_defense_buckets
            .entry(site_id.to_string())
            .or_insert_with(|| std::sync::Mutex::new(SiteDefenseBucket::default()));
        let mut bucket = entry.lock().expect("site defense bucket lock poisoned");
        if bucket.window_start != window_start {
            bucket.window_start = window_start;
            bucket.soft_events = 0;
            bucket.hard_events = 0;
        }
        if is_soft {
            bucket.soft_events = bucket.soft_events.saturating_add(1);
        }
        if is_hard {
            bucket.hard_events = bucket.hard_events.saturating_add(1);
        }

        let Some(route) = route else {
            return;
        };
        if route_defense_exempt(route) {
            return;
        }
        let route_key = route_defense_key(site_id, route);
        if !self.ensure_route_defense_capacity(&route_key, window_start) {
            return;
        }
        let entry = self
            .route_defense_buckets
            .entry(route_key)
            .or_insert_with(|| std::sync::Mutex::new(SiteDefenseBucket::default()));
        let mut bucket = entry.lock().expect("route defense bucket lock poisoned");
        if bucket.window_start != window_start {
            bucket.window_start = window_start;
            bucket.soft_events = 0;
            bucket.hard_events = 0;
        }
        if is_soft {
            bucket.soft_events = bucket.soft_events.saturating_add(1);
        }
        if is_hard {
            bucket.hard_events = bucket.hard_events.saturating_add(1);
        }
        if let Some(depth) = route_defense_depth_for_counts(bucket.soft_events, bucket.hard_events)
        {
            self.note_ai_defense_route_trigger(
                site_id,
                route,
                depth.as_str(),
                bucket.soft_events,
                bucket.hard_events,
                now,
            );
        }
    }

    pub fn effective_http2_max_concurrent_streams(&self, configured: usize) -> usize {
        let pressure = self.runtime_pressure_snapshot();
        protocol_stream_budget(configured, pressure.defense_depth)
    }

    pub fn apply_http3_runtime_budget(&self, config: &mut crate::config::Http3Config) {
        let pressure = self.runtime_pressure_snapshot();
        config.max_concurrent_streams =
            protocol_stream_budget(config.max_concurrent_streams, pressure.defense_depth);
        if matches!(pressure.defense_depth, "lean" | "survival") {
            config.enable_connection_migration = false;
            config.qpack_table_size = config.qpack_table_size.min(1024);
        }
        if pressure.defense_depth == "survival" {
            config.idle_timeout_secs = config.idle_timeout_secs.min(30).max(5);
        }
    }

    pub async fn traffic_map_snapshot(
        &self,
        window_seconds: u32,
    ) -> traffic_map::TrafficMapSnapshot {
        self.traffic_map.snapshot(window_seconds).await
    }

    pub fn subscribe_traffic_realtime(
        &self,
    ) -> broadcast::Receiver<traffic_map::TrafficRealtimeEventRaw> {
        self.traffic_map.subscribe_realtime()
    }

    pub fn local_defense_recommendations(&self, limit: usize) -> Vec<LocalDefenseRecommendation> {
        let now = unix_timestamp();
        let mut recommendations = self
            .route_defense_buckets
            .iter()
            .filter_map(|entry| {
                let (site_id, route) = split_route_defense_key(entry.key())?;
                let bucket = entry.value().lock().expect("route defense bucket lock poisoned");
                if now.saturating_sub(bucket.window_start) > 75 {
                    return None;
                }
                let total = bucket.soft_events.saturating_add(bucket.hard_events);
                let depth = route_defense_depth_for_counts(bucket.soft_events, bucket.hard_events)?;
                let suggested_value = match depth {
                    DefenseDepth::Survival => "45",
                    DefenseDepth::Lean => "70",
                    DefenseDepth::Full | DefenseDepth::Balanced => return None,
                };
                let ttl_secs = match depth {
                    DefenseDepth::Survival => 900,
                    DefenseDepth::Lean => 600,
                    DefenseDepth::Full | DefenseDepth::Balanced => 300,
                };
                let confidence = route_defense_confidence(total, bucket.hard_events, depth);
                Some(LocalDefenseRecommendation {
                    key: format!(
                        "local_route_pressure:{}:{}",
                        compact_recommendation_key(&site_id),
                        compact_recommendation_key(&route)
                    ),
                    site_id,
                    route: route.clone(),
                    defense_depth: depth.as_str().to_string(),
                    soft_events: bucket.soft_events,
                    hard_events: bucket.hard_events,
                    total_events: total,
                    action: "tighten_route_cc".to_string(),
                    suggested_value: suggested_value.to_string(),
                    ttl_secs,
                    confidence,
                    rationale: format!(
                        "route local defense is {} after {} soft and {} hard events in the current window",
                        depth.as_str(),
                        bucket.soft_events,
                        bucket.hard_events
                    ),
                })
            })
            .collect::<Vec<_>>();

        recommendations.sort_by(|left, right| {
            right
                .hard_events
                .cmp(&left.hard_events)
                .then_with(|| right.total_events.cmp(&left.total_events))
                .then_with(|| right.confidence.cmp(&left.confidence))
        });
        recommendations.truncate(limit);
        recommendations
    }

    pub async fn enrich_traffic_realtime_event(
        &self,
        event: traffic_map::TrafficRealtimeEventRaw,
    ) -> traffic_map::TrafficRealtimeEvent {
        self.traffic_map.enrich_realtime_event(event).await
    }

    pub fn upstream_health_snapshot(&self) -> UpstreamHealthSnapshot {
        self.upstream_health
            .read()
            .expect("upstream_health lock poisoned")
            .clone()
    }

    pub fn set_upstream_health(&self, healthy: bool, last_error: Option<String>) {
        let mut guard = self
            .upstream_health
            .write()
            .expect("upstream_health lock poisoned");
        guard.healthy = healthy;
        guard.last_error = last_error;
        guard.last_check_at = Some(unix_timestamp());
    }

    pub fn http3_runtime_snapshot(&self) -> Http3RuntimeSnapshot {
        self.http3_runtime
            .read()
            .expect("http3_runtime lock poisoned")
            .clone()
    }

    pub fn auto_tuning_snapshot(&self) -> auto_tuning::AutoTuningRuntimeSnapshot {
        self.auto_tuning_runtime
            .read()
            .expect("auto_tuning_runtime lock poisoned")
            .clone()
    }

    pub fn adaptive_protection_snapshot(
        &self,
    ) -> adaptive_protection::AdaptiveProtectionRuntimeSnapshot {
        self.adaptive_protection_runtime
            .read()
            .expect("adaptive_protection_runtime lock poisoned")
            .clone()
    }

    pub async fn ai_auto_audit_runtime_snapshot(&self) -> AiAutoAuditRuntimeSnapshot {
        let guard = self.ai_auto_audit_runtime.lock().await;
        AiAutoAuditRuntimeSnapshot {
            last_run_at: guard.last_run_at,
            last_completed_at: guard.last_completed_at,
            last_trigger_signature: guard.last_trigger_signature.clone(),
            last_observed_signature: guard.last_observed_signature.clone(),
            last_trigger_reason: guard.last_trigger_reason.clone(),
            last_report_id: guard.last_report_id,
        }
    }

    pub async fn note_ai_auto_audit_run_started(
        &self,
        signature: String,
        reason: String,
        now: i64,
    ) {
        let mut guard = self.ai_auto_audit_runtime.lock().await;
        guard.last_run_at = Some(now);
        guard.last_trigger_signature = Some(signature);
        guard.last_trigger_reason = Some(reason);
    }

    pub async fn note_ai_auto_audit_run_completed(&self, report_id: Option<i64>, now: i64) {
        let mut guard = self.ai_auto_audit_runtime.lock().await;
        guard.last_completed_at = Some(now);
        guard.last_report_id = report_id;
    }

    pub async fn note_ai_auto_audit_observed_signature(&self, signature: Option<String>) {
        let mut guard = self.ai_auto_audit_runtime.lock().await;
        guard.last_observed_signature = signature;
    }

    pub async fn run_auto_tuning_tick(&self) -> Result<()> {
        let Some(mut metrics) = self.metrics_snapshot() else {
            return Ok(());
        };
        if let Some(inspector) = self.l4_inspector().as_ref() {
            let overview = inspector.get_statistics().behavior.overview;
            metrics.l4_direct_idle_no_request_buckets = overview.direct_idle_no_request_buckets;
            metrics.l4_direct_idle_no_request_connections =
                overview.direct_idle_no_request_connections;
        }
        let config = self.config_snapshot();
        let now = unix_timestamp();

        let decision = {
            let mut controller = self.auto_tuning_controller.lock().await;
            let mut runtime = self
                .auto_tuning_runtime
                .write()
                .expect("auto_tuning_runtime lock poisoned");
            auto_tuning::run_control_step(&config, &mut runtime, &mut controller, &metrics, now)
        };

        if let Some(decision) = decision {
            self.apply_runtime_config(decision.next_config);
            if decision.requires_l4_refresh {
                self.refresh_l4_behavior_tuning_from_config();
            }
        }

        self.refresh_adaptive_protection_runtime(Some(metrics));
        self.refresh_l4_behavior_tuning_from_config();
        let effective_cc_defense = self.effective_l7_cc_defense();
        self.l7_cc_guard().update_config(&effective_cc_defense);

        Ok(())
    }

    pub fn set_http3_runtime(
        &self,
        status: impl Into<String>,
        listener_started: bool,
        listener_addr: Option<String>,
        last_error: Option<String>,
    ) {
        let mut guard = self
            .http3_runtime
            .write()
            .expect("http3_runtime lock poisoned");
        let config = self.config_snapshot();
        guard.feature_available = cfg!(feature = "http3");
        guard.configured_enabled = config.http3_config.enabled;
        guard.tls13_enabled = config.http3_config.enable_tls13;
        guard.certificate_configured = config.http3_config.certificate_path.is_some();
        guard.private_key_configured = config.http3_config.private_key_path.is_some();
        guard.listener_started = listener_started;
        guard.listener_addr = listener_addr;
        guard.status = status.into();
        guard.last_error = last_error;
    }

    pub fn refresh_http3_runtime_metadata(&self) {
        let config = self.config_snapshot();
        let mut guard = self
            .http3_runtime
            .write()
            .expect("http3_runtime lock poisoned");
        guard.feature_available = cfg!(feature = "http3");
        guard.configured_enabled = config.http3_config.enabled;
        guard.tls13_enabled = config.http3_config.enable_tls13;
        guard.certificate_configured = config.http3_config.certificate_path.is_some();
        guard.private_key_configured = config.http3_config.private_key_path.is_some();
    }

    pub async fn refresh_gateway_runtime_from_storage(&self) -> Result<()> {
        let config = self.config_snapshot();
        self.gateway_runtime
            .reload(&config, self.sqlite_store.as_deref())
            .await
    }

    pub async fn refresh_l4_runtime_from_config(&self) -> Result<()> {
        let config = self.config_snapshot();
        let l4_enabled =
            config.l4_config.ddos_protection_enabled || config.l4_config.connection_rate_limit > 0;
        let mut effective_l4_config = config.l4_config.clone();
        adaptive_protection::apply_l4_runtime_policy(
            &mut effective_l4_config,
            &self.adaptive_protection_snapshot(),
        );
        let next = l4_enabled.then(|| {
            Arc::new(L4Inspector::new(
                effective_l4_config,
                config.bloom_enabled,
                config.l4_bloom_false_positive_verification,
            ))
        });

        if let Some(inspector) = next.as_ref() {
            inspector.start(self).await?;
        }

        let mut guard = self
            .l4_inspector
            .write()
            .expect("l4_inspector lock poisoned");
        *guard = next;
        Ok(())
    }

    pub fn refresh_l4_behavior_tuning_from_config(&self) {
        let config = self.config_snapshot();
        if let Some(inspector) = self.l4_inspector() {
            let mut effective_l4_config = config.l4_config.clone();
            adaptive_protection::apply_l4_runtime_policy(
                &mut effective_l4_config,
                &self.adaptive_protection_snapshot(),
            );
            inspector.update_behavior_tuning(&effective_l4_config);
        }
    }

    pub fn refresh_l7_bloom_filter_from_config(&self) {
        let config = self.config_snapshot();
        let next = config.bloom_enabled.then(|| {
            Arc::new(crate::l7::L7BloomFilterManager::new(
                config.l7_config.clone(),
                config.bloom_enabled,
                config.l7_bloom_false_positive_verification,
            ))
        });
        let mut guard = self
            .l7_bloom_filter
            .write()
            .expect("l7_bloom_filter lock poisoned");
        *guard = next;
    }

    pub(super) fn effective_l7_cc_defense(&self) -> crate::config::l7::CcDefenseConfig {
        adaptive_protection::derive_effective_cc_config(
            &self.config_snapshot(),
            &self.adaptive_protection_snapshot(),
        )
    }

    pub(super) fn refresh_adaptive_protection_runtime(
        &self,
        metrics: Option<crate::metrics::MetricsSnapshot>,
    ) {
        let config = self.config_snapshot();
        let auto = self.auto_tuning_snapshot();
        let snapshot =
            adaptive_protection::build_runtime_snapshot(&config, &auto, metrics.as_ref());
        let mut guard = self
            .adaptive_protection_runtime
            .write()
            .expect("adaptive_protection_runtime lock poisoned");
        *guard = snapshot;
    }
}

fn protocol_stream_budget(configured: usize, defense_depth: &str) -> usize {
    let configured = configured.max(1);
    match defense_depth {
        "survival" => configured.min(8),
        "lean" => configured.min(24),
        "balanced" => configured.min(64),
        _ => configured,
    }
}

fn defense_depth_is_stricter(left: DefenseDepth, right: DefenseDepth) -> bool {
    defense_depth_rank(left) > defense_depth_rank(right)
}

fn defense_depth_rank(depth: DefenseDepth) -> u8 {
    match depth {
        DefenseDepth::Full => 0,
        DefenseDepth::Balanced => 1,
        DefenseDepth::Lean => 2,
        DefenseDepth::Survival => 3,
    }
}

impl WafContext {
    fn site_defense_depth(&self, site_id: &str) -> Option<DefenseDepth> {
        let entry = self.site_defense_buckets.get(site_id)?;
        let bucket = entry.lock().expect("site defense bucket lock poisoned");
        let now = unix_timestamp();
        if now.saturating_sub(bucket.window_start) > 75 {
            return None;
        }
        if bucket.hard_events >= 12 || bucket.soft_events.saturating_add(bucket.hard_events) >= 80 {
            return Some(DefenseDepth::Survival);
        }
        if bucket.hard_events >= 4 || bucket.soft_events.saturating_add(bucket.hard_events) >= 24 {
            return Some(DefenseDepth::Lean);
        }
        None
    }

    fn route_defense_depth(&self, site_id: &str, route: &str) -> Option<DefenseDepth> {
        if route_defense_exempt(route) {
            return None;
        }
        let entry = self
            .route_defense_buckets
            .get(&route_defense_key(site_id, route))?;
        let bucket = entry.lock().expect("route defense bucket lock poisoned");
        let now = unix_timestamp();
        if now.saturating_sub(bucket.window_start) > 75 {
            return None;
        }
        route_defense_depth_for_counts(bucket.soft_events, bucket.hard_events)
    }

    fn ensure_route_defense_capacity(&self, route_key: &str, window_start: i64) -> bool {
        if self.route_defense_buckets.contains_key(route_key)
            || self.route_defense_buckets.len() < MAX_ROUTE_DEFENSE_BUCKETS
        {
            return true;
        }

        let stale_before = window_start.saturating_sub(120);
        let stale_keys = self
            .route_defense_buckets
            .iter()
            .filter_map(|entry| {
                let bucket = entry
                    .value()
                    .lock()
                    .expect("route defense bucket lock poisoned");
                (bucket.window_start < stale_before).then(|| entry.key().clone())
            })
            .take(256)
            .collect::<Vec<_>>();
        for key in stale_keys {
            self.route_defense_buckets.remove(&key);
        }

        self.route_defense_buckets.len() < MAX_ROUTE_DEFENSE_BUCKETS
    }
}

fn select_strictest_depth(
    left: Option<DefenseDepth>,
    right: Option<DefenseDepth>,
) -> Option<DefenseDepth> {
    match (left, right) {
        (Some(left), Some(right)) => {
            if defense_depth_is_stricter(left, right) {
                Some(left)
            } else {
                Some(right)
            }
        }
        (Some(depth), None) | (None, Some(depth)) => Some(depth),
        (None, None) => None,
    }
}

fn apply_route_local_cc_tightening(request: &mut UnifiedHttpRequest, depth: DefenseDepth) {
    let (route_scale, host_scale, force_challenge) = match depth {
        DefenseDepth::Survival => (45, 70, true),
        DefenseDepth::Lean => (70, 85, false),
        DefenseDepth::Full | DefenseDepth::Balanced => return,
    };
    set_min_percent_metadata(request, "ai.cc.route_threshold_scale_percent", route_scale);
    set_min_percent_metadata(request, "ai.cc.host_threshold_scale_percent", host_scale);
    request.add_metadata(
        "runtime.route.cc_threshold_scale_percent".to_string(),
        route_scale.to_string(),
    );
    if force_challenge {
        request.add_metadata("ai.cc.force_challenge".to_string(), "true".to_string());
    }
}

fn set_min_percent_metadata(request: &mut UnifiedHttpRequest, key: &str, value: u32) {
    let current = request
        .get_metadata(key)
        .and_then(|item| item.parse::<u32>().ok())
        .unwrap_or(100);
    if value < current {
        request.add_metadata(key.to_string(), value.to_string());
    }
}

fn runtime_route_path(uri: &str) -> String {
    let path = uri.split('?').next().unwrap_or(uri).trim();
    let path = if path.is_empty() { "/" } else { path };
    let trimmed = if path != "/" {
        path.trim_end_matches('/')
    } else {
        path
    };
    if trimmed.len() <= 160 {
        trimmed.to_ascii_lowercase()
    } else {
        let digest = stable_hash_hex(trimmed);
        format!("route:{digest}")
    }
}

fn route_defense_key(site_id: &str, route: &str) -> String {
    format!("{site_id}|{route}")
}

fn split_route_defense_key(value: &str) -> Option<(String, String)> {
    let (site_id, route) = value.split_once('|')?;
    Some((site_id.to_string(), route.to_string()))
}

fn route_defense_depth_for_counts(soft_events: u64, hard_events: u64) -> Option<DefenseDepth> {
    let total = soft_events.saturating_add(hard_events);
    if hard_events >= 5 || total >= 18 {
        return Some(DefenseDepth::Survival);
    }
    if hard_events >= 2 || total >= 8 {
        return Some(DefenseDepth::Lean);
    }
    None
}

fn route_defense_confidence(total_events: u64, hard_events: u64, depth: DefenseDepth) -> u8 {
    let base = match depth {
        DefenseDepth::Survival => 82,
        DefenseDepth::Lean => 68,
        DefenseDepth::Full | DefenseDepth::Balanced => 50,
    };
    let hard_bonus = hard_events.saturating_mul(3).min(12) as u8;
    let volume_bonus = total_events.saturating_sub(8).min(10) as u8;
    (base + hard_bonus + volume_bonus).min(100)
}

fn compact_recommendation_key(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>()
        .join("_")
        .chars()
        .take(96)
        .collect()
}

fn route_defense_exempt(route: &str) -> bool {
    route == "/favicon.ico"
        || route == "/robots.txt"
        || route == "/sitemap.xml"
        || route.starts_with("/.well-known/")
        || route.starts_with("/assets/")
        || route.starts_with("/static/")
}

fn stable_hash_hex(value: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    value.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::InspectionLayer;
    use crate::protocol::{HttpVersion, UnifiedHttpRequest};

    #[tokio::test]
    async fn route_defense_tightens_only_the_hot_route() {
        let config = crate::config::Config {
            sqlite_enabled: false,
            ..crate::config::Config::default()
        };
        let context = WafContext::new(config).await.unwrap();
        let result = InspectionResult::drop(InspectionLayer::L7, "route pressure");

        for _ in 0..2 {
            let mut request = UnifiedHttpRequest::new(
                HttpVersion::Http1_1,
                "GET".to_string(),
                "/api/login?from=test".to_string(),
            );
            request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
            context.note_site_defense_signal(&request, &result);
        }

        let mut hot = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/api/login".to_string(),
        );
        hot.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        hot.add_metadata("runtime.defense.depth".to_string(), "balanced".to_string());
        context.annotate_site_runtime_budget(&mut hot);

        assert_eq!(
            hot.get_metadata("runtime.route.defense_depth")
                .map(String::as_str),
            Some("lean")
        );
        assert_eq!(
            hot.get_metadata("ai.cc.route_threshold_scale_percent")
                .map(String::as_str),
            Some("70")
        );
        assert_eq!(
            hot.get_metadata("ai.cc.host_threshold_scale_percent")
                .map(String::as_str),
            Some("85")
        );

        let mut cold = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/api/profile".to_string(),
        );
        cold.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        cold.add_metadata("runtime.defense.depth".to_string(), "balanced".to_string());
        context.annotate_site_runtime_budget(&mut cold);

        assert!(cold.get_metadata("runtime.route.defense_depth").is_none());
        assert!(cold
            .get_metadata("ai.cc.route_threshold_scale_percent")
            .is_none());
    }

    #[tokio::test]
    async fn local_defense_recommendations_preview_hot_routes() {
        let config = crate::config::Config {
            sqlite_enabled: false,
            ..crate::config::Config::default()
        };
        let context = WafContext::new(config).await.unwrap();
        let result = InspectionResult::drop(InspectionLayer::L7, "route pressure");

        for _ in 0..5 {
            let mut request = UnifiedHttpRequest::new(
                HttpVersion::Http1_1,
                "POST".to_string(),
                "/api/login".to_string(),
            );
            request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
            context.note_site_defense_signal(&request, &result);
        }

        let recommendations = context.local_defense_recommendations(10);

        assert_eq!(recommendations.len(), 1);
        let recommendation = &recommendations[0];
        assert_eq!(recommendation.site_id, "site-a");
        assert_eq!(recommendation.route, "/api/login");
        assert_eq!(recommendation.defense_depth, "survival");
        assert_eq!(recommendation.action, "tighten_route_cc");
        assert_eq!(recommendation.suggested_value, "45");
        assert_eq!(recommendation.ttl_secs, 900);
        assert!(recommendation.confidence >= 90);
    }

    #[tokio::test]
    async fn ai_defense_trigger_waits_for_enough_route_signals() {
        let config = crate::config::Config {
            sqlite_enabled: false,
            ..crate::config::Config::default()
        };
        let context = WafContext::new(config).await.unwrap();
        let result = InspectionResult::drop(InspectionLayer::L7, "route pressure");

        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "POST".to_string(),
            "/api/login".to_string(),
        );
        request.add_metadata("gateway.site_id".to_string(), "site-a".to_string());
        context.note_site_defense_signal(&request, &result);

        assert!(context
            .consume_ai_auto_defense_trigger(unix_timestamp())
            .is_none());

        context.note_site_defense_signal(&request, &result);

        assert!(context
            .consume_ai_auto_defense_trigger(unix_timestamp())
            .as_deref()
            .is_some_and(|reason| reason.starts_with("route_pressure:site-a:/api/login")));
    }
}
