use super::{
    adaptive_protection, auto_tuning, resource_budget, traffic_map, unix_timestamp,
    AiAutoAuditRuntimeSnapshot, DefenseDepth, Http3RuntimeSnapshot, LocalDefenseRecommendation,
    RuntimePressureSnapshot, SiteDefenseBucket, UpstreamHealthSnapshot, WafContext,
};
use crate::core::InspectionResult;
use crate::l4::L4Inspector;
use crate::locks::{mutex_lock, read_lock, write_lock};
use crate::protocol::UnifiedHttpRequest;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::broadcast;

mod helpers;

#[cfg(test)]
mod tests;

use helpers::*;

const MAX_ROUTE_DEFENSE_BUCKETS: usize = 8_192;

impl WafContext {
    pub fn runtime_pressure_snapshot(&self) -> RuntimePressureSnapshot {
        let auto = self.auto_tuning_snapshot();
        let cpu_pressure = self.cpu_pressure_snapshot();
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
        score = score.saturating_add(cpu_pressure.score);

        let level = match score {
            0..=1 => "normal",
            2..=3 => "elevated",
            4..=5 => "high",
            _ => "attack",
        };

        let mut pressure = RuntimePressureSnapshot {
            level,
            capacity_class: "",
            defense_depth: "",
            server_mode: "",
            server_mode_scale_percent: 100,
            server_mode_reason: "",
            storage_queue_usage_percent,
            cpu_usage_percent: cpu_pressure.usage_percent,
            cpu_pressure_score: cpu_pressure.score,
            cpu_sample_available: cpu_pressure.sample_available,
            drop_delay: matches!(level, "high" | "attack"),
            trim_event_persistence: storage_queue_usage_percent >= 75
                || matches!(level, "high" | "attack"),
            l7_bucket_limit: 0,
            l7_page_window_limit: 0,
            behavior_bucket_limit: 0,
            behavior_sample_stride: 1,
            prefer_drop: false,
        };
        self.resource_sentinel.apply_runtime_pressure(&mut pressure);
        let budget = resource_budget::current_runtime_resource_budget(
            pressure.level,
            pressure.storage_queue_usage_percent,
        );
        pressure.capacity_class = budget.capacity_class.as_str();
        pressure.defense_depth = budget.defense_depth.as_str();
        pressure.server_mode = budget.server_mode.as_str();
        pressure.server_mode_scale_percent = budget.server_mode_scale_percent;
        pressure.server_mode_reason = budget.server_mode_reason;
        pressure.drop_delay = pressure.drop_delay || budget.prefer_drop;
        pressure.trim_event_persistence =
            pressure.trim_event_persistence || budget.aggregate_events;
        pressure.l7_bucket_limit = budget.l7_bucket_limit;
        pressure.l7_page_window_limit = budget.l7_page_window_limit;
        pressure.behavior_bucket_limit = budget.behavior_bucket_limit;
        pressure.behavior_sample_stride = budget.behavior_sample_stride;
        pressure.prefer_drop = budget.prefer_drop;
        pressure
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
            "runtime.pressure.cpu_percent".to_string(),
            format!("{:.2}", pressure.cpu_usage_percent),
        );
        request.add_metadata(
            "runtime.pressure.cpu_score".to_string(),
            pressure.cpu_pressure_score.to_string(),
        );
        request.add_metadata(
            "runtime.pressure.cpu_sample_available".to_string(),
            pressure.cpu_sample_available.to_string(),
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
            "runtime.server.mode".to_string(),
            pressure.server_mode.to_string(),
        );
        request.add_metadata(
            "runtime.server.mode_scale_percent".to_string(),
            pressure.server_mode_scale_percent.to_string(),
        );
        request.add_metadata(
            "runtime.server.mode_reason".to_string(),
            pressure.server_mode_reason.to_string(),
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

    fn cpu_pressure_snapshot(&self) -> super::system_pressure::CpuPressureSnapshot {
        self.cpu_pressure_monitor
            .lock()
            .map(|mut monitor| monitor.snapshot())
            .unwrap_or_default()
    }

    pub fn annotate_site_runtime_budget(&self, request: &mut UnifiedHttpRequest) {
        let Some(site_id) = request.get_metadata("gateway.site_id").cloned() else {
            return;
        };
        let site_priority = site_priority_from_metadata(request);
        let configured_policy = site_overload_policy_from_metadata(request);
        let site_depth = self.site_defense_depth(&site_id);
        let route = runtime_route_path(&request.uri);
        let route_depth = self.route_defense_depth(&site_id, &route);
        let current_depth = request
            .get_metadata("runtime.defense.depth")
            .map(|value| DefenseDepth::from_str(value))
            .unwrap_or(DefenseDepth::Balanced);
        let local_strictest_depth = select_strictest_depth(site_depth, route_depth);
        let effective_depth = local_strictest_depth
            .filter(|depth| defense_depth_is_stricter(*depth, current_depth))
            .unwrap_or(current_depth);
        let pseudo_pressure = match effective_depth {
            DefenseDepth::Survival => "attack",
            DefenseDepth::Lean => "high",
            _ => "elevated",
        };
        let current_queue = request
            .get_metadata("runtime.pressure.storage_queue_percent")
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0);
        let server_mode_scale_percent = request
            .get_metadata("runtime.server.mode_scale_percent")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or(100)
            .clamp(50, 140);
        let budget =
            resource_budget::current_runtime_resource_budget(pseudo_pressure, current_queue);
        if defense_depth_is_stricter(effective_depth, current_depth) {
            request.add_metadata(
                "runtime.defense.depth".to_string(),
                effective_depth.as_str().to_string(),
            );
            request.add_metadata(
                "runtime.site.defense_depth".to_string(),
                effective_depth.as_str().to_string(),
            );
        }
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
            if local_strictest_depth.is_some() {
                "site_local_attack_pressure"
            } else {
                "runtime_adaptive_budget"
            }
            .to_string(),
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

        let reserved_rps = metadata_u32(request, "gateway.site_reserved_rps");
        let reserved_concurrency = metadata_u32(request, "gateway.site_reserved_concurrency");
        let base_rps_limit = if reserved_rps > 0 {
            reserved_rps
        } else {
            capacity_rps_floor(budget.capacity_class.as_str(), site_priority)
        };
        let base_rps_limit = base_rps_limit
            .saturating_mul(server_mode_scale_percent)
            .saturating_div(100)
            .max(1);
        let effective_rps_limit = base_rps_limit
            .saturating_mul(depth_rps_scale_percent(effective_depth))
            .saturating_div(100)
            .max(1);
        let current_rps = self.observe_site_request_rate(&site_id, unix_timestamp());
        let resolved_policy =
            resolve_site_overload_policy(configured_policy, site_priority, effective_depth);
        let proactive_shed = matches!(
            resolved_policy,
            crate::core::gateway::GatewaySiteOverloadPolicy::Sacrificial
        ) && matches!(effective_depth, DefenseDepth::Survival);
        let over_rps_budget = current_rps > effective_rps_limit as u64;
        let site_action = if proactive_shed {
            "shed"
        } else if over_rps_budget {
            match resolved_policy {
                crate::core::gateway::GatewaySiteOverloadPolicy::ChallengeFirst => "challenge",
                crate::core::gateway::GatewaySiteOverloadPolicy::BlockFirst => "block",
                crate::core::gateway::GatewaySiteOverloadPolicy::FailClose => "fail_close",
                crate::core::gateway::GatewaySiteOverloadPolicy::Sacrificial => "shed",
                crate::core::gateway::GatewaySiteOverloadPolicy::Inherit => "allow",
            }
        } else {
            "allow"
        };
        request.add_metadata(
            "runtime.site.priority".to_string(),
            site_priority.as_str().to_string(),
        );
        request.add_metadata(
            "runtime.site.overload_policy".to_string(),
            resolved_policy.as_str().to_string(),
        );
        request.add_metadata(
            "runtime.site.reserved_concurrency".to_string(),
            reserved_concurrency.to_string(),
        );
        request.add_metadata(
            "runtime.site.reserved_rps".to_string(),
            reserved_rps.to_string(),
        );
        request.add_metadata(
            "runtime.site.effective_rps_limit".to_string(),
            effective_rps_limit.to_string(),
        );
        request.add_metadata(
            "runtime.site.current_rps".to_string(),
            current_rps.to_string(),
        );
        request.add_metadata("runtime.site.action".to_string(), site_action.to_string());
        request.add_metadata(
            "runtime.site.proxy_mode".to_string(),
            if matches!(site_action, "fail_close" | "shed") {
                "shed"
            } else if site_action == "challenge" {
                "degraded"
            } else {
                "normal"
            }
            .to_string(),
        );
        if over_rps_budget {
            request.add_metadata(
                "runtime.site.over_rps_budget".to_string(),
                "true".to_string(),
            );
            request.add_metadata(
                "runtime.site.defense_reason".to_string(),
                "site_reserved_rps_budget_exceeded".to_string(),
            );
        }
        if proactive_shed {
            request.add_metadata(
                "runtime.site.defense_reason".to_string(),
                "site_sacrificed_for_server_survival".to_string(),
            );
            request.add_metadata("runtime.prefer_drop".to_string(), "true".to_string());
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
        let mut bucket = mutex_lock(entry.value(), "site defense bucket");
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
        let mut bucket = mutex_lock(entry.value(), "route defense bucket");
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
        protocol_stream_budget(
            configured,
            pressure.defense_depth,
            pressure.server_mode_scale_percent,
        )
    }

    pub fn apply_http3_runtime_budget(&self, config: &mut crate::config::Http3Config) {
        let pressure = self.runtime_pressure_snapshot();
        config.max_concurrent_streams = protocol_stream_budget(
            config.max_concurrent_streams,
            pressure.defense_depth,
            pressure.server_mode_scale_percent,
        );
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
                let bucket = mutex_lock(entry.value(), "route defense bucket");
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
        read_lock(&self.upstream_health, "upstream_health").clone()
    }

    pub fn set_upstream_health(&self, healthy: bool, last_error: Option<String>) {
        let mut guard = write_lock(&self.upstream_health, "upstream_health");
        guard.healthy = healthy;
        guard.last_error = last_error;
        guard.last_check_at = Some(unix_timestamp());
    }

    pub fn http3_runtime_snapshot(&self) -> Http3RuntimeSnapshot {
        read_lock(&self.http3_runtime, "http3_runtime").clone()
    }

    pub fn auto_tuning_snapshot(&self) -> auto_tuning::AutoTuningRuntimeSnapshot {
        read_lock(&self.auto_tuning_runtime, "auto_tuning_runtime").clone()
    }

    pub fn adaptive_protection_snapshot(
        &self,
    ) -> adaptive_protection::AdaptiveProtectionRuntimeSnapshot {
        read_lock(
            &self.adaptive_protection_runtime,
            "adaptive_protection_runtime",
        )
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
            let mut runtime = write_lock(&self.auto_tuning_runtime, "auto_tuning_runtime");
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
            .map(|guard| guard)
            .unwrap_or_else(|poisoned| {
                log::warn!("http3_runtime lock poisoned; recovering with current value");
                poisoned.into_inner()
            });
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
            .map(|guard| guard)
            .unwrap_or_else(|poisoned| {
                log::warn!("http3_runtime lock poisoned; recovering with current value");
                poisoned.into_inner()
            });
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
            .map(|guard| guard)
            .unwrap_or_else(|poisoned| {
                log::warn!("l4_inspector lock poisoned; recovering with current value");
                poisoned.into_inner()
            });
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
            .map(|guard| guard)
            .unwrap_or_else(|poisoned| {
                log::warn!("l7_bloom_filter lock poisoned; recovering with current value");
                poisoned.into_inner()
            });
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
            .map(|guard| guard)
            .unwrap_or_else(|poisoned| {
                log::warn!(
                    "adaptive_protection_runtime lock poisoned; recovering with current value"
                );
                poisoned.into_inner()
            });
        *guard = snapshot;
    }
}
