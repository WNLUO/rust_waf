use super::{
    adaptive_protection, auto_tuning, resource_budget, traffic_map, unix_timestamp,
    AiAutoAuditRuntimeSnapshot, Http3RuntimeSnapshot, RuntimePressureSnapshot,
    UpstreamHealthSnapshot, WafContext,
};
use crate::l4::L4Inspector;
use crate::protocol::UnifiedHttpRequest;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::broadcast;

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
