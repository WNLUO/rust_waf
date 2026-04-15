pub(crate) mod adaptive_protection;
mod auto_tuning;
pub mod engine;
mod engine_maintenance;
mod engine_tls;
pub mod gateway;
pub mod packet;
mod system_profile;
pub mod traffic_map;

use crate::config::Config;
use crate::core::gateway::GatewayRuntime;
use crate::l4::L4Inspector;
use crate::l7::{HttpTrafficProcessor, L7BehaviorGuard, L7CcGuard, SlowAttackGuard};
use crate::metrics::MetricsCollector;
use crate::protocol::UnifiedHttpRequest;
use crate::rules::RuleEngine;
use crate::storage::{AiTempPolicyEntry, AiTempPolicyHitRecord, SqliteStore};
use anyhow::Result;
use log::{info, warn};
use std::net::IpAddr;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, Mutex};

pub use adaptive_protection::AdaptiveProtectionRuntimeSnapshot;
pub use auto_tuning::{
    AutoTuningControllerState, AutoTuningRecommendationSnapshot, AutoTuningRuntimeSnapshot,
};
pub use engine::WafEngine;
pub use packet::{
    CustomHttpResponse, InspectionAction, InspectionLayer, InspectionResult, PacketInfo, Protocol,
    RandomStatusConfig, TarpitConfig,
};

#[derive(Debug, Clone)]
pub struct UpstreamHealthSnapshot {
    pub healthy: bool,
    pub last_check_at: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Http3RuntimeSnapshot {
    pub feature_available: bool,
    pub configured_enabled: bool,
    pub tls13_enabled: bool,
    pub certificate_configured: bool,
    pub private_key_configured: bool,
    pub listener_started: bool,
    pub listener_addr: Option<String>,
    pub status: String,
    pub last_error: Option<String>,
}

pub struct WafContext {
    pub config: Config,
    runtime_config: Arc<RwLock<Config>>,
    l4_inspector: RwLock<Option<Arc<L4Inspector>>>,
    l7_cc_guard: RwLock<Arc<L7CcGuard>>,
    l7_behavior_guard: RwLock<Arc<L7BehaviorGuard>>,
    slow_attack_guard: RwLock<Arc<SlowAttackGuard>>,
    pub http_processor: HttpTrafficProcessor,
    pub rule_engine: RwLock<Option<RuleEngine>>,
    pub metrics: Option<MetricsCollector>,
    pub sqlite_store: Option<Arc<SqliteStore>>,
    pub gateway_runtime: GatewayRuntime,
    pub traffic_map: traffic_map::TrafficMapCollector,
    upstream_health: RwLock<UpstreamHealthSnapshot>,
    http3_runtime: RwLock<Http3RuntimeSnapshot>,
    auto_tuning_runtime: RwLock<AutoTuningRuntimeSnapshot>,
    auto_tuning_controller: Mutex<AutoTuningControllerState>,
    adaptive_protection_runtime: RwLock<AdaptiveProtectionRuntimeSnapshot>,
    ai_temp_policies: RwLock<Vec<AiTempPolicyEntry>>,
    ai_auto_audit_runtime: Mutex<AiAutoAuditRuntimeState>,
    rule_count: AtomicU64,
    rule_version: AtomicI64,
}

#[derive(Debug, Clone)]
pub struct RuntimePressureSnapshot {
    pub level: &'static str,
    pub storage_queue_usage_percent: u64,
    pub drop_delay: bool,
    pub trim_event_persistence: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AiAutoAuditRuntimeSnapshot {
    pub last_run_at: Option<i64>,
    pub last_completed_at: Option<i64>,
    pub last_trigger_signature: Option<String>,
    pub last_observed_signature: Option<String>,
    pub last_trigger_reason: Option<String>,
    pub last_report_id: Option<i64>,
}

#[derive(Debug, Default)]
struct AiAutoAuditRuntimeState {
    last_run_at: Option<i64>,
    last_completed_at: Option<i64>,
    last_trigger_signature: Option<String>,
    last_observed_signature: Option<String>,
    last_trigger_reason: Option<String>,
    last_report_id: Option<i64>,
}

impl WafContext {
    pub async fn new(config: Config) -> Result<Self> {
        let l4_enabled =
            config.l4_config.ddos_protection_enabled || config.l4_config.connection_rate_limit > 0;
        let bloom_enabled = config.bloom_enabled;
        let l4_bloom_verification = config.l4_bloom_false_positive_verification;
        let metrics = if config.metrics_enabled {
            Some(MetricsCollector::new())
        } else {
            None
        };
        let sqlite_store = if config.sqlite_enabled {
            Some(Arc::new(
                SqliteStore::new_with_queue_capacity(
                    config.sqlite_path.clone(),
                    config.sqlite_auto_migrate,
                    config.sqlite_queue_capacity,
                )
                .await?,
            ))
        } else {
            None
        };
        let (rule_engine, rule_count, rule_version) =
            load_rule_engine_state(&config, sqlite_store.as_deref()).await?;
        let gateway_runtime = GatewayRuntime::load(&config, sqlite_store.as_deref()).await?;
        let http_processor = HttpTrafficProcessor::new(&config.l7_config);
        let auto_tuning_runtime = auto_tuning::build_runtime_snapshot(&config);
        let adaptive_protection_runtime =
            adaptive_protection::build_runtime_snapshot(&config, &auto_tuning_runtime, None);
        let effective_cc_defense =
            adaptive_protection::derive_effective_cc_config(&config, &adaptive_protection_runtime);
        let mut effective_l4_config = config.l4_config.clone();
        adaptive_protection::apply_l4_runtime_policy(
            &mut effective_l4_config,
            &adaptive_protection_runtime,
        );

        Ok(Self {
            runtime_config: Arc::new(RwLock::new(config.clone())),
            l4_inspector: RwLock::new(l4_enabled.then(|| {
                Arc::new(L4Inspector::new(
                    effective_l4_config,
                    bloom_enabled,
                    l4_bloom_verification,
                ))
            })),
            l7_cc_guard: RwLock::new(Arc::new(L7CcGuard::new(&effective_cc_defense))),
            l7_behavior_guard: RwLock::new(Arc::new(L7BehaviorGuard::new())),
            slow_attack_guard: RwLock::new(Arc::new(SlowAttackGuard::new(
                &config.l7_config.slow_attack_defense,
            ))),
            http_processor,
            rule_engine: RwLock::new(rule_engine),
            metrics,
            sqlite_store,
            gateway_runtime,
            traffic_map: traffic_map::TrafficMapCollector::new(),
            upstream_health: RwLock::new(UpstreamHealthSnapshot {
                healthy: true,
                last_check_at: None,
                last_error: None,
            }),
            http3_runtime: RwLock::new(Http3RuntimeSnapshot {
                feature_available: cfg!(feature = "http3"),
                configured_enabled: config.http3_config.enabled,
                tls13_enabled: config.http3_config.enable_tls13,
                certificate_configured: config.http3_config.certificate_path.is_some(),
                private_key_configured: config.http3_config.private_key_path.is_some(),
                listener_started: false,
                listener_addr: None,
                status: if config.http3_config.enabled {
                    "pending".to_string()
                } else {
                    "disabled".to_string()
                },
                last_error: None,
            }),
            auto_tuning_runtime: RwLock::new(auto_tuning_runtime),
            auto_tuning_controller: Mutex::new(AutoTuningControllerState::default()),
            adaptive_protection_runtime: RwLock::new(adaptive_protection_runtime),
            ai_temp_policies: RwLock::new(Vec::new()),
            ai_auto_audit_runtime: Mutex::new(AiAutoAuditRuntimeState::default()),
            rule_count: AtomicU64::new(rule_count),
            rule_version: AtomicI64::new(rule_version),
            config,
        })
    }

    pub fn config_snapshot(&self) -> Config {
        self.runtime_config
            .read()
            .expect("runtime_config lock poisoned")
            .clone()
    }

    pub fn apply_runtime_config(&self, config: Config) {
        {
            let mut guard = self
                .runtime_config
                .write()
                .expect("runtime_config lock poisoned");
            *guard = config;
        }
        {
            let mut guard = self
                .auto_tuning_runtime
                .write()
                .expect("auto_tuning_runtime lock poisoned");
            auto_tuning::refresh_runtime_snapshot(
                &mut guard,
                &self
                    .runtime_config
                    .read()
                    .expect("runtime_config lock poisoned"),
            );
        }
        self.refresh_adaptive_protection_runtime(None);
        let effective_cc_defense = self.effective_l7_cc_defense();
        self.l7_cc_guard().update_config(&effective_cc_defense);
        self.slow_attack_guard()
            .update_config(&self.config_snapshot().l7_config.slow_attack_defense);
        self.refresh_l4_behavior_tuning_from_config();
        self.refresh_http3_runtime_metadata();
    }

    pub fn l4_inspector(&self) -> Option<Arc<L4Inspector>> {
        self.l4_inspector
            .read()
            .expect("l4_inspector lock poisoned")
            .as_ref()
            .cloned()
    }

    pub fn l4_runtime_enabled(&self) -> bool {
        self.l4_inspector().as_ref().map(|_| true).unwrap_or(false)
    }

    pub fn l7_cc_guard(&self) -> Arc<L7CcGuard> {
        self.l7_cc_guard
            .read()
            .expect("l7_cc_guard lock poisoned")
            .clone()
    }

    pub fn slow_attack_guard(&self) -> Arc<SlowAttackGuard> {
        self.slow_attack_guard
            .read()
            .expect("slow_attack_guard lock poisoned")
            .clone()
    }

    pub fn l7_behavior_guard(&self) -> Arc<L7BehaviorGuard> {
        self.l7_behavior_guard
            .read()
            .expect("l7_behavior_guard lock poisoned")
            .clone()
    }

    pub fn metrics_snapshot(&self) -> Option<crate::metrics::MetricsSnapshot> {
        self.metrics.as_ref().map(MetricsCollector::get_stats)
    }

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

        RuntimePressureSnapshot {
            level,
            storage_queue_usage_percent,
            drop_delay: matches!(level, "high" | "attack"),
            trim_event_persistence: storage_queue_usage_percent >= 75
                || matches!(level, "high" | "attack"),
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
        if pressure.drop_delay {
            request.add_metadata(
                "runtime.pressure.drop_delay".to_string(),
                "true".to_string(),
            );
        }
        if pressure.trim_event_persistence {
            request.add_metadata(
                "runtime.pressure.trim_event_persistence".to_string(),
                "true".to_string(),
            );
        }
    }

    pub fn active_ai_temp_policies(&self) -> Vec<AiTempPolicyEntry> {
        self.ai_temp_policies
            .read()
            .expect("ai_temp_policies lock poisoned")
            .clone()
    }

    pub async fn refresh_ai_temp_policies(&self) -> Result<()> {
        let Some(store) = self.sqlite_store.as_ref() else {
            return Ok(());
        };
        let now = unix_timestamp();
        let _ = store.expire_ai_temp_policies(now).await?;
        let items = store.list_active_ai_temp_policies(now).await?;
        let mut guard = self
            .ai_temp_policies
            .write()
            .expect("ai_temp_policies lock poisoned");
        *guard = items;
        Ok(())
    }

    pub fn apply_ai_temp_policies_to_request(
        &self,
        request: &mut UnifiedHttpRequest,
    ) -> Option<InspectionResult> {
        let policies = self.active_ai_temp_policies();
        if policies.is_empty() {
            return None;
        }

        let host = request
            .get_header("host")
            .map(|value| {
                value
                    .split(':')
                    .next()
                    .unwrap_or(value)
                    .trim()
                    .to_ascii_lowercase()
            })
            .unwrap_or_default();
        let route = request
            .uri
            .split('?')
            .next()
            .unwrap_or(&request.uri)
            .to_string();
        let client_ip = request
            .client_ip
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or_default()
            .to_string();
        let identity = ai_request_identity(request);

        let mut matched_hits = Vec::new();
        let mut route_scale_percent = 100u32;
        let mut host_scale_percent = 100u32;
        let mut extra_delay_ms = 0u64;
        let mut behavior_score_boost = 0u32;
        let mut force_watch = false;
        let mut force_challenge = false;
        let mut block_reason = None::<String>;

        for policy in policies {
            let matched =
                match_ai_temp_policy(&policy, &host, &route, &client_ip, identity.as_deref());
            let Some(matched) = matched else {
                continue;
            };
            matched_hits.push(AiTempPolicyHitRecord {
                id: policy.id,
                action: policy.action.clone(),
                scope_type: policy.scope_type.clone(),
                scope_value: policy.scope_value.clone(),
                matched_value: matched.matched_value,
                match_mode: matched.match_mode,
            });
            match policy.action.as_str() {
                "add_temp_block" => {
                    block_reason = Some(format!(
                        "AI temp policy blocked request: {} ({})",
                        policy.title, policy.rationale
                    ));
                    request.add_metadata(
                        "ai.temp_block_duration_secs".to_string(),
                        self.config_snapshot()
                            .integrations
                            .ai_audit
                            .temp_block_ttl_secs
                            .to_string(),
                    );
                }
                "increase_delay" => {
                    extra_delay_ms = extra_delay_ms
                        .max(parse_suggested_delay_ms(&policy.suggested_value).unwrap_or(250));
                }
                "increase_challenge" => force_challenge = true,
                "tighten_route_cc" => {
                    route_scale_percent = route_scale_percent
                        .min(parse_scale_percent(&policy.suggested_value).unwrap_or(80));
                }
                "tighten_host_cc" => {
                    host_scale_percent = host_scale_percent
                        .min(parse_scale_percent(&policy.suggested_value).unwrap_or(85));
                }
                "raise_identity_risk" => {
                    behavior_score_boost = behavior_score_boost.max(35);
                }
                "add_behavior_watch" => {
                    behavior_score_boost = behavior_score_boost.max(20);
                    force_watch = true;
                }
                _ => {}
            }
        }

        self.record_ai_temp_policy_hits(matched_hits);

        if let Some(reason) = block_reason {
            request.add_metadata("ai.policy.action".to_string(), "add_temp_block".to_string());
            return Some(InspectionResult::respond_and_persist_ip(
                InspectionLayer::L7,
                reason.clone(),
                CustomHttpResponse {
                    status_code: 429,
                    headers: vec![
                        (
                            "content-type".to_string(),
                            "application/json; charset=utf-8".to_string(),
                        ),
                        ("cache-control".to_string(), "no-store".to_string()),
                        ("x-rust-waf-ai-policy".to_string(), "temp_block".to_string()),
                    ],
                    body: serde_json::json!({
                        "success": false,
                        "action": "temp_block",
                        "message": "访问已被专项防护策略临时阻断",
                        "reason": reason,
                    })
                    .to_string()
                    .into_bytes(),
                    tarpit: None,
                    random_status: None,
                },
            ));
        }

        if route_scale_percent < 100 {
            request.add_metadata(
                "ai.cc.route_threshold_scale_percent".to_string(),
                route_scale_percent.to_string(),
            );
        }
        if host_scale_percent < 100 {
            request.add_metadata(
                "ai.cc.host_threshold_scale_percent".to_string(),
                host_scale_percent.to_string(),
            );
        }
        if extra_delay_ms > 0 {
            request.add_metadata(
                "ai.cc.extra_delay_ms".to_string(),
                extra_delay_ms.to_string(),
            );
        }
        if force_challenge {
            request.add_metadata("ai.cc.force_challenge".to_string(), "true".to_string());
        }
        if behavior_score_boost > 0 {
            request.add_metadata(
                "ai.behavior.score_boost".to_string(),
                behavior_score_boost.to_string(),
            );
        }
        if force_watch {
            request.add_metadata("ai.behavior.force_watch".to_string(), "true".to_string());
        }

        None
    }

    fn record_ai_temp_policy_hits(&self, hits: Vec<AiTempPolicyHitRecord>) {
        if hits.is_empty() {
            return;
        }
        let Some(store) = self.sqlite_store.as_ref().cloned() else {
            return;
        };
        tokio::spawn(async move {
            let now = unix_timestamp();
            for hit in hits {
                let _ = store.record_ai_temp_policy_hit(&hit, now).await;
            }
        });
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

    pub fn auto_tuning_snapshot(&self) -> AutoTuningRuntimeSnapshot {
        self.auto_tuning_runtime
            .read()
            .expect("auto_tuning_runtime lock poisoned")
            .clone()
    }

    pub fn adaptive_protection_snapshot(&self) -> AdaptiveProtectionRuntimeSnapshot {
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

    fn effective_l7_cc_defense(&self) -> crate::config::l7::CcDefenseConfig {
        adaptive_protection::derive_effective_cc_config(
            &self.config_snapshot(),
            &self.adaptive_protection_snapshot(),
        )
    }

    fn refresh_adaptive_protection_runtime(
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

    pub async fn refresh_rules_from_storage(&self) -> Result<bool> {
        if !self.config_snapshot().sqlite_rules_enabled {
            return Ok(false);
        }

        let Some(store) = self.sqlite_store.as_ref() else {
            return Ok(false);
        };

        let (latest_count, latest_version) = store.rules_state().await?;
        let current_count = self.rule_count.load(Ordering::Relaxed);
        let current_version = self.rule_version.load(Ordering::Relaxed);

        if latest_count == current_count && latest_version == current_version {
            return Ok(false);
        }

        let rules = store.load_rules().await?;
        let new_engine = compile_rule_engine(rules)?;

        {
            let mut guard = self.rule_engine.write().expect("rule_engine lock poisoned");
            *guard = new_engine;
        }

        self.rule_count.store(latest_count, Ordering::Relaxed);
        self.rule_version.store(latest_version, Ordering::Relaxed);
        info!(
            "Reloaded {} rule(s) from SQLite (version={})",
            latest_count, latest_version
        );

        Ok(true)
    }

    pub async fn shutdown_storage(&self) -> Result<()> {
        if let Some(store) = self.sqlite_store.as_ref() {
            store.shutdown().await?;
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub fn active_rule_count(&self) -> u64 {
        self.rule_count.load(Ordering::Relaxed)
    }
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn ai_request_identity(request: &UnifiedHttpRequest) -> Option<String> {
    fn cookie_value(request: &UnifiedHttpRequest, name: &str) -> Option<String> {
        let raw = request.get_header("cookie")?;
        raw.split(';').find_map(|segment| {
            let mut parts = segment.trim().splitn(2, '=');
            let key = parts.next()?.trim();
            let value = parts.next()?.trim();
            (key.eq_ignore_ascii_case(name) && !value.is_empty()).then(|| value.to_string())
        })
    }

    if let Some(value) = cookie_value(request, "rwaf_fp") {
        return Some(format!("fp:{value}"));
    }
    if let Some(value) = request.get_header("x-browser-fingerprint-id") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(format!("fp:{trimmed}"));
        }
    }
    let ip = request.client_ip.as_deref()?.trim();
    if ip.is_empty() {
        return None;
    }
    let ua = request
        .get_header("user-agent")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("-");
    Some(format!("ipua:{ip}|{ua}"))
}

fn parse_scale_percent(value: &str) -> Option<u32> {
    let digits = value
        .chars()
        .filter(|char| char.is_ascii_digit())
        .collect::<String>();
    let parsed = digits.parse::<u32>().ok()?;
    (parsed > 0).then_some(parsed.min(100))
}

fn parse_suggested_delay_ms(value: &str) -> Option<u64> {
    let digits = value
        .chars()
        .filter(|char| char.is_ascii_digit())
        .collect::<String>();
    digits.parse::<u64>().ok()
}

#[derive(Debug, Clone)]
struct AiTempPolicyMatch {
    match_mode: String,
    matched_value: String,
}

fn match_ai_temp_policy(
    policy: &AiTempPolicyEntry,
    host: &str,
    route: &str,
    client_ip: &str,
    identity: Option<&str>,
) -> Option<AiTempPolicyMatch> {
    let operator = policy.operator.trim().to_ascii_lowercase();
    match policy.scope_type.as_str() {
        "host" => match_string_scope(host, &policy.scope_value, &operator, true),
        "route" => match_string_scope(route, &policy.scope_value, &operator, false),
        "source_ip" => match_ip_scope(client_ip, &policy.scope_value, &operator),
        "identity" => match_string_scope(
            identity.unwrap_or_default(),
            &policy.scope_value,
            &operator,
            false,
        ),
        _ => None,
    }
}

fn match_string_scope(
    actual: &str,
    expected: &str,
    operator: &str,
    case_insensitive: bool,
) -> Option<AiTempPolicyMatch> {
    let actual = actual.trim();
    let expected = expected.trim();
    if actual.is_empty() || expected.is_empty() {
        return None;
    }

    let actual_cmp = if case_insensitive {
        actual.to_ascii_lowercase()
    } else {
        actual.to_string()
    };
    let expected_cmp = if case_insensitive {
        expected.to_ascii_lowercase()
    } else {
        expected.to_string()
    };

    if expected_cmp == actual_cmp {
        return Some(AiTempPolicyMatch {
            match_mode: "exact".to_string(),
            matched_value: actual.to_string(),
        });
    }

    let prefix_enabled =
        operator == "prefix" || operator == "starts_with" || expected_cmp.ends_with('*');
    if prefix_enabled {
        let prefix = expected_cmp.trim_end_matches('*').trim_end();
        if !prefix.is_empty() && actual_cmp.starts_with(prefix) {
            return Some(AiTempPolicyMatch {
                match_mode: "prefix".to_string(),
                matched_value: actual.to_string(),
            });
        }
    }

    let suffix_enabled = operator == "suffix"
        || operator == "ends_with"
        || expected_cmp.starts_with("*.")
        || expected_cmp.starts_with('.');
    if suffix_enabled {
        let suffix = expected_cmp.trim_start_matches('*').trim_start();
        if !suffix.is_empty() && actual_cmp.ends_with(suffix) {
            return Some(AiTempPolicyMatch {
                match_mode: "suffix".to_string(),
                matched_value: actual.to_string(),
            });
        }
    }

    let contains_enabled = operator == "contains";
    if contains_enabled && actual_cmp.contains(&expected_cmp) {
        return Some(AiTempPolicyMatch {
            match_mode: "contains".to_string(),
            matched_value: actual.to_string(),
        });
    }

    None
}

fn match_ip_scope(actual: &str, expected: &str, operator: &str) -> Option<AiTempPolicyMatch> {
    let actual = actual.trim();
    let expected = expected.trim();
    if actual.is_empty() || expected.is_empty() {
        return None;
    }
    if actual == expected {
        return Some(AiTempPolicyMatch {
            match_mode: "exact".to_string(),
            matched_value: actual.to_string(),
        });
    }
    if operator == "cidr" || expected.contains('/') {
        if ip_matches_cidr(actual, expected) {
            return Some(AiTempPolicyMatch {
                match_mode: "cidr".to_string(),
                matched_value: actual.to_string(),
            });
        }
    }
    None
}

fn ip_matches_cidr(actual: &str, cidr: &str) -> bool {
    let (base, prefix) = match cidr.split_once('/') {
        Some(parts) => parts,
        None => return false,
    };
    let Ok(actual_ip) = actual.parse::<IpAddr>() else {
        return false;
    };
    let Ok(base_ip) = base.trim().parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix_len) = prefix.trim().parse::<u8>() else {
        return false;
    };
    match (actual_ip, base_ip) {
        (IpAddr::V4(actual_v4), IpAddr::V4(base_v4)) if prefix_len <= 32 => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix_len))
            };
            (u32::from(actual_v4) & mask) == (u32::from(base_v4) & mask)
        }
        (IpAddr::V6(actual_v6), IpAddr::V6(base_v6)) if prefix_len <= 128 => {
            let actual_value = u128::from_be_bytes(actual_v6.octets());
            let base_value = u128::from_be_bytes(base_v6.octets());
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix_len))
            };
            (actual_value & mask) == (base_value & mask)
        }
        _ => false,
    }
}

async fn load_rule_engine_state(
    config: &Config,
    sqlite_store: Option<&SqliteStore>,
) -> Result<(Option<RuleEngine>, u64, i64)> {
    if config.sqlite_rules_enabled {
        if let Some(store) = sqlite_store {
            if !config.rules.is_empty() {
                let seeded = store.seed_rules(&config.rules).await?;
                if seeded > 0 {
                    info!("Seeded {} config rule(s) into SQLite", seeded);
                }
            }

            let rules = store.load_rules().await?;
            let (rule_count, rule_version) = store.rules_state().await?;
            let rule_engine = compile_rule_engine(rules)?;
            return Ok((rule_engine, rule_count, rule_version));
        }

        warn!("SQLite rule loading requested but SQLite storage is unavailable");
    }

    let rule_count = config.rules.len() as u64;
    Ok((compile_rule_engine(config.rules.clone())?, rule_count, 0))
}

fn compile_rule_engine(rules: Vec<crate::config::Rule>) -> Result<Option<RuleEngine>> {
    if rules.is_empty() {
        Ok(None)
    } else {
        Ok(Some(RuleEngine::new(rules)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, Http3Config, L4Config, L7Config, Rule, RuleAction, RuleLayer, RuntimeProfile,
        Severity,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_db_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        std::env::temp_dir()
            .join(format!(
                "{}_core_{}_{}.db",
                env!("CARGO_PKG_NAME"),
                name,
                nanos
            ))
            .display()
            .to_string()
    }

    fn test_rule(id: &str, pattern: &str) -> Rule {
        Rule {
            id: id.to_string(),
            name: format!("Rule {}", id),
            enabled: true,
            layer: RuleLayer::L7,
            pattern: pattern.to_string(),
            action: RuleAction::Block,
            severity: Severity::High,
            plugin_template_id: None,
            response_template: None,
        }
    }

    #[tokio::test]
    async fn test_context_loads_and_refreshes_sqlite_rules() {
        let db_path = unique_test_db_path("rules_refresh");
        let config = Config {
            interface: "lo0".to_string(),
            listen_addrs: vec!["127.0.0.1:0".to_string()],
            tcp_upstream_addr: None,
            udp_upstream_addr: None,
            runtime_profile: RuntimeProfile::Standard,
            api_enabled: false,
            api_bind: "127.0.0.1:3740".to_string(),
            bloom_enabled: false,
            l4_bloom_false_positive_verification: false,
            l7_bloom_false_positive_verification: false,
            maintenance_interval_secs: 30,
            l4_config: L4Config::default(),
            l7_config: L7Config::default(),
            http3_config: Http3Config::default(),
            rules: vec![test_rule("seed-1", "attack")],
            metrics_enabled: true,
            sqlite_enabled: true,
            sqlite_path: db_path,
            sqlite_auto_migrate: true,
            sqlite_rules_enabled: true,
            max_concurrent_tasks: 128,
            ..Config::default()
        };

        let context = WafContext::new(config).await.unwrap();
        assert_eq!(context.active_rule_count(), 1);

        let store = context.sqlite_store.as_ref().unwrap();
        store
            .seed_rules(&[test_rule("seed-2", "exploit")])
            .await
            .unwrap();

        let refreshed = context.refresh_rules_from_storage().await.unwrap();
        assert!(refreshed);
        assert_eq!(context.active_rule_count(), 2);
    }

    fn test_policy(scope_type: &str, scope_value: &str, operator: &str) -> AiTempPolicyEntry {
        AiTempPolicyEntry {
            id: 1,
            created_at: 0,
            updated_at: 0,
            expires_at: i64::MAX,
            status: "active".to_string(),
            source_report_id: None,
            policy_key: "test".to_string(),
            title: "test".to_string(),
            policy_type: "test".to_string(),
            layer: "l7".to_string(),
            scope_type: scope_type.to_string(),
            scope_value: scope_value.to_string(),
            action: "increase_challenge".to_string(),
            operator: operator.to_string(),
            suggested_value: "80".to_string(),
            rationale: "test".to_string(),
            confidence: 80,
            auto_applied: true,
            hit_count: 0,
            last_hit_at: None,
            effect_json: "{}".to_string(),
        }
    }

    #[test]
    fn test_route_prefix_temp_policy_matching() {
        let matched = match_ai_temp_policy(
            &test_policy("route", "/login/*", "prefix"),
            "example.com",
            "/login/submit",
            "203.0.113.8",
            Some("fp:abc"),
        )
        .unwrap();
        assert_eq!(matched.match_mode, "prefix");
        assert_eq!(matched.matched_value, "/login/submit");
    }

    #[test]
    fn test_host_suffix_temp_policy_matching() {
        let matched = match_ai_temp_policy(
            &test_policy("host", "*.example.com", "suffix"),
            "api.example.com",
            "/",
            "203.0.113.8",
            Some("fp:abc"),
        )
        .unwrap();
        assert_eq!(matched.match_mode, "suffix");
    }

    #[test]
    fn test_source_ip_cidr_temp_policy_matching() {
        let matched = match_ai_temp_policy(
            &test_policy("source_ip", "203.0.113.0/24", "cidr"),
            "example.com",
            "/",
            "203.0.113.77",
            Some("fp:abc"),
        )
        .unwrap();
        assert_eq!(matched.match_mode, "cidr");
    }
}
