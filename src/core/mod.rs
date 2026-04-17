pub(crate) mod adaptive_protection;
mod ai_defense_runtime;
mod ai_temp_policy;
mod ai_temp_policy_runtime;
mod auto_tuning;
pub mod engine;
mod engine_maintenance;
mod engine_tls;
pub mod gateway;
pub mod packet;
mod resource_budget;
mod rule_engine;
mod runtime_state;
mod self_protection;
mod storage_runtime;
mod system_profile;
pub mod traffic_map;

use crate::config::Config;
use crate::core::gateway::GatewayRuntime;
use crate::l4::L4Inspector;
use crate::l7::{
    HttpTrafficProcessor, L7BehaviorGuard, L7BloomFilterManager, L7CcGuard, SlowAttackGuard,
};
use crate::metrics::MetricsCollector;
use crate::rules::RuleEngine;
use crate::storage::{AiRouteProfileEntry, AiTempPolicyEntry, SqliteStore};
use anyhow::Result;
use dashmap::DashMap;
use rule_engine::load_rule_engine_state;
use std::sync::atomic::{AtomicI64, AtomicU64};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use storage_runtime::restore_runtime_blocked_ips;
use tokio::sync::Mutex;

pub use adaptive_protection::AdaptiveProtectionRuntimeSnapshot;
pub use auto_tuning::{
    AutoTuningControllerState, AutoTuningRecommendationSnapshot, AutoTuningRuntimeSnapshot,
};
pub use engine::WafEngine;
pub use packet::{
    CustomHttpResponse, InspectionAction, InspectionLayer, InspectionResult, PacketInfo, Protocol,
    RandomStatusConfig, TarpitConfig,
};
pub use resource_budget::{DefenseDepth, RuntimeCapacityClass, RuntimeResourceBudget};
pub use self_protection::ServerPublicIpSnapshot;

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
    l7_bloom_filter: RwLock<Option<Arc<L7BloomFilterManager>>>,
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
    ai_route_profiles: RwLock<Vec<AiRouteProfileEntry>>,
    ai_auto_audit_runtime: Mutex<AiAutoAuditRuntimeState>,
    ai_defense_trigger_runtime: std::sync::Mutex<AiDefenseTriggerState>,
    ai_defense_identity_buckets: DashMap<String, std::sync::Mutex<AiDefenseIdentityBucket>>,
    ai_route_result_buckets: DashMap<String, std::sync::Mutex<AiRouteResultBucket>>,
    site_defense_buckets: DashMap<String, std::sync::Mutex<SiteDefenseBucket>>,
    route_defense_buckets: DashMap<String, std::sync::Mutex<SiteDefenseBucket>>,
    server_public_ips: RwLock<self_protection::ServerPublicIpRuntime>,
    rule_count: AtomicU64,
    rule_version: AtomicI64,
}

#[derive(Debug, Clone)]
pub struct RuntimePressureSnapshot {
    pub level: &'static str,
    pub capacity_class: &'static str,
    pub defense_depth: &'static str,
    pub storage_queue_usage_percent: u64,
    pub drop_delay: bool,
    pub trim_event_persistence: bool,
    pub l7_bucket_limit: usize,
    pub l7_page_window_limit: usize,
    pub behavior_bucket_limit: usize,
    pub behavior_sample_stride: u64,
    pub prefer_drop: bool,
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

#[derive(Debug, Default)]
struct AiDefenseTriggerState {
    pending: bool,
    pending_since: Option<i64>,
    pending_reason: Option<String>,
    last_trigger_at: Option<i64>,
    last_run_at: Option<i64>,
}

#[derive(Debug, Default)]
struct AiDefenseIdentityBucket {
    window_start: i64,
    total_events: u64,
    unresolved_events: u64,
    trusted_proxy_events: u64,
    verified_challenge_events: u64,
    interactive_session_events: u64,
    spoofed_forward_header_events: u64,
    distinct_clients: std::collections::HashSet<String>,
    user_agents: std::collections::BTreeMap<String, u64>,
}

#[derive(Debug, Default)]
struct AiRouteResultBucket {
    window_start: i64,
    total_responses: u64,
    upstream_successes: u64,
    upstream_errors: u64,
    local_responses: u64,
    blocked_responses: u64,
    challenge_issued: u64,
    challenge_verified: u64,
    interactive_sessions: u64,
    policy_matched_responses: u64,
    suspected_false_positive_events: u64,
    status_families: std::collections::BTreeMap<String, u64>,
    status_codes: std::collections::BTreeMap<String, u64>,
    policy_actions: std::collections::BTreeMap<String, u64>,
    latency_ms_total: u64,
    latency_samples: u64,
    slow_responses: u64,
}

#[derive(Debug, Default)]
struct SiteDefenseBucket {
    window_start: i64,
    soft_events: u64,
    hard_events: u64,
}

#[derive(Debug, Clone)]
pub struct LocalDefenseRecommendation {
    pub key: String,
    pub site_id: String,
    pub route: String,
    pub defense_depth: String,
    pub soft_events: u64,
    pub hard_events: u64,
    pub total_events: u64,
    pub action: String,
    pub suggested_value: String,
    pub ttl_secs: u64,
    pub confidence: u8,
    pub rationale: String,
}

#[derive(Debug, Clone)]
pub struct AiDefenseSignalSnapshot {
    pub generated_at: i64,
    pub sqlite_available: bool,
    pub active_temp_policy_count: u32,
    pub max_active_temp_policy_count: u32,
    pub trigger_reason: Option<String>,
    pub trigger_pending_secs: u64,
    pub runtime_pressure: AiDefenseRuntimePressureSignal,
    pub l4_pressure: Option<AiDefenseL4Signal>,
    pub upstream_health: AiDefenseUpstreamSignal,
    pub active_policy_summaries: Vec<AiDefensePolicySignal>,
    pub identity_summaries: Vec<AiDefenseIdentitySignal>,
    pub route_effects: Vec<AiDefenseRouteEffectSignal>,
    pub policy_effects: Vec<AiDefensePolicyEffectSignal>,
    pub route_profiles: Vec<AiDefenseRouteProfileSignal>,
    pub local_recommendations: Vec<LocalDefenseRecommendation>,
    pub server_public_ips: ServerPublicIpSnapshot,
}

#[derive(Debug, Clone)]
pub struct AiDefenseRuntimePressureSignal {
    pub level: String,
    pub defense_depth: String,
    pub prefer_drop: bool,
    pub trim_event_persistence: bool,
    pub l7_friction_pressure_percent: f64,
    pub identity_pressure_percent: f64,
    pub avg_proxy_latency_ms: u64,
}

#[derive(Debug, Clone)]
pub struct AiDefenseL4Signal {
    pub active_connections: u64,
    pub blocked_connections: u64,
    pub rate_limit_hits: u64,
    pub ddos_events: u64,
    pub protocol_anomalies: u64,
    pub defense_actions: u64,
    pub top_ports: Vec<AiDefensePortSignal>,
}

#[derive(Debug, Clone)]
pub struct AiDefensePortSignal {
    pub port: String,
    pub connections: u64,
    pub blocks: u64,
    pub ddos_events: u64,
}

#[derive(Debug, Clone)]
pub struct AiDefenseUpstreamSignal {
    pub healthy: bool,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AiDefensePolicySignal {
    pub policy_key: String,
    pub scope_type: String,
    pub scope_value: String,
    pub action: String,
    pub hit_count: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone)]
pub struct AiDefenseIdentitySignal {
    pub site_id: String,
    pub route: String,
    pub total_events: u64,
    pub distinct_client_count: usize,
    pub unresolved_events: u64,
    pub trusted_proxy_events: u64,
    pub verified_challenge_events: u64,
    pub interactive_session_events: u64,
    pub spoofed_forward_header_events: u64,
    pub top_user_agents: Vec<AiDefenseUserAgentSignal>,
}

#[derive(Debug, Clone)]
pub struct AiDefenseUserAgentSignal {
    pub value: String,
    pub count: u64,
}

#[derive(Debug, Clone)]
pub struct AiRouteResultObservation {
    pub status_code: u16,
    pub latency_ms: Option<u64>,
    pub upstream_error: bool,
    pub local_response: bool,
    pub blocked: bool,
}

#[derive(Debug, Clone)]
pub struct AiDefenseRouteEffectSignal {
    pub site_id: String,
    pub route: String,
    pub total_responses: u64,
    pub upstream_successes: u64,
    pub upstream_errors: u64,
    pub local_responses: u64,
    pub blocked_responses: u64,
    pub challenge_issued: u64,
    pub challenge_verified: u64,
    pub interactive_sessions: u64,
    pub policy_matched_responses: u64,
    pub suspected_false_positive_events: u64,
    pub status_families: std::collections::BTreeMap<String, u64>,
    pub status_codes: std::collections::BTreeMap<String, u64>,
    pub policy_actions: std::collections::BTreeMap<String, u64>,
    pub avg_latency_ms: Option<u64>,
    pub slow_responses: u64,
    pub false_positive_risk: String,
    pub effectiveness_hint: String,
}

#[derive(Debug, Clone)]
pub struct AiDefensePolicyEffectSignal {
    pub policy_key: String,
    pub scope_type: String,
    pub scope_value: String,
    pub action: String,
    pub hit_count: i64,
    pub outcome_status: String,
    pub outcome_score: i64,
    pub observations: i64,
    pub upstream_errors: i64,
    pub suspected_false_positive_events: i64,
    pub challenge_verified: i64,
    pub pressure_after_observations: i64,
}

#[derive(Debug, Clone)]
pub struct AiDefenseRouteProfileSignal {
    pub site_id: String,
    pub route_pattern: String,
    pub match_mode: String,
    pub route_type: String,
    pub sensitivity: String,
    pub auth_required: String,
    pub normal_traffic_pattern: String,
    pub recommended_actions: Vec<String>,
    pub avoid_actions: Vec<String>,
    pub evidence: serde_json::Value,
    pub raw_confidence: i64,
    pub staleness_secs: Option<u64>,
    pub confidence: i64,
    pub source: String,
    pub status: String,
    pub rationale: String,
}

#[derive(Debug, Clone)]
pub struct AiDefenseDecision {
    pub key: String,
    pub title: String,
    pub layer: String,
    pub scope_type: String,
    pub scope_value: String,
    pub action: String,
    pub operator: String,
    pub suggested_value: String,
    pub ttl_secs: u64,
    pub confidence: u8,
    pub auto_apply: bool,
    pub rationale: String,
}

#[derive(Debug, Clone, Default)]
pub struct AiDefenseRunResult {
    pub generated_at: i64,
    pub trigger_reason: Option<String>,
    pub decisions: Vec<AiDefenseDecision>,
    pub applied: usize,
    pub skipped: usize,
    pub disabled_reason: Option<String>,
}

impl WafContext {
    pub async fn new(config: Config) -> Result<Self> {
        let l4_enabled =
            config.l4_config.ddos_protection_enabled || config.l4_config.connection_rate_limit > 0;
        let bloom_enabled = config.bloom_enabled;
        let l4_bloom_verification = config.l4_bloom_false_positive_verification;
        let l7_bloom_verification = config.l7_bloom_false_positive_verification;
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

        let context = Self {
            runtime_config: Arc::new(RwLock::new(config.clone())),
            l4_inspector: RwLock::new(l4_enabled.then(|| {
                Arc::new(L4Inspector::new(
                    effective_l4_config,
                    bloom_enabled,
                    l4_bloom_verification,
                ))
            })),
            l7_bloom_filter: RwLock::new(bloom_enabled.then(|| {
                Arc::new(L7BloomFilterManager::new(
                    config.l7_config.clone(),
                    bloom_enabled,
                    l7_bloom_verification,
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
            ai_route_profiles: RwLock::new(Vec::new()),
            ai_auto_audit_runtime: Mutex::new(AiAutoAuditRuntimeState::default()),
            ai_defense_trigger_runtime: std::sync::Mutex::new(AiDefenseTriggerState::default()),
            ai_defense_identity_buckets: DashMap::new(),
            ai_route_result_buckets: DashMap::new(),
            site_defense_buckets: DashMap::new(),
            route_defense_buckets: DashMap::new(),
            server_public_ips: RwLock::new(self_protection::ServerPublicIpRuntime::default()),
            rule_count: AtomicU64::new(rule_count),
            rule_version: AtomicI64::new(rule_version),
            config,
        };

        if let (Some(store), Some(inspector)) = (
            context.sqlite_store.as_ref(),
            context.l4_inspector().as_ref().cloned(),
        ) {
            restore_runtime_blocked_ips(store.as_ref(), inspector.as_ref()).await?;
        }

        Ok(context)
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
        self.refresh_l7_bloom_filter_from_config();
        self.refresh_l4_behavior_tuning_from_config();
        self.refresh_http3_runtime_metadata();
    }

    pub fn learn_trusted_cdn_peer(&self, peer_ip: std::net::IpAddr, evidence_header: &str) -> bool {
        if peer_ip.is_unspecified() || peer_ip.is_loopback() {
            return false;
        }

        let cidr = match peer_ip {
            std::net::IpAddr::V4(ip) => format!("{ip}/32"),
            std::net::IpAddr::V6(ip) => format!("{ip}/128"),
        };
        let mut next = self.config_snapshot();
        if next
            .effective_trusted_proxy_cidrs()
            .iter()
            .filter_map(|item| item.parse::<ipnet::IpNet>().ok())
            .any(|network| network.contains(&peer_ip))
        {
            return false;
        }
        if next
            .l4_config
            .trusted_cdn
            .manual_cidrs
            .iter()
            .any(|item| item == &cidr)
        {
            return false;
        }
        let pressure = self.runtime_pressure_snapshot();
        if next.l4_config.trusted_cdn.manual_cidrs.len()
            >= resource_budget::current_runtime_resource_budget(
                pressure.level,
                pressure.storage_queue_usage_percent,
            )
            .trusted_cdn_auto_learn_limit
        {
            log::warn!(
                "Skipped learning trusted CDN peer {} from header {} because the automatic learn budget is full",
                cidr,
                evidence_header
            );
            return false;
        }

        next.l4_config.trusted_cdn.manual_cidrs.push(cidr.clone());
        let next = next.normalized();
        self.apply_runtime_config(next.clone());

        if let Some(store) = self.sqlite_store.as_ref().cloned() {
            let evidence_header = evidence_header.to_string();
            tokio::spawn(async move {
                if let Err(err) = store.upsert_app_config(&next).await {
                    log::warn!(
                        "Failed to persist learned trusted CDN peer {} from header {}: {}",
                        cidr,
                        evidence_header,
                        err
                    );
                }
            });
        }

        true
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

    pub fn l7_bloom_filter(&self) -> Option<Arc<L7BloomFilterManager>> {
        self.l7_bloom_filter
            .read()
            .expect("l7_bloom_filter lock poisoned")
            .as_ref()
            .cloned()
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
}

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests;
