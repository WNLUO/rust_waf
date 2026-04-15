use serde::{Deserialize, Serialize};

use super::{GatewayConfig, Http3Config, L4Config, L7Config, Rule};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub interface: String,
    pub listen_addrs: Vec<String>,
    #[serde(default)]
    pub tcp_upstream_addr: Option<String>,
    #[serde(default)]
    pub udp_upstream_addr: Option<String>,
    pub runtime_profile: RuntimeProfile,
    pub api_enabled: bool,
    pub api_bind: String,
    pub bloom_enabled: bool,
    pub l4_bloom_false_positive_verification: bool,
    pub l7_bloom_false_positive_verification: bool,
    pub maintenance_interval_secs: u64,
    pub l4_config: L4Config,
    pub l7_config: L7Config,
    #[serde(default)]
    pub gateway_config: GatewayConfig,
    pub http3_config: Http3Config,
    pub rules: Vec<Rule>,
    pub metrics_enabled: bool,
    #[serde(default = "super::default_sqlite_enabled")]
    pub sqlite_enabled: bool,
    #[serde(default = "super::default_sqlite_path")]
    pub sqlite_path: String,
    #[serde(default = "super::default_sqlite_auto_migrate")]
    pub sqlite_auto_migrate: bool,
    #[serde(default = "super::default_sqlite_queue_capacity")]
    pub sqlite_queue_capacity: usize,
    #[serde(default, deserialize_with = "super::deserialize_boolish")]
    pub sqlite_rules_enabled: bool,
    #[serde(default)]
    pub max_concurrent_tasks: usize,
    #[serde(default)]
    pub console_settings: ConsoleSettings,
    #[serde(default)]
    pub integrations: IntegrationsConfig,
    #[serde(default)]
    pub admin_api_auth: AdminApiAuthConfig,
    #[serde(default)]
    pub auto_tuning: AutoTuningConfig,
    #[serde(default)]
    pub adaptive_protection: AdaptiveProtectionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleSettings {
    #[serde(default = "super::default_gateway_name")]
    pub gateway_name: String,
    #[serde(default)]
    pub drop_unmatched_requests: bool,
    #[serde(default)]
    pub cdn_525_diagnostic_mode: bool,
    #[serde(default)]
    pub client_identity_debug_enabled: bool,
    #[serde(default)]
    pub emergency_mode: bool,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveProtectionConfig {
    #[serde(default = "default_adaptive_protection_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub mode: AdaptiveProtectionMode,
    #[serde(default)]
    pub goal: AdaptiveProtectionGoal,
    #[serde(default = "default_adaptive_cdn_fronted")]
    pub cdn_fronted: bool,
    #[serde(default)]
    pub allow_emergency_reject: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdaptiveProtectionMode {
    Relaxed,
    #[default]
    Balanced,
    Strict,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AdaptiveProtectionGoal {
    AvailabilityFirst,
    #[default]
    Balanced,
    SecurityFirst,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrationsConfig {
    #[serde(default)]
    pub safeline: SafeLineConfig,
    #[serde(default)]
    pub ai_audit: AiAuditConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAuditConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub provider: AiAuditProviderConfig,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_ai_audit_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_ai_audit_fallback_to_rules")]
    pub fallback_to_rules: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AiAuditProviderConfig {
    #[default]
    LocalRules,
    StubModel,
    OpenAiCompatible,
    XiaomiMimo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminApiAuthConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub bearer_token: String,
    #[serde(default = "super::default_admin_api_audit_enabled")]
    pub audit_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeLineConfig {
    #[serde(default = "super::default_safeline_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub auto_sync_events: bool,
    #[serde(default)]
    pub auto_sync_blocked_ips_push: bool,
    #[serde(default)]
    pub auto_sync_blocked_ips_pull: bool,
    #[serde(default = "super::default_safeline_auto_sync_interval_secs")]
    pub auto_sync_interval_secs: u64,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub api_token: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "super::default_verify_tls")]
    pub verify_tls: bool,
    #[serde(default = "super::default_openapi_doc_path")]
    pub openapi_doc_path: String,
    #[serde(default = "super::default_auth_probe_path")]
    pub auth_probe_path: String,
    #[serde(default = "super::default_site_list_path")]
    pub site_list_path: String,
    #[serde(default = "super::default_event_list_path")]
    pub event_list_path: String,
    #[serde(default = "super::default_blocklist_sync_path")]
    pub blocklist_sync_path: String,
    #[serde(default = "super::default_blocklist_delete_path")]
    pub blocklist_delete_path: String,
    #[serde(default)]
    pub blocklist_ip_group_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoTuningConfig {
    #[serde(default)]
    pub mode: AutoTuningMode,
    #[serde(default)]
    pub intent: AutoTuningIntent,
    #[serde(default = "default_auto_runtime_adjust_enabled")]
    pub runtime_adjust_enabled: bool,
    #[serde(default = "default_auto_bootstrap_secs")]
    pub bootstrap_secs: u64,
    #[serde(default = "default_auto_control_interval_secs")]
    pub control_interval_secs: u64,
    #[serde(default = "default_auto_cooldown_secs")]
    pub cooldown_secs: u64,
    #[serde(default = "default_auto_max_step_percent")]
    pub max_step_percent: u8,
    #[serde(default = "default_auto_rollback_window_minutes")]
    pub rollback_window_minutes: u64,
    #[serde(default)]
    pub pinned_fields: Vec<String>,
    #[serde(default)]
    pub slo: AutoSloTargets,
}

const fn default_adaptive_protection_enabled() -> bool {
    true
}

const fn default_ai_audit_timeout_ms() -> u64 {
    15_000
}

const fn default_ai_audit_fallback_to_rules() -> bool {
    true
}

const fn default_adaptive_cdn_fronted() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoSloTargets {
    #[serde(default = "default_auto_tls_handshake_timeout_rate_percent")]
    pub tls_handshake_timeout_rate_percent: f64,
    #[serde(default = "default_auto_bucket_reject_rate_percent")]
    pub bucket_reject_rate_percent: f64,
    #[serde(default = "default_auto_p95_proxy_latency_ms")]
    pub p95_proxy_latency_ms: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AutoTuningMode {
    Off,
    #[default]
    Observe,
    Active,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AutoTuningIntent {
    Conservative,
    #[default]
    Balanced,
    Aggressive,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfile {
    Minimal,
    #[default]
    Standard,
}

impl RuntimeProfile {
    pub fn is_minimal(self) -> bool {
        matches!(self, Self::Minimal)
    }
}

const fn default_auto_runtime_adjust_enabled() -> bool {
    false
}

const fn default_auto_bootstrap_secs() -> u64 {
    60
}

const fn default_auto_control_interval_secs() -> u64 {
    30
}

const fn default_auto_cooldown_secs() -> u64 {
    120
}

const fn default_auto_max_step_percent() -> u8 {
    8
}

const fn default_auto_rollback_window_minutes() -> u64 {
    10
}

const fn default_auto_tls_handshake_timeout_rate_percent() -> f64 {
    0.3
}

const fn default_auto_bucket_reject_rate_percent() -> f64 {
    0.5
}

const fn default_auto_p95_proxy_latency_ms() -> u64 {
    800
}

impl Default for AutoTuningConfig {
    fn default() -> Self {
        Self {
            mode: AutoTuningMode::default(),
            intent: AutoTuningIntent::default(),
            runtime_adjust_enabled: default_auto_runtime_adjust_enabled(),
            bootstrap_secs: default_auto_bootstrap_secs(),
            control_interval_secs: default_auto_control_interval_secs(),
            cooldown_secs: default_auto_cooldown_secs(),
            max_step_percent: default_auto_max_step_percent(),
            rollback_window_minutes: default_auto_rollback_window_minutes(),
            pinned_fields: Vec::new(),
            slo: AutoSloTargets::default(),
        }
    }
}

impl Default for AutoSloTargets {
    fn default() -> Self {
        Self {
            tls_handshake_timeout_rate_percent: default_auto_tls_handshake_timeout_rate_percent(),
            bucket_reject_rate_percent: default_auto_bucket_reject_rate_percent(),
            p95_proxy_latency_ms: default_auto_p95_proxy_latency_ms(),
        }
    }
}
