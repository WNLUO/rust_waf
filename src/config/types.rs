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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleSettings {
    #[serde(default = "super::default_gateway_name")]
    pub gateway_name: String,
    #[serde(default)]
    pub emergency_mode: bool,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrationsConfig {
    #[serde(default)]
    pub safeline: SafeLineConfig,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProfile {
    Minimal,
    Standard,
}

impl RuntimeProfile {
    pub fn is_minimal(self) -> bool {
        matches!(self, Self::Minimal)
    }
}

impl Default for RuntimeProfile {
    fn default() -> Self {
        Self::Standard
    }
}
