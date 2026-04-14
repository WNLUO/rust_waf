use anyhow::Result;
use serde::de::{self, Deserializer};
use serde::Deserialize;

use super::super::*;

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            listen_addrs: vec!["0.0.0.0:66".to_string()],
            tcp_upstream_addr: None,
            udp_upstream_addr: None,
            runtime_profile: RuntimeProfile::Standard,
            api_enabled: true,
            api_bind: "127.0.0.1:3740".to_string(),
            bloom_enabled: true,
            l4_bloom_false_positive_verification: true,
            l7_bloom_false_positive_verification: true,
            maintenance_interval_secs: 30,
            l4_config: L4Config::default(),
            l7_config: L7Config::default(),
            gateway_config: GatewayConfig::default(),
            http3_config: Http3Config::default(),
            rules: vec![],
            metrics_enabled: true,
            sqlite_enabled: default_sqlite_enabled(),
            sqlite_path: default_sqlite_path(),
            sqlite_auto_migrate: default_sqlite_auto_migrate(),
            sqlite_queue_capacity: default_sqlite_queue_capacity(),
            sqlite_rules_enabled: default_sqlite_rules_enabled(),
            max_concurrent_tasks: 0,
            console_settings: ConsoleSettings::default(),
            integrations: IntegrationsConfig::default(),
            admin_api_auth: AdminApiAuthConfig::default(),
            auto_tuning: AutoTuningConfig::default(),
        }
        .normalized()
    }
}

pub(crate) fn deserialize_boolish<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Boolish {
        Bool(bool),
        Int(u8),
        String(String),
    }

    match Boolish::deserialize(deserializer)? {
        Boolish::Bool(value) => Ok(value),
        Boolish::Int(0) => Ok(false),
        Boolish::Int(1) => Ok(true),
        Boolish::Int(other) => Err(de::Error::custom(format!(
            "invalid integer {other}, expected 0 or 1"
        ))),
        Boolish::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(true),
            "false" | "0" => Ok(false),
            other => Err(de::Error::custom(format!(
                "invalid string '{other}', expected true/false/0/1"
            ))),
        },
    }
}

impl Default for ConsoleSettings {
    fn default() -> Self {
        Self {
            gateway_name: default_gateway_name(),
            drop_unmatched_requests: false,
            cdn_525_diagnostic_mode: false,
            emergency_mode: false,
            notes: String::new(),
        }
    }
}

impl Default for SafeLineConfig {
    fn default() -> Self {
        Self {
            enabled: default_safeline_enabled(),
            auto_sync_events: true,
            auto_sync_blocked_ips_push: false,
            auto_sync_blocked_ips_pull: true,
            auto_sync_interval_secs: default_safeline_auto_sync_interval_secs(),
            base_url: String::new(),
            api_token: String::new(),
            username: String::new(),
            password: String::new(),
            verify_tls: default_verify_tls(),
            openapi_doc_path: default_openapi_doc_path(),
            auth_probe_path: default_auth_probe_path(),
            site_list_path: default_site_list_path(),
            event_list_path: default_event_list_path(),
            blocklist_sync_path: default_blocklist_sync_path(),
            blocklist_delete_path: default_blocklist_delete_path(),
            blocklist_ip_group_ids: Vec::new(),
        }
    }
}

impl Default for AdminApiAuthConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bearer_token: String::new(),
            audit_enabled: default_admin_api_audit_enabled(),
        }
    }
}
