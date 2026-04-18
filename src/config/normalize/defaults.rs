use crate::config::types::StoragePolicyConfig;
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
            storage_policy: StoragePolicyConfig::default(),
            sqlite_rules_enabled: default_sqlite_rules_enabled(),
            max_concurrent_tasks: 0,
            console_settings: ConsoleSettings::default(),
            integrations: IntegrationsConfig::default(),
            admin_api_auth: AdminApiAuthConfig::default(),
            auto_tuning: AutoTuningConfig::default(),
            adaptive_protection: AdaptiveProtectionConfig::default(),
            bot_detection: BotDetectionConfig::default(),
        }
        .normalized()
    }
}

impl Default for BotDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            crawlers: default_bot_crawlers(),
            providers: default_bot_providers(),
        }
    }
}

pub(crate) fn default_bot_crawlers() -> Vec<BotCrawlerConfig> {
    vec![
        bot_crawler(
            "Googlebot",
            Some("google"),
            "search",
            "reduce_friction",
            &["googlebot", "adsbot-google", "google-inspectiontool"],
        ),
        bot_crawler(
            "Bingbot",
            Some("bing"),
            "search",
            "reduce_friction",
            &["bingbot", "msnbot"],
        ),
        bot_crawler(
            "Baiduspider",
            None,
            "search",
            "reduce_friction",
            &["baiduspider"],
        ),
        bot_crawler(
            "Sogou Spider",
            None,
            "search",
            "reduce_friction",
            &["sogou web spider", "sogou spider"],
        ),
        bot_crawler(
            "YandexBot",
            None,
            "search",
            "reduce_friction",
            &["yandexbot"],
        ),
        bot_crawler(
            "DuckDuckBot",
            None,
            "search",
            "reduce_friction",
            &["duckduckbot"],
        ),
        bot_crawler("Applebot", None, "search", "reduce_friction", &["applebot"]),
        bot_crawler(
            "GPTBot",
            None,
            "ai",
            "observe",
            &["gptbot", "chatgpt-user", "oai-searchbot"],
        ),
        bot_crawler(
            "ClaudeBot",
            None,
            "ai",
            "observe",
            &["claudebot", "anthropic-ai"],
        ),
        bot_crawler("PerplexityBot", None, "ai", "observe", &["perplexitybot"]),
        bot_crawler("Bytespider", None, "ai", "observe", &["bytespider"]),
        bot_crawler("AhrefsBot", None, "seo", "observe", &["ahrefsbot"]),
        bot_crawler("SemrushBot", None, "seo", "observe", &["semrushbot"]),
    ]
}

pub(crate) fn default_bot_providers() -> Vec<BotProviderConfig> {
    vec![
        BotProviderConfig {
            enabled: true,
            id: "google".to_string(),
            urls: vec![
                "https://developers.google.com/static/search/apis/ipranges/googlebot.json".to_string(),
                "https://developers.google.com/static/search/apis/ipranges/special-crawlers.json".to_string(),
                "https://developers.google.com/static/search/apis/ipranges/user-triggered-fetchers.json".to_string(),
                "https://developers.google.com/crawling/ipranges/common-crawlers.json".to_string(),
                "https://developers.google.com/crawling/ipranges/special-crawlers.json".to_string(),
                "https://developers.google.com/crawling/ipranges/user-triggered-fetchers.json".to_string(),
            ],
            format: "json_recursive".to_string(),
            reverse_dns_enabled: true,
            reverse_dns_suffixes: vec![
                ".googlebot.com".to_string(),
                ".google.com".to_string(),
                ".googleusercontent.com".to_string(),
            ],
        },
        BotProviderConfig {
            enabled: true,
            id: "bing".to_string(),
            urls: vec!["https://www.bing.com/toolbox/bingbot.json".to_string()],
            format: "json_recursive".to_string(),
            reverse_dns_enabled: true,
            reverse_dns_suffixes: vec![".search.msn.com".to_string()],
        },
    ]
}

fn bot_crawler(
    name: &str,
    provider: Option<&str>,
    category: &str,
    policy: &str,
    tokens: &[&str],
) -> BotCrawlerConfig {
    BotCrawlerConfig {
        enabled: true,
        name: name.to_string(),
        provider: provider.map(ToOwned::to_owned),
        category: category.to_string(),
        policy: policy.to_string(),
        tokens: tokens.iter().map(|item| item.to_string()).collect(),
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
            client_identity_debug_enabled: false,
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

impl Default for AiAuditConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: AiAuditProviderConfig::LocalRules,
            model: String::new(),
            base_url: String::new(),
            api_key: String::new(),
            timeout_ms: 15_000,
            fallback_to_rules: true,
            event_sample_limit: 120,
            recent_event_limit: 12,
            include_raw_event_samples: false,
            auto_apply_temp_policies: true,
            temp_policy_ttl_secs: 15 * 60,
            temp_block_ttl_secs: 30 * 60,
            auto_apply_min_confidence: 70,
            max_active_temp_policies: 24,
            allow_auto_temp_block: false,
            allow_auto_extend_effective_policies: true,
            auto_revoke_warmup_secs: 5 * 60,
            auto_defense_enabled: true,
            auto_defense_auto_apply: true,
            auto_defense_min_confidence: 82,
            auto_defense_max_apply_per_tick: 2,
            auto_defense_trigger_cooldown_secs: 45,
            auto_defense_fallback_interval_secs: 5 * 60,
            auto_audit_enabled: false,
            auto_audit_interval_secs: 5 * 60,
            auto_audit_cooldown_secs: 10 * 60,
            auto_audit_on_pressure_high: true,
            auto_audit_on_attack_mode: true,
            auto_audit_on_hotspot_shift: true,
            auto_audit_force_local_rules_under_attack: true,
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

impl Default for AdaptiveProtectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            mode: AdaptiveProtectionMode::Balanced,
            goal: AdaptiveProtectionGoal::Balanced,
            cdn_fronted: true,
            allow_emergency_reject: false,
        }
    }
}
