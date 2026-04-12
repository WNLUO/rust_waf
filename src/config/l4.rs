use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L4Config {
    pub ddos_protection_enabled: bool,
    pub advanced_ddos_enabled: bool,
    pub connection_rate_limit: usize,
    pub syn_flood_threshold: usize,
    pub max_tracked_ips: usize,
    pub max_blocked_ips: usize,
    pub state_ttl_secs: u64,
    #[serde(default = "default_bloom_filter_scale")]
    pub bloom_filter_scale: f64,
    #[serde(default = "default_behavior_event_channel_capacity")]
    pub behavior_event_channel_capacity: usize,
    #[serde(default = "default_behavior_drop_critical_threshold")]
    pub behavior_drop_critical_threshold: u64,
    #[serde(default = "default_behavior_fallback_ratio_percent")]
    pub behavior_fallback_ratio_percent: u8,
    #[serde(default = "default_behavior_overload_blocked_connections_threshold")]
    pub behavior_overload_blocked_connections_threshold: u64,
    #[serde(default = "default_behavior_overload_active_connections_threshold")]
    pub behavior_overload_active_connections_threshold: u64,
    #[serde(default = "default_behavior_normal_connection_budget_per_minute")]
    pub behavior_normal_connection_budget_per_minute: u32,
    #[serde(default = "default_behavior_suspicious_connection_budget_per_minute")]
    pub behavior_suspicious_connection_budget_per_minute: u32,
    #[serde(default = "default_behavior_high_risk_connection_budget_per_minute")]
    pub behavior_high_risk_connection_budget_per_minute: u32,
    #[serde(default = "default_behavior_high_overload_budget_scale_percent")]
    pub behavior_high_overload_budget_scale_percent: u8,
    #[serde(default = "default_behavior_critical_overload_budget_scale_percent")]
    pub behavior_critical_overload_budget_scale_percent: u8,
    #[serde(default = "default_behavior_high_overload_delay_ms")]
    pub behavior_high_overload_delay_ms: u64,
    #[serde(default = "default_behavior_critical_overload_delay_ms")]
    pub behavior_critical_overload_delay_ms: u64,
    #[serde(default = "default_behavior_soft_delay_threshold_percent")]
    pub behavior_soft_delay_threshold_percent: u16,
    #[serde(default = "default_behavior_hard_delay_threshold_percent")]
    pub behavior_hard_delay_threshold_percent: u16,
    #[serde(default = "default_behavior_soft_delay_ms")]
    pub behavior_soft_delay_ms: u64,
    #[serde(default = "default_behavior_hard_delay_ms")]
    pub behavior_hard_delay_ms: u64,
    #[serde(default = "default_behavior_reject_threshold_percent")]
    pub behavior_reject_threshold_percent: u16,
    #[serde(default = "default_behavior_critical_reject_threshold_percent")]
    pub behavior_critical_reject_threshold_percent: u16,
}

const fn default_bloom_filter_scale() -> f64 {
    1.0
}

const fn default_behavior_event_channel_capacity() -> usize {
    4096
}

const fn default_behavior_drop_critical_threshold() -> u64 {
    128
}

const fn default_behavior_fallback_ratio_percent() -> u8 {
    80
}

const fn default_behavior_overload_blocked_connections_threshold() -> u64 {
    512
}

const fn default_behavior_overload_active_connections_threshold() -> u64 {
    2048
}

const fn default_behavior_normal_connection_budget_per_minute() -> u32 {
    120
}

const fn default_behavior_suspicious_connection_budget_per_minute() -> u32 {
    60
}

const fn default_behavior_high_risk_connection_budget_per_minute() -> u32 {
    20
}

const fn default_behavior_high_overload_budget_scale_percent() -> u8 {
    80
}

const fn default_behavior_critical_overload_budget_scale_percent() -> u8 {
    50
}

const fn default_behavior_high_overload_delay_ms() -> u64 {
    15
}

const fn default_behavior_critical_overload_delay_ms() -> u64 {
    40
}

const fn default_behavior_soft_delay_threshold_percent() -> u16 {
    100
}

const fn default_behavior_hard_delay_threshold_percent() -> u16 {
    200
}

const fn default_behavior_soft_delay_ms() -> u64 {
    25
}

const fn default_behavior_hard_delay_ms() -> u64 {
    60
}

const fn default_behavior_reject_threshold_percent() -> u16 {
    300
}

const fn default_behavior_critical_reject_threshold_percent() -> u16 {
    200
}

impl Default for L4Config {
    fn default() -> Self {
        Self {
            ddos_protection_enabled: true,
            advanced_ddos_enabled: false,
            connection_rate_limit: 100,
            syn_flood_threshold: 50,
            max_tracked_ips: 4096,
            max_blocked_ips: 1024,
            state_ttl_secs: 300,
            bloom_filter_scale: default_bloom_filter_scale(),
            behavior_event_channel_capacity: default_behavior_event_channel_capacity(),
            behavior_drop_critical_threshold: default_behavior_drop_critical_threshold(),
            behavior_fallback_ratio_percent: default_behavior_fallback_ratio_percent(),
            behavior_overload_blocked_connections_threshold:
                default_behavior_overload_blocked_connections_threshold(),
            behavior_overload_active_connections_threshold:
                default_behavior_overload_active_connections_threshold(),
            behavior_normal_connection_budget_per_minute:
                default_behavior_normal_connection_budget_per_minute(),
            behavior_suspicious_connection_budget_per_minute:
                default_behavior_suspicious_connection_budget_per_minute(),
            behavior_high_risk_connection_budget_per_minute:
                default_behavior_high_risk_connection_budget_per_minute(),
            behavior_high_overload_budget_scale_percent:
                default_behavior_high_overload_budget_scale_percent(),
            behavior_critical_overload_budget_scale_percent:
                default_behavior_critical_overload_budget_scale_percent(),
            behavior_high_overload_delay_ms: default_behavior_high_overload_delay_ms(),
            behavior_critical_overload_delay_ms: default_behavior_critical_overload_delay_ms(),
            behavior_soft_delay_threshold_percent: default_behavior_soft_delay_threshold_percent(),
            behavior_hard_delay_threshold_percent: default_behavior_hard_delay_threshold_percent(),
            behavior_soft_delay_ms: default_behavior_soft_delay_ms(),
            behavior_hard_delay_ms: default_behavior_hard_delay_ms(),
            behavior_reject_threshold_percent: default_behavior_reject_threshold_percent(),
            behavior_critical_reject_threshold_percent:
                default_behavior_critical_reject_threshold_percent(),
        }
    }
}
