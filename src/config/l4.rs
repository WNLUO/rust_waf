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
    #[serde(default)]
    pub trusted_cdn: TrustedCdnConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedCdnConfig {
    #[serde(default)]
    pub manual_cidrs: Vec<String>,
    #[serde(default = "default_trusted_cdn_sync_interval_value")]
    pub sync_interval_value: u64,
    #[serde(default)]
    pub sync_interval_unit: TrustedCdnSyncIntervalUnit,
    #[serde(default)]
    pub edgeone_overseas: TrustedCdnEdgeOneConfig,
    #[serde(default)]
    pub aliyun_esa: TrustedCdnAliyunEsaConfig,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustedCdnSyncIntervalUnit {
    #[default]
    Minute,
    Hour,
    Day,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedCdnEdgeOneConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub synced_cidrs: Vec<String>,
    #[serde(default)]
    pub last_synced_at: Option<i64>,
    #[serde(default)]
    pub last_sync_status: TrustedCdnSyncStatus,
    #[serde(default)]
    pub last_sync_message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedCdnAliyunEsaConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub site_id: String,
    #[serde(default)]
    pub access_key_id: String,
    #[serde(default)]
    pub access_key_secret: String,
    #[serde(default = "default_aliyun_esa_endpoint")]
    pub endpoint: String,
    #[serde(default)]
    pub synced_cidrs: Vec<String>,
    #[serde(default)]
    pub last_synced_at: Option<i64>,
    #[serde(default)]
    pub last_sync_status: TrustedCdnSyncStatus,
    #[serde(default)]
    pub last_sync_message: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TrustedCdnSyncStatus {
    #[default]
    Idle,
    Success,
    Error,
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

const fn default_trusted_cdn_sync_interval_value() -> u64 {
    12
}

fn default_aliyun_esa_endpoint() -> String {
    "esa.cn-hangzhou.aliyuncs.com".to_string()
}

impl TrustedCdnConfig {
    pub fn sync_interval_secs(&self) -> u64 {
        let base = self.sync_interval_value.max(1);
        match self.sync_interval_unit {
            TrustedCdnSyncIntervalUnit::Minute => base.saturating_mul(60),
            TrustedCdnSyncIntervalUnit::Hour => base.saturating_mul(60 * 60),
            TrustedCdnSyncIntervalUnit::Day => base.saturating_mul(60 * 60 * 24),
        }
    }

    pub fn enabled_synced_cidrs(&self) -> Vec<String> {
        let mut cidrs = Vec::new();
        if self.edgeone_overseas.enabled {
            cidrs.extend(self.edgeone_overseas.synced_cidrs.iter().cloned());
        }
        if self.aliyun_esa.enabled {
            cidrs.extend(self.aliyun_esa.synced_cidrs.iter().cloned());
        }
        cidrs
    }

    pub fn effective_cidrs(&self) -> Vec<String> {
        let mut cidrs = self.manual_cidrs.clone();
        cidrs.extend(self.enabled_synced_cidrs());
        cidrs
    }
}

impl Default for TrustedCdnConfig {
    fn default() -> Self {
        Self {
            manual_cidrs: Vec::new(),
            sync_interval_value: default_trusted_cdn_sync_interval_value(),
            sync_interval_unit: TrustedCdnSyncIntervalUnit::default(),
            edgeone_overseas: TrustedCdnEdgeOneConfig::default(),
            aliyun_esa: TrustedCdnAliyunEsaConfig::default(),
        }
    }
}

impl Default for TrustedCdnEdgeOneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            synced_cidrs: Vec::new(),
            last_synced_at: None,
            last_sync_status: TrustedCdnSyncStatus::Idle,
            last_sync_message: String::new(),
        }
    }
}

impl Default for TrustedCdnAliyunEsaConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            site_id: String::new(),
            access_key_id: String::new(),
            access_key_secret: String::new(),
            endpoint: default_aliyun_esa_endpoint(),
            synced_cidrs: Vec::new(),
            last_synced_at: None,
            last_sync_status: TrustedCdnSyncStatus::Idle,
            last_sync_message: String::new(),
        }
    }
}

impl Default for L4Config {
    fn default() -> Self {
        Self {
            ddos_protection_enabled: true,
            advanced_ddos_enabled: true,
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
            trusted_cdn: TrustedCdnConfig::default(),
        }
    }
}
