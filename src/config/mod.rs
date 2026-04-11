use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::env;
use std::net::SocketAddr;

pub mod gateway;
pub mod http3;
pub mod l4;
pub mod l7;

pub use gateway::GatewayConfig;
pub use http3::Http3Config;
pub use l4::L4Config;
pub use l7::L7Config;

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
    #[serde(default = "default_sqlite_enabled")]
    pub sqlite_enabled: bool,
    #[serde(default = "default_sqlite_path")]
    pub sqlite_path: String,
    #[serde(default = "default_sqlite_auto_migrate")]
    pub sqlite_auto_migrate: bool,
    #[serde(default)]
    pub sqlite_rules_enabled: bool,
    #[serde(default)]
    pub max_concurrent_tasks: usize,
    #[serde(default)]
    pub console_settings: ConsoleSettings,
    #[serde(default)]
    pub integrations: IntegrationsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsoleSettings {
    #[serde(default = "default_gateway_name")]
    pub gateway_name: String,
    #[serde(default = "default_auto_refresh_seconds")]
    pub auto_refresh_seconds: u32,
    #[serde(default)]
    pub emergency_mode: bool,
    #[serde(default = "default_notification_level")]
    pub notification_level: String,
    #[serde(default = "default_retain_days")]
    pub retain_days: u32,
    #[serde(default)]
    pub notes: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntegrationsConfig {
    #[serde(default)]
    pub safeline: SafeLineConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafeLineConfig {
    #[serde(default = "default_safeline_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub auto_sync_events: bool,
    #[serde(default)]
    pub auto_sync_blocked_ips_push: bool,
    #[serde(default)]
    pub auto_sync_blocked_ips_pull: bool,
    #[serde(default = "default_safeline_auto_sync_interval_secs")]
    pub auto_sync_interval_secs: u64,
    #[serde(default)]
    pub base_url: String,
    #[serde(default)]
    pub api_token: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_verify_tls")]
    pub verify_tls: bool,
    #[serde(default = "default_openapi_doc_path")]
    pub openapi_doc_path: String,
    #[serde(default = "default_auth_probe_path")]
    pub auth_probe_path: String,
    #[serde(default = "default_site_list_path")]
    pub site_list_path: String,
    #[serde(default = "default_event_list_path")]
    pub event_list_path: String,
    #[serde(default = "default_blocklist_sync_path")]
    pub blocklist_sync_path: String,
    #[serde(default = "default_blocklist_delete_path")]
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
        Self::Minimal
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub layer: RuleLayer,
    pub pattern: String,
    pub action: RuleAction,
    pub severity: Severity,
    #[serde(default)]
    pub plugin_template_id: Option<String>,
    #[serde(default)]
    pub response_template: Option<RuleResponseTemplate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResponseTemplate {
    pub status_code: u16,
    #[serde(default = "default_rule_response_content_type")]
    pub content_type: String,
    #[serde(default)]
    pub body_source: RuleResponseBodySource,
    #[serde(default)]
    pub gzip: bool,
    #[serde(default)]
    pub body_text: String,
    #[serde(default)]
    pub body_file_path: String,
    #[serde(default)]
    pub headers: Vec<RuleResponseHeader>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleResponseHeader {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleResponseBodySource {
    #[default]
    InlineText,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleLayer {
    L4,
    L7,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Block,
    Alert,
    Respond,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl RuleLayer {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::L4 => "l4",
            Self::L7 => "l7",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "l4" => Ok(Self::L4),
            "l7" => Ok(Self::L7),
            other => Err(format!("Unsupported rule layer '{}'", other)),
        }
    }
}

impl RuleAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::Alert => "alert",
            Self::Respond => "respond",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "allow" => Ok(Self::Allow),
            "block" => Ok(Self::Block),
            "alert" => Ok(Self::Alert),
            "respond" => Ok(Self::Respond),
            other => Err(format!("Unsupported rule action '{}'", other)),
        }
    }
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(format!("Unsupported rule severity '{}'", other)),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            interface: "eth0".to_string(),
            listen_addrs: vec!["0.0.0.0:8080".to_string()],
            tcp_upstream_addr: None,
            udp_upstream_addr: None,
            runtime_profile: RuntimeProfile::Minimal,
            api_enabled: false,
            api_bind: "127.0.0.1:3000".to_string(),
            bloom_enabled: false,
            l4_bloom_false_positive_verification: false,
            l7_bloom_false_positive_verification: false,
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
            sqlite_rules_enabled: false,
            max_concurrent_tasks: 0,
            console_settings: ConsoleSettings::default(),
            integrations: IntegrationsConfig::default(),
        }
        .normalized()
    }
}

fn default_rule_response_content_type() -> String {
    "text/plain; charset=utf-8".to_string()
}

impl Config {
    pub fn normalized(mut self) -> Self {
        if self.sqlite_path.trim().is_empty() {
            self.sqlite_path = default_sqlite_path();
        }

        if !self.sqlite_enabled {
            self.sqlite_rules_enabled = false;
        } else {
            self.sqlite_auto_migrate = true;
        }

        // 确保至少有一个监听地址
        if self.listen_addrs.is_empty() {
            self.listen_addrs = vec!["0.0.0.0:8080".to_string()];
        }

        self.udp_upstream_addr = self.udp_upstream_addr.take().and_then(|addr| {
            let trimmed = addr.trim();
            if trimmed.is_empty() {
                None
            } else {
                match trimmed.parse::<SocketAddr>() {
                    Ok(_) => Some(trimmed.to_string()),
                    Err(err) => {
                        log::warn!(
                            "Invalid udp_upstream_addr '{}': {}, disabling UDP forwarding",
                            trimmed,
                            err
                        );
                        None
                    }
                }
            }
        });

        self.tcp_upstream_addr = self.tcp_upstream_addr.take().and_then(|addr| {
            let trimmed = addr.trim();
            if trimmed.is_empty() {
                None
            } else {
                match trimmed.parse::<SocketAddr>() {
                    Ok(_) => Some(trimmed.to_string()),
                    Err(err) => {
                        log::warn!(
                            "Invalid tcp_upstream_addr '{}': {}, disabling TCP forwarding",
                            trimmed,
                            err
                        );
                        None
                    }
                }
            }
        });

        // 多端口配置需要标准模式
        if self.listen_addrs.len() > 1 && self.runtime_profile.is_minimal() {
            log::info!("Multiple listen addresses detected, upgrading to Standard profile");
            self.runtime_profile = RuntimeProfile::Standard;
        }

        if self.runtime_profile.is_minimal() {
            self.api_enabled = false;
            self.bloom_enabled = false;
            self.l4_bloom_false_positive_verification = false;
            self.l7_bloom_false_positive_verification = false;
            self.l4_config.advanced_ddos_enabled = false;
            self.l4_config.connection_rate_limit = self.l4_config.connection_rate_limit.min(64);
            self.l4_config.syn_flood_threshold = self.l4_config.syn_flood_threshold.min(32);
            self.l4_config.max_tracked_ips =
                clamp_or_default(self.l4_config.max_tracked_ips, 512).min(1024);
            self.l4_config.max_blocked_ips =
                clamp_or_default(self.l4_config.max_blocked_ips, 128).min(256);
            self.l4_config.state_ttl_secs = clamp_u64(self.l4_config.state_ttl_secs, 60, 1800, 180);
            self.l7_config.max_request_size =
                clamp_or_default(self.l7_config.max_request_size, 4096);
            self.l7_config.first_byte_timeout_ms =
                clamp_u64(self.l7_config.first_byte_timeout_ms, 250, 10_000, 2_000);
            self.l7_config.read_idle_timeout_ms =
                clamp_u64(self.l7_config.read_idle_timeout_ms, 500, 15_000, 5_000);
            self.l7_config.tls_handshake_timeout_ms =
                clamp_u64(self.l7_config.tls_handshake_timeout_ms, 500, 10_000, 3_000);
            self.l7_config.proxy_connect_timeout_ms =
                clamp_u64(self.l7_config.proxy_connect_timeout_ms, 250, 10_000, 1_500);
            self.l7_config.proxy_write_timeout_ms =
                clamp_u64(self.l7_config.proxy_write_timeout_ms, 500, 15_000, 3_000);
            self.l7_config.proxy_read_timeout_ms =
                clamp_u64(self.l7_config.proxy_read_timeout_ms, 500, 30_000, 10_000);
            self.l7_config.upstream_healthcheck_interval_secs =
                clamp_u64(self.l7_config.upstream_healthcheck_interval_secs, 1, 60, 5);
            self.l7_config.upstream_healthcheck_timeout_ms = clamp_u64(
                self.l7_config.upstream_healthcheck_timeout_ms,
                250,
                10_000,
                1_000,
            );
            self.l4_config.bloom_filter_scale =
                clamp_scale(self.l4_config.bloom_filter_scale, 0.5, 0.1, 1.0);
            self.l7_config.bloom_filter_scale =
                clamp_scale(self.l7_config.bloom_filter_scale, 0.5, 0.1, 1.0);
        } else {
            self.l4_config.max_tracked_ips = clamp_or_default(self.l4_config.max_tracked_ips, 4096);
            self.l4_config.max_blocked_ips = clamp_or_default(self.l4_config.max_blocked_ips, 1024);
            self.l4_config.state_ttl_secs = clamp_u64(self.l4_config.state_ttl_secs, 60, 3600, 300);
            self.l7_config.max_request_size =
                clamp_or_default(self.l7_config.max_request_size, 8192);
            self.l7_config.first_byte_timeout_ms =
                clamp_u64(self.l7_config.first_byte_timeout_ms, 250, 30_000, 2_000);
            self.l7_config.read_idle_timeout_ms =
                clamp_u64(self.l7_config.read_idle_timeout_ms, 500, 30_000, 5_000);
            self.l7_config.tls_handshake_timeout_ms =
                clamp_u64(self.l7_config.tls_handshake_timeout_ms, 500, 15_000, 3_000);
            self.l7_config.proxy_connect_timeout_ms =
                clamp_u64(self.l7_config.proxy_connect_timeout_ms, 250, 15_000, 1_500);
            self.l7_config.proxy_write_timeout_ms =
                clamp_u64(self.l7_config.proxy_write_timeout_ms, 500, 30_000, 3_000);
            self.l7_config.proxy_read_timeout_ms =
                clamp_u64(self.l7_config.proxy_read_timeout_ms, 500, 60_000, 10_000);
            self.l7_config.upstream_healthcheck_interval_secs =
                clamp_u64(self.l7_config.upstream_healthcheck_interval_secs, 1, 120, 5);
            self.l7_config.upstream_healthcheck_timeout_ms = clamp_u64(
                self.l7_config.upstream_healthcheck_timeout_ms,
                250,
                15_000,
                1_000,
            );
            self.l4_config.bloom_filter_scale =
                clamp_scale(self.l4_config.bloom_filter_scale, 1.0, 0.25, 1.0);
            self.l7_config.bloom_filter_scale =
                clamp_scale(self.l7_config.bloom_filter_scale, 1.0, 0.25, 1.0);
        }

        self.l7_config.real_ip_headers = self
            .l7_config
            .real_ip_headers
            .iter()
            .map(|header| header.trim().to_ascii_lowercase())
            .filter(|header| !header.is_empty())
            .collect();
        if self.l7_config.real_ip_headers.is_empty() {
            self.l7_config.real_ip_headers = l7::default_real_ip_headers();
        }

        self.l7_config.trusted_proxy_cidrs = self
            .l7_config
            .trusted_proxy_cidrs
            .iter()
            .map(|cidr| cidr.trim().to_string())
            .filter(|cidr| !cidr.is_empty())
            .collect();

        if !self.bloom_enabled {
            self.l4_bloom_false_positive_verification = false;
            self.l7_bloom_false_positive_verification = false;
        }

        // 验证HTTP/3.0配置
        if let Err(e) = self.http3_config.validate() {
            log::warn!(
                "HTTP/3.0 configuration validation failed: {}, using defaults",
                e
            );
            self.http3_config = Http3Config::default();
        }

        if self.runtime_profile.is_minimal() {
            self.maintenance_interval_secs = clamp_u64(self.maintenance_interval_secs, 30, 300, 60);
        } else {
            self.maintenance_interval_secs = clamp_u64(self.maintenance_interval_secs, 5, 180, 30);
        }

        if self.max_concurrent_tasks == 0 {
            self.max_concurrent_tasks = if self.runtime_profile.is_minimal() {
                128
            } else {
                512
            };
        }

        let (min_concurrency, max_concurrency) = if self.runtime_profile.is_minimal() {
            (32usize, 256usize)
        } else {
            (128usize, 1024usize)
        };
        self.max_concurrent_tasks = self
            .max_concurrent_tasks
            .clamp(min_concurrency, max_concurrency);

        self.console_settings.gateway_name = self.console_settings.gateway_name.trim().to_string();
        if self.console_settings.gateway_name.is_empty() {
            self.console_settings.gateway_name = default_gateway_name();
        }
        self.console_settings.auto_refresh_seconds =
            self.console_settings.auto_refresh_seconds.clamp(3, 60);
        self.console_settings.notification_level =
            normalize_notification_level(&self.console_settings.notification_level);
        self.console_settings.retain_days = self.console_settings.retain_days.clamp(1, 365);
        self.console_settings.notes = self.console_settings.notes.trim().to_string();
        self.gateway_config.https_listen_addr =
            self.gateway_config.https_listen_addr.trim().to_string();
        if self.gateway_config.default_certificate_id == Some(0) {
            self.gateway_config.default_certificate_id = None;
        }

        self.integrations.safeline.base_url =
            normalize_base_url(&self.integrations.safeline.base_url);
        self.integrations.safeline.auto_sync_interval_secs = clamp_u64(
            self.integrations.safeline.auto_sync_interval_secs,
            15,
            86_400,
            default_safeline_auto_sync_interval_secs(),
        );
        self.integrations.safeline.api_token =
            self.integrations.safeline.api_token.trim().to_string();
        self.integrations.safeline.username =
            self.integrations.safeline.username.trim().to_string();
        self.integrations.safeline.password =
            self.integrations.safeline.password.trim().to_string();
        self.integrations.safeline.openapi_doc_path = normalize_path(
            &self.integrations.safeline.openapi_doc_path,
            "/openapi_doc/",
        );
        self.integrations.safeline.auth_probe_path = normalize_path(
            &self.integrations.safeline.auth_probe_path,
            "/api/IPGroupAPI",
        );
        self.integrations.safeline.site_list_path = normalize_path(
            &self.integrations.safeline.site_list_path,
            "/api/WebsiteAPI",
        );
        self.integrations.safeline.event_list_path = normalize_path(
            &self.integrations.safeline.event_list_path,
            "/api/AttackLogAPI",
        );
        self.integrations.safeline.blocklist_sync_path = normalize_path(
            &self.integrations.safeline.blocklist_sync_path,
            "/api/IPGroupAPI",
        );
        self.integrations.safeline.blocklist_delete_path = normalize_path(
            &self.integrations.safeline.blocklist_delete_path,
            "/api/IPGroupAPI",
        );
        self.integrations.safeline.blocklist_ip_group_ids =
            normalize_string_list(&self.integrations.safeline.blocklist_ip_group_ids);

        self
    }
}

impl Default for ConsoleSettings {
    fn default() -> Self {
        Self {
            gateway_name: default_gateway_name(),
            auto_refresh_seconds: default_auto_refresh_seconds(),
            emergency_mode: false,
            notification_level: default_notification_level(),
            retain_days: default_retain_days(),
            notes: String::new(),
        }
    }
}

impl Default for SafeLineConfig {
    fn default() -> Self {
        Self {
            enabled: default_safeline_enabled(),
            auto_sync_events: false,
            auto_sync_blocked_ips_push: false,
            auto_sync_blocked_ips_pull: false,
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

fn clamp_or_default(value: usize, default: usize) -> usize {
    if value == 0 {
        default
    } else {
        value
    }
}

fn clamp_u64(value: u64, min: u64, max: u64, default: u64) -> u64 {
    let value = if value == 0 { default } else { value };
    value.clamp(min, max)
}

fn clamp_scale(value: f64, default: f64, min: f64, max: f64) -> f64 {
    let initial = if value == 0.0 { default } else { value };
    initial.clamp(min, max)
}

fn default_gateway_name() -> String {
    "玄枢防护网关".to_string()
}

const fn default_auto_refresh_seconds() -> u32 {
    5
}

const fn default_sqlite_enabled() -> bool {
    true
}

fn default_notification_level() -> String {
    "critical".to_string()
}

const fn default_safeline_enabled() -> bool {
    true
}

const fn default_retain_days() -> u32 {
    30
}

const fn default_verify_tls() -> bool {
    false
}

fn default_openapi_doc_path() -> String {
    "/openapi_doc/".to_string()
}

fn default_auth_probe_path() -> String {
    "/api/open/system/key".to_string()
}

fn default_site_list_path() -> String {
    "/api/open/site".to_string()
}

fn default_event_list_path() -> String {
    "/api/open/records".to_string()
}

fn default_blocklist_sync_path() -> String {
    "/api/open/ipgroup".to_string()
}

fn default_blocklist_delete_path() -> String {
    "/api/open/ipgroup".to_string()
}

const fn default_safeline_auto_sync_interval_secs() -> u64 {
    300
}

fn normalize_notification_level(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "all" => "all".to_string(),
        "blocked_only" => "blocked_only".to_string(),
        _ => "critical".to_string(),
    }
}

fn normalize_base_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
}

fn normalize_path(value: &str, default: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return default.to_string();
    }
    if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn normalize_string_list(values: &[String]) -> Vec<String> {
    let mut normalized = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        if normalized.iter().any(|item| item == trimmed) {
            continue;
        }
        normalized.push(trimmed.to_string());
    }
    normalized
}

pub fn resolve_sqlite_path() -> String {
    env::var("WAF_SQLITE_PATH").unwrap_or_else(|_| default_sqlite_path())
}

pub fn apply_env_overrides(mut config: Config) -> Config {
    if let Ok(value) = env::var("WAF_RUNTIME_PROFILE") {
        match value.trim().to_ascii_lowercase().as_str() {
            "minimal" => config.runtime_profile = RuntimeProfile::Minimal,
            "standard" => config.runtime_profile = RuntimeProfile::Standard,
            other => log::warn!(
                "Unsupported WAF_RUNTIME_PROFILE '{}', keeping SQLite value",
                other
            ),
        }
    }

    if let Ok(value) = env::var("WAF_API_ENABLED") {
        if let Some(parsed) = parse_bool_env(&value) {
            config.api_enabled = parsed;
        } else {
            log::warn!(
                "Unsupported WAF_API_ENABLED '{}', keeping SQLite value",
                value
            );
        }
    }

    if let Ok(value) = env::var("WAF_API_BIND") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            config.api_bind = trimmed.to_string();
        }
    }

    if let Ok(value) = env::var("WAF_LISTEN_ADDRS") {
        let addrs = value
            .split(',')
            .map(|addr| addr.trim().to_string())
            .filter(|addr| !addr.is_empty())
            .collect::<Vec<_>>();
        if !addrs.is_empty() {
            config.listen_addrs = addrs;
        }
    }

    if let Ok(value) = env::var("WAF_TCP_UPSTREAM_ADDR") {
        config.tcp_upstream_addr = non_empty_env(value);
    }

    if let Ok(value) = env::var("WAF_UDP_UPSTREAM_ADDR") {
        config.udp_upstream_addr = non_empty_env(value);
    }

    if let Ok(value) = env::var("WAF_SQLITE_RULES_ENABLED") {
        if let Some(parsed) = parse_bool_env(&value) {
            config.sqlite_rules_enabled = parsed;
        } else {
            log::warn!(
                "Unsupported WAF_SQLITE_RULES_ENABLED '{}', keeping SQLite value",
                value
            );
        }
    }

    config
}

fn parse_bool_env(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn non_empty_env(value: String) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn default_sqlite_path() -> String {
    "data/waf.db".to_string()
}

const fn default_sqlite_auto_migrate() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_strips_empty_udp_upstream_addr() {
        let config = Config {
            udp_upstream_addr: Some("   ".to_string()),
            ..Config::default()
        }
        .normalized();

        assert!(config.udp_upstream_addr.is_none());
    }

    #[test]
    fn normalized_drops_invalid_udp_upstream_addr() {
        let config = Config {
            udp_upstream_addr: Some("not-an-addr".to_string()),
            ..Config::default()
        }
        .normalized();

        assert!(config.udp_upstream_addr.is_none());
    }

    #[test]
    fn normalized_drops_invalid_tcp_upstream_addr() {
        let config = Config {
            tcp_upstream_addr: Some("not-an-addr".to_string()),
            ..Config::default()
        }
        .normalized();

        assert!(config.tcp_upstream_addr.is_none());
    }

    #[test]
    fn normalized_cleans_real_ip_headers_and_trusted_proxy_cidrs() {
        let config = Config {
            l7_config: L7Config {
                real_ip_headers: vec![
                    " X-Forwarded-For ".to_string(),
                    "".to_string(),
                    "CF-Connecting-IP".to_string(),
                ],
                trusted_proxy_cidrs: vec![
                    " 203.0.113.0/24 ".to_string(),
                    "".to_string(),
                    "198.51.100.10/32".to_string(),
                ],
                ..L7Config::default()
            },
            ..Config::default()
        }
        .normalized();

        assert_eq!(
            config.l7_config.real_ip_headers,
            vec![
                "x-forwarded-for".to_string(),
                "cf-connecting-ip".to_string()
            ]
        );
        assert_eq!(
            config.l7_config.trusted_proxy_cidrs,
            vec!["203.0.113.0/24".to_string(), "198.51.100.10/32".to_string()]
        );
    }
}
