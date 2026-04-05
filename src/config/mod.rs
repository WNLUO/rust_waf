use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub mod http3;
pub mod l4;
pub mod l7;

pub use http3::Http3Config;
pub use l4::L4Config;
pub use l7::L7Config;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub interface: String,
    pub listen_addrs: Vec<String>,
    pub runtime_profile: RuntimeProfile,
    pub api_enabled: bool,
    pub api_bind: String,
    pub bloom_enabled: bool,
    pub l4_bloom_false_positive_verification: bool,
    pub l7_bloom_false_positive_verification: bool,
    pub maintenance_interval_secs: u64,
    pub l4_config: L4Config,
    pub l7_config: L7Config,
    pub http3_config: Http3Config,
    pub rules: Vec<Rule>,
    pub metrics_enabled: bool,
    #[serde(default)]
    pub sqlite_enabled: bool,
    #[serde(default = "default_sqlite_path")]
    pub sqlite_path: String,
    #[serde(default = "default_sqlite_auto_migrate")]
    pub sqlite_auto_migrate: bool,
    #[serde(default)]
    pub sqlite_rules_enabled: bool,
    #[serde(default)]
    pub max_concurrent_tasks: usize,
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
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "allow" => Ok(Self::Allow),
            "block" => Ok(Self::Block),
            "alert" => Ok(Self::Alert),
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
            runtime_profile: RuntimeProfile::Minimal,
            api_enabled: false,
            api_bind: "127.0.0.1:3000".to_string(),
            bloom_enabled: false,
            l4_bloom_false_positive_verification: false,
            l7_bloom_false_positive_verification: false,
            maintenance_interval_secs: 30,
            l4_config: L4Config::default(),
            l7_config: L7Config::default(),
            http3_config: Http3Config::default(),
            rules: vec![],
            metrics_enabled: true,
            sqlite_enabled: false,
            sqlite_path: default_sqlite_path(),
            sqlite_auto_migrate: default_sqlite_auto_migrate(),
            sqlite_rules_enabled: false,
            max_concurrent_tasks: 0,
        }
        .normalized()
    }
}

pub fn load_config() -> Result<Config> {
    if let Some(config_path) = resolve_config_path() {
        let raw = fs::read_to_string(&config_path)?;

        // 向后兼容：先检查是否存在旧的listen_addr字段
        if let Ok(legacy_config) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(listen_addr) = legacy_config.get("listen_addr").and_then(|v| v.as_str()) {
                let listen_addr_string = listen_addr.to_string();
                log::warn!("Legacy configuration detected: 'listen_addr' has been converted to 'listen_addrs' array");

                // 创建新的配置对象，替换listen_addr为listen_addrs
                let mut config_value = legacy_config;
                config_value.as_object_mut().unwrap().remove("listen_addr");
                config_value.as_object_mut().unwrap().insert(
                    "listen_addrs".to_string(),
                    serde_json::json!([listen_addr_string]),
                );

                let config: Config = serde_json::from_value(config_value)?;
                return Ok(config.normalized());
            }
        }

        // 如果不存在旧的字段，正常反序列化
        let config: Config = serde_json::from_str(&raw)?;
        return Ok(config.normalized());
    }

    Ok(Config::default())
}

impl Config {
    pub fn normalized(mut self) -> Self {
        if self.sqlite_path.trim().is_empty() {
            self.sqlite_path = default_sqlite_path();
        }

        if !self.sqlite_enabled {
            self.sqlite_rules_enabled = false;
        }

        // 确保至少有一个监听地址
        if self.listen_addrs.is_empty() {
            self.listen_addrs = vec!["0.0.0.0:8080".to_string()];
        }

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
            self.l4_config.scan_enabled = false;
            self.l4_config.connection_rate_limit = self.l4_config.connection_rate_limit.min(64);
            self.l4_config.syn_flood_threshold = self.l4_config.syn_flood_threshold.min(32);
            self.l4_config.max_tracked_ips =
                clamp_or_default(self.l4_config.max_tracked_ips, 512).min(1024);
            self.l4_config.max_blocked_ips =
                clamp_or_default(self.l4_config.max_blocked_ips, 128).min(256);
            self.l4_config.state_ttl_secs = clamp_u64(self.l4_config.state_ttl_secs, 60, 1800, 180);
            self.l7_config.max_request_size =
                clamp_or_default(self.l7_config.max_request_size, 4096);
            self.l7_config.prefilter_enabled = true;
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
            self.l4_config.bloom_filter_scale =
                clamp_scale(self.l4_config.bloom_filter_scale, 1.0, 0.25, 1.0);
            self.l7_config.bloom_filter_scale =
                clamp_scale(self.l7_config.bloom_filter_scale, 1.0, 0.25, 1.0);
        }

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

        self
    }
}

fn resolve_config_path() -> Option<PathBuf> {
    if let Some(path) = env::var_os("WAF_CONFIG") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }

    [
        Path::new("config/waf.json"),
        Path::new("config/minimal.json"),
        Path::new("waf.json"),
    ]
    .into_iter()
    .find(|path| path.is_file())
    .map(Path::to_path_buf)
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

fn default_sqlite_path() -> String {
    "data/waf.db".to_string()
}

const fn default_sqlite_auto_migrate() -> bool {
    true
}
