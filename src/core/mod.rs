pub mod engine;
mod engine_maintenance;
mod engine_tls;
pub mod gateway;
pub mod packet;

use crate::config::Config;
use crate::core::gateway::GatewayRuntime;
use crate::l4::L4Inspector;
use crate::l7::HttpTrafficProcessor;
use crate::metrics::MetricsCollector;
use crate::rules::RuleEngine;
use crate::storage::SqliteStore;
use anyhow::Result;
use log::{info, warn};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

pub use engine::WafEngine;
pub use packet::{
    CustomHttpResponse, InspectionAction, InspectionLayer, InspectionResult, PacketInfo, Protocol,
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
    pub l4_inspector: Option<L4Inspector>,
    pub http_processor: HttpTrafficProcessor,
    pub rule_engine: RwLock<Option<RuleEngine>>,
    pub metrics: Option<MetricsCollector>,
    pub sqlite_store: Option<Arc<SqliteStore>>,
    pub gateway_runtime: GatewayRuntime,
    upstream_health: RwLock<UpstreamHealthSnapshot>,
    http3_runtime: RwLock<Http3RuntimeSnapshot>,
    rule_count: AtomicU64,
    rule_version: AtomicI64,
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
                SqliteStore::new(config.sqlite_path.clone(), config.sqlite_auto_migrate).await?,
            ))
        } else {
            None
        };
        let (rule_engine, rule_count, rule_version) =
            load_rule_engine_state(&config, sqlite_store.as_deref()).await?;
        let gateway_runtime = GatewayRuntime::load(&config, sqlite_store.as_deref()).await?;
        let http_processor = HttpTrafficProcessor::new(&config.l7_config);

        Ok(Self {
            runtime_config: Arc::new(RwLock::new(config.clone())),
            l4_inspector: l4_enabled.then(|| {
                L4Inspector::new(
                    config.l4_config.clone(),
                    bloom_enabled,
                    l4_bloom_verification,
                )
            }),
            http_processor,
            rule_engine: RwLock::new(rule_engine),
            metrics,
            sqlite_store,
            gateway_runtime,
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
        self.refresh_http3_runtime_metadata();
    }

    pub fn metrics_snapshot(&self) -> Option<crate::metrics::MetricsSnapshot> {
        self.metrics.as_ref().map(MetricsCollector::get_stats)
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
            api_bind: "127.0.0.1:3000".to_string(),
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
}
