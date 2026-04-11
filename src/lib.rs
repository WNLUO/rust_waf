// WAF库文件
// 导出公共API用于测试

use anyhow::Result;
use log::info;

pub mod bloom_filter;
pub mod config;
pub mod core;
pub mod integrations;
pub mod l4;
pub mod l7;
pub mod metrics;
pub mod protocol;
pub mod rules;
pub mod storage;
pub mod tls;

#[cfg(feature = "api")]
pub mod api;

// 重新导出常用类型
pub use config::http3::Http3Config;
pub use config::l7::Http2Config;
pub use config::{Config, L7Config, RuntimeProfile};
pub use core::{InspectionLayer, InspectionResult, PacketInfo, Protocol, WafContext, WafEngine};
pub use l7::HttpTrafficProcessor;
pub use protocol::{
    Http1Handler, Http2Handler, Http3Handler, Http3StreamManager, HttpVersion, ProtocolDetector,
    UnifiedHttpRequest,
};
pub use storage::SqliteStore;

pub async fn load_runtime_config() -> Result<Config> {
    let sqlite_path = config::resolve_sqlite_path();
    let bootstrap_store = storage::SqliteStore::new(sqlite_path.clone(), true).await?;

    let mut config = if let Some(config) = bootstrap_store.load_app_config().await? {
        info!("Loaded configuration from SQLite: {}", sqlite_path);
        config
    } else {
        let mut config = config::Config::default();
        config.sqlite_enabled = true;
        config.sqlite_path = sqlite_path.clone();
        config.sqlite_auto_migrate = true;
        bootstrap_store.seed_app_config(&config).await?;
        info!("Seeded default configuration into SQLite: {}", sqlite_path);
        config
    };

    config.sqlite_enabled = true;
    config.sqlite_path = sqlite_path;
    config.sqlite_auto_migrate = true;

    Ok(config::apply_env_overrides(config).normalized())
}

pub async fn build_engine() -> Result<WafEngine> {
    let config = load_runtime_config().await?;
    info!(
        "Loaded configuration: profile={:?}, api_enabled={}, bloom_enabled={}, l4_bloom_fp_verification={}, l7_bloom_fp_verification={}",
        config.runtime_profile,
        config.api_enabled,
        config.bloom_enabled,
        config.l4_bloom_false_positive_verification,
        config.l7_bloom_false_positive_verification
    );

    WafEngine::new(config).await
}

pub async fn run() -> Result<()> {
    let mut waf_engine = build_engine().await?;
    waf_engine.start().await
}
