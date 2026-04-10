#[cfg(feature = "api")]
mod api;
mod bloom_filter;
mod config;
mod core;
mod integrations;
mod l4;
mod l7;
mod metrics;
mod protocol;
mod rules;
mod storage;
mod tls;

use anyhow::Result;
use env_logger::Env;
use log::info;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("Starting WAF system...");

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
    config = config::apply_env_overrides(config);
    let config = config.normalized();
    info!(
        "Loaded configuration: profile={:?}, api_enabled={}, bloom_enabled={}, l4_bloom_fp_verification={}, l7_bloom_fp_verification={}",
        config.runtime_profile,
        config.api_enabled,
        config.bloom_enabled,
        config.l4_bloom_false_positive_verification,
        config.l7_bloom_false_positive_verification
    );

    // Initialize core WAF engine
    let mut waf_engine = core::WafEngine::new(config).await?;

    // Start the engine
    waf_engine.start().await?;

    Ok(())
}
