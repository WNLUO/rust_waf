#[cfg(feature = "api")]
mod api;
mod bloom_filter;
mod config;
mod core;
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
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("Starting WAF system...");

    // Initialize configuration
    let config = config::load_config()?;
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
