use anyhow::Result;
use env_logger::Env;
use log::info;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let _ = dotenvy::dotenv();
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    info!("Starting WAF system...");
    waf::run().await
}
