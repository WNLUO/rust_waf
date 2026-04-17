use crate::config::{Config, Rule};
use crate::rules::RuleEngine;
use crate::storage::SqliteStore;
use anyhow::Result;
use log::{info, warn};

pub(super) async fn load_rule_engine_state(
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

pub(super) fn compile_rule_engine(rules: Vec<Rule>) -> Result<Option<RuleEngine>> {
    if rules.is_empty() {
        Ok(None)
    } else {
        Ok(Some(RuleEngine::new(rules)?))
    }
}
