use super::{rule_engine::compile_rule_engine, unix_timestamp, WafContext};
use crate::l4::L4Inspector;
use crate::storage::SqliteStore;
use anyhow::Result;
use log::{info, warn};
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::Duration;

impl WafContext {
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

    pub async fn shutdown_storage(&self) -> Result<()> {
        if let Some(store) = self.sqlite_store.as_ref() {
            store.shutdown().await?;
        }
        Ok(())
    }

    #[cfg_attr(not(feature = "api"), allow(dead_code))]
    pub fn active_rule_count(&self) -> u64 {
        self.rule_count.load(Ordering::Relaxed)
    }
}

pub(super) async fn restore_runtime_blocked_ips(
    store: &SqliteStore,
    inspector: &L4Inspector,
) -> Result<()> {
    let now = unix_timestamp();
    let blocked_ips = store.list_active_local_blocked_ips().await?;
    let mut restored = 0_u64;
    let mut restored_ips = HashSet::new();

    for entry in blocked_ips {
        let Ok(ip) = entry.ip.parse::<std::net::IpAddr>() else {
            warn!(
                "Skipping blocked IP restore for invalid address '{}' (id={})",
                entry.ip, entry.id
            );
            continue;
        };
        if !restored_ips.insert(ip) {
            continue;
        }
        let remaining_secs = entry.expires_at.saturating_sub(now);
        if remaining_secs == 0 {
            continue;
        }
        if inspector.block_ip(
            &ip,
            &entry.reason,
            Duration::from_secs(remaining_secs as u64),
        ) {
            restored = restored.saturating_add(1);
        }
    }

    if restored > 0 {
        info!(
            "Restored {} active local blocked IP(s) into runtime memory",
            restored
        );
    }

    Ok(())
}
