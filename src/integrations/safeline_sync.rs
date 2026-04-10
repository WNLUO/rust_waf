use crate::config::SafeLineConfig;
use crate::storage::{
    BlockedIpQuery, BlockedIpRecord, SafeLineBlocklistPullResult, SafeLineBlocklistSyncResult,
    SafeLineImportResult, SafeLineSiteMappingEntry, SecurityEventRecord, SqliteStore,
};
use anyhow::{bail, Result};

pub async fn sync_events(
    store: &SqliteStore,
    config: &SafeLineConfig,
) -> Result<SafeLineImportResult> {
    ensure_enabled(config)?;

    let mappings = store.list_safeline_site_mappings().await?;
    let events = crate::integrations::safeline::list_security_events(config).await?;
    let records = events
        .into_iter()
        .map(|event| apply_safeline_mapping(event, &mappings))
        .collect::<Vec<_>>();

    store.import_safeline_security_events(&records).await
}

pub async fn push_blocked_ips(
    store: &SqliteStore,
    config: &SafeLineConfig,
) -> Result<SafeLineBlocklistSyncResult> {
    ensure_enabled(config)?;

    let blocked = store
        .list_blocked_ips(&BlockedIpQuery {
            limit: 200,
            active_only: true,
            ..BlockedIpQuery::default()
        })
        .await?;

    let mut accepted = Vec::new();
    let mut failed = 0usize;

    for record in &blocked.items {
        let result = crate::integrations::safeline::push_blocked_ip(config, record).await?;
        if result.accepted {
            accepted.push(record.clone());
        } else {
            failed += 1;
        }
    }

    store
        .import_safeline_blocked_ips_sync_result(&accepted, failed)
        .await
}

pub async fn pull_blocked_ips(
    store: &SqliteStore,
    config: &SafeLineConfig,
) -> Result<SafeLineBlocklistPullResult> {
    ensure_enabled(config)?;

    let records = crate::integrations::safeline::list_blocked_ips(config)
        .await?
        .into_iter()
        .map(BlockedIpRecord::from)
        .collect::<Vec<_>>();

    store.import_safeline_blocked_ips_pull(&records).await
}

fn ensure_enabled(config: &SafeLineConfig) -> Result<()> {
    if !config.enabled {
        bail!("雷池集成尚未启用");
    }
    Ok(())
}

fn apply_safeline_mapping(
    event: crate::integrations::safeline::SafeLineSecurityEventSummary,
    mappings: &[SafeLineSiteMappingEntry],
) -> SecurityEventRecord {
    let mut record = SecurityEventRecord::from(event);

    if let Some(mapping) = mappings
        .iter()
        .find(|mapping| matches_mapping(&record, mapping))
    {
        record.provider_site_id = Some(mapping.safeline_site_id.clone());
        record.provider_site_name = Some(mapping.local_alias.clone());
        record.provider_site_domain = Some(mapping.safeline_site_domain.clone());
    }

    record
}

fn matches_mapping(record: &SecurityEventRecord, mapping: &SafeLineSiteMappingEntry) -> bool {
    record
        .provider_site_id
        .as_deref()
        .map(|value| value == mapping.safeline_site_id)
        .unwrap_or(false)
        || record
            .provider_site_domain
            .as_deref()
            .map(|value| !value.is_empty() && value == mapping.safeline_site_domain)
            .unwrap_or(false)
        || record
            .provider_site_name
            .as_deref()
            .map(|value| !value.is_empty() && value == mapping.safeline_site_name)
            .unwrap_or(false)
}
