use super::*;

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

