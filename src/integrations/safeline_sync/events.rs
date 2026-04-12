use super::*;

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
