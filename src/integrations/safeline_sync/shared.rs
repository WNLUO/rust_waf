use super::*;

pub(super) fn ensure_enabled(config: &SafeLineConfig) -> Result<()> {
    if !config.enabled {
        bail!("雷池集成尚未启用");
    }
    Ok(())
}

pub(super) fn apply_safeline_mapping(
    event: crate::integrations::safeline::SafeLineSecurityEventSummary,
    mappings: &[crate::storage::SafeLineSiteMappingEntry],
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

fn matches_mapping(
    record: &SecurityEventRecord,
    mapping: &crate::storage::SafeLineSiteMappingEntry,
) -> bool {
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

pub(super) fn parse_json_vec(value: &str) -> Result<Vec<String>> {
    Ok(serde_json::from_str::<Vec<String>>(value)?)
}

pub(super) fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
