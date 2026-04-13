use super::*;

pub(super) fn ensure_enabled(config: &SafeLineConfig) -> Result<()> {
    if !config.enabled {
        bail!("雷池集成尚未启用");
    }
    Ok(())
}

pub(crate) fn is_configured(config: &SafeLineConfig) -> bool {
    let has_base_url = !config.base_url.trim().is_empty();
    let has_token = !config.api_token.trim().is_empty();
    let has_user_password =
        !config.username.trim().is_empty() && !config.password.trim().is_empty();

    has_base_url && (has_token || has_user_password)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safeline_configuration_requires_base_url_and_auth() {
        let mut config = SafeLineConfig::default();
        assert!(!is_configured(&config));

        config.enabled = true;
        config.base_url = "https://safeline.example.com".to_string();
        assert!(!is_configured(&config));

        config.api_token = "token".to_string();
        assert!(is_configured(&config));
    }
}
