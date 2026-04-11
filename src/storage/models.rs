use anyhow::Result;

use crate::config::{Config, Rule, RuleAction, RuleLayer, RuleResponseTemplate, Severity};

use super::unix_timestamp;

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RuleActionPluginEntry {
    pub plugin_id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub enabled: bool,
    pub installed_at: i64,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RuleActionTemplateEntry {
    pub template_id: String,
    pub plugin_id: String,
    pub name: String,
    pub description: String,
    pub layer: String,
    pub action: String,
    pub pattern: String,
    pub severity: String,
    pub response_template_json: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct RuleActionPluginUpsert {
    pub plugin_id: String,
    pub name: String,
    pub version: String,
    pub description: String,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
pub struct RuleActionTemplateUpsert {
    pub template_id: String,
    pub plugin_id: String,
    pub name: String,
    pub description: String,
    pub layer: String,
    pub action: String,
    pub pattern: String,
    pub severity: String,
    pub response_template: RuleResponseTemplate,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SecurityEventEntry {
    pub id: i64,
    pub layer: String,
    pub provider: Option<String>,
    pub provider_event_id: Option<String>,
    pub provider_site_id: Option<String>,
    pub provider_site_name: Option<String>,
    pub provider_site_domain: Option<String>,
    pub action: String,
    pub reason: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: i64,
    pub dest_port: i64,
    pub protocol: String,
    pub http_method: Option<String>,
    pub uri: Option<String>,
    pub http_version: Option<String>,
    pub created_at: i64,
    pub handled: bool,
    pub handled_at: Option<i64>,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct BlockedIpEntry {
    pub id: i64,
    pub provider: Option<String>,
    pub provider_remote_id: Option<String>,
    pub ip: String,
    pub reason: String,
    pub blocked_at: i64,
    pub expires_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SafeLineSiteMappingEntry {
    pub id: i64,
    pub safeline_site_id: String,
    pub safeline_site_name: String,
    pub safeline_site_domain: String,
    pub local_alias: String,
    pub enabled: bool,
    pub is_primary: bool,
    pub notes: String,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SafeLineCachedSiteEntry {
    pub remote_site_id: String,
    pub name: String,
    pub domain: String,
    pub status: String,
    pub enabled: Option<bool>,
    pub server_names_json: String,
    pub ports_json: String,
    pub ssl_ports_json: String,
    pub upstreams_json: String,
    pub ssl_enabled: bool,
    pub cert_id: Option<i64>,
    pub cert_type: Option<i64>,
    pub cert_filename: Option<String>,
    pub key_filename: Option<String>,
    pub health_check: Option<bool>,
    pub raw_json: String,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LocalSiteEntry {
    pub id: i64,
    pub name: String,
    pub primary_hostname: String,
    pub hostnames_json: String,
    pub listen_ports_json: String,
    pub upstreams_json: String,
    pub enabled: bool,
    pub tls_enabled: bool,
    pub local_certificate_id: Option<i64>,
    pub source: String,
    pub sync_mode: String,
    pub notes: String,
    pub last_synced_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LocalCertificateEntry {
    pub id: i64,
    pub name: String,
    pub domains_json: String,
    pub issuer: String,
    pub valid_from: Option<i64>,
    pub valid_to: Option<i64>,
    pub source_type: String,
    pub provider_remote_id: Option<String>,
    pub trusted: bool,
    pub expired: bool,
    pub notes: String,
    pub last_synced_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct LocalCertificateSecretEntry {
    pub certificate_id: i64,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SiteSyncLinkEntry {
    pub id: i64,
    pub local_site_id: i64,
    pub provider: String,
    pub remote_site_id: String,
    pub remote_site_name: String,
    pub remote_cert_id: Option<String>,
    pub sync_mode: String,
    pub last_local_hash: Option<String>,
    pub last_remote_hash: Option<String>,
    pub last_error: Option<String>,
    pub last_synced_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[cfg_attr(not(feature = "api"), allow(dead_code))]
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SafeLineSyncStateEntry {
    pub resource: String,
    pub last_cursor: Option<i64>,
    pub last_success_at: Option<i64>,
    pub last_imported_count: i64,
    pub last_skipped_count: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineBlocklistSyncResult {
    pub synced: usize,
    pub skipped: usize,
    pub failed: usize,
    pub last_cursor: Option<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct SafeLineBlocklistPullResult {
    pub imported: usize,
    pub skipped: usize,
    pub last_cursor: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct SecurityEventRecord {
    pub layer: String,
    pub provider: Option<String>,
    pub provider_event_id: Option<String>,
    pub provider_site_id: Option<String>,
    pub provider_site_name: Option<String>,
    pub provider_site_domain: Option<String>,
    pub action: String,
    pub reason: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: i64,
    pub dest_port: i64,
    pub protocol: String,
    pub http_method: Option<String>,
    pub uri: Option<String>,
    pub http_version: Option<String>,
    pub created_at: i64,
    pub handled: bool,
    pub handled_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct BlockedIpRecord {
    pub provider: Option<String>,
    pub provider_remote_id: Option<String>,
    pub ip: String,
    pub reason: String,
    pub blocked_at: i64,
    pub expires_at: i64,
}

#[derive(sqlx::FromRow)]
pub(super) struct StoredRuleRow {
    pub(super) id: String,
    pub(super) name: String,
    pub(super) enabled: bool,
    pub(super) layer: String,
    pub(super) pattern: String,
    pub(super) action: String,
    pub(super) severity: String,
    pub(super) plugin_template_id: Option<String>,
    pub(super) response_template_json: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(super) struct StoredAppConfigRow {
    pub(super) config_json: String,
}

impl SecurityEventRecord {
    pub fn now(
        layer: impl Into<String>,
        action: impl Into<String>,
        reason: impl Into<String>,
        source_ip: impl Into<String>,
        dest_ip: impl Into<String>,
        source_port: u16,
        dest_port: u16,
        protocol: impl Into<String>,
    ) -> Self {
        Self {
            layer: layer.into(),
            provider: None,
            provider_event_id: None,
            provider_site_id: None,
            provider_site_name: None,
            provider_site_domain: None,
            action: action.into(),
            reason: reason.into(),
            source_ip: source_ip.into(),
            dest_ip: dest_ip.into(),
            source_port: i64::from(source_port),
            dest_port: i64::from(dest_port),
            protocol: protocol.into(),
            http_method: None,
            uri: None,
            http_version: None,
            created_at: unix_timestamp(),
            handled: false,
            handled_at: None,
        }
    }
}

impl BlockedIpRecord {
    pub fn new(
        ip: impl Into<String>,
        reason: impl Into<String>,
        blocked_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            provider: None,
            provider_remote_id: None,
            ip: ip.into(),
            reason: reason.into(),
            blocked_at,
            expires_at,
        }
    }
}

impl TryFrom<StoredRuleRow> for Rule {
    type Error = anyhow::Error;

    fn try_from(value: StoredRuleRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            name: value.name,
            enabled: value.enabled,
            layer: parse_rule_layer(&value.layer)?,
            pattern: value.pattern,
            action: parse_rule_action(&value.action)?,
            severity: parse_severity(&value.severity)?,
            plugin_template_id: value.plugin_template_id,
            response_template: deserialize_rule_response_template(
                value.response_template_json.as_deref(),
            )?,
        })
    }
}

pub(super) fn serialize_rule_response_template(
    template: Option<&RuleResponseTemplate>,
) -> Result<Option<String>> {
    template
        .map(serde_json::to_string)
        .transpose()
        .map_err(Into::into)
}

pub(super) fn deserialize_rule_response_template(
    value: Option<&str>,
) -> Result<Option<RuleResponseTemplate>> {
    value
        .filter(|raw| !raw.trim().is_empty())
        .map(serde_json::from_str::<RuleResponseTemplate>)
        .transpose()
        .map_err(Into::into)
}

impl TryFrom<StoredAppConfigRow> for Config {
    type Error = anyhow::Error;

    fn try_from(value: StoredAppConfigRow) -> Result<Self, Self::Error> {
        Ok(serde_json::from_str::<Config>(&value.config_json)?.normalized())
    }
}

pub(super) fn parse_rule_layer(value: &str) -> Result<RuleLayer> {
    RuleLayer::parse(value).map_err(anyhow::Error::msg)
}

pub(super) fn parse_rule_action(value: &str) -> Result<RuleAction> {
    RuleAction::parse(value).map_err(anyhow::Error::msg)
}

pub(super) fn parse_severity(value: &str) -> Result<Severity> {
    Severity::parse(value).map_err(anyhow::Error::msg)
}
