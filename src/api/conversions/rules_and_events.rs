use super::super::types::*;
use super::super::{
    non_empty_string, parse_blocked_ip_sort_field, parse_event_sort_field, parse_sort_direction,
};
use crate::config::{Rule, RuleResponseBodySource, RuleResponseHeader, RuleResponseTemplate};
use rand::{distributions::Alphanumeric, Rng};
use std::collections::HashSet;

impl From<crate::storage::SafeLineSyncStateEntry> for SafeLineSyncStateResponse {
    fn from(value: crate::storage::SafeLineSyncStateEntry) -> Self {
        Self {
            resource: value.resource,
            last_cursor: value.last_cursor,
            last_success_at: value.last_success_at,
            last_imported_count: value.last_imported_count.max(0) as u32,
            last_skipped_count: value.last_skipped_count.max(0) as u32,
            updated_at: value.updated_at,
        }
    }
}

impl RuleUpsertRequest {
    pub(crate) fn into_rule(self) -> Result<Rule, String> {
        let id = self.id.clone();
        self.into_rule_with_id(id)
    }

    pub(crate) fn into_rule_with_id(self, id: String) -> Result<Rule, String> {
        let id = id.trim().to_string();
        let name = self.name.trim().to_string();
        let pattern = self.pattern.trim().to_string();
        if id.is_empty() {
            return Err("Rule id cannot be empty".to_string());
        }
        if name.is_empty() {
            return Err("Rule name cannot be empty".to_string());
        }
        if pattern.is_empty() {
            return Err("Rule pattern cannot be empty".to_string());
        }

        Ok(Rule {
            id,
            name,
            enabled: self.enabled,
            layer: crate::config::RuleLayer::parse(&self.layer).map_err(|err| err.to_string())?,
            pattern,
            action: crate::config::RuleAction::parse(&self.action)
                .map_err(|err| err.to_string())?,
            severity: crate::config::Severity::parse(&self.severity)
                .map_err(|err| err.to_string())?,
            plugin_template_id: self
                .plugin_template_id
                .filter(|value| !value.trim().is_empty()),
            response_template: self.response_template.map(Into::into),
        })
    }
}

impl RuleResponseTemplatePayload {
    pub(crate) fn from_template(template: RuleResponseTemplate) -> Self {
        Self {
            status_code: template.status_code,
            content_type: template.content_type,
            body_source: match template.body_source {
                RuleResponseBodySource::InlineText => "inline_text".to_string(),
                RuleResponseBodySource::File => "file".to_string(),
            },
            gzip: template.gzip,
            body_text: template.body_text,
            body_file_path: template.body_file_path,
            headers: template
                .headers
                .into_iter()
                .map(RuleResponseHeaderPayload::from)
                .collect(),
        }
    }
}

impl From<RuleResponseTemplatePayload> for RuleResponseTemplate {
    fn from(value: RuleResponseTemplatePayload) -> Self {
        Self {
            status_code: value.status_code,
            content_type: value.content_type.trim().to_string(),
            body_source: parse_rule_response_body_source(&value.body_source),
            gzip: value.gzip,
            body_text: value.body_text,
            body_file_path: value.body_file_path.trim().to_string(),
            headers: value.headers.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<RuleResponseHeader> for RuleResponseHeaderPayload {
    fn from(value: RuleResponseHeader) -> Self {
        Self {
            key: value.key,
            value: value.value,
        }
    }
}

impl From<RuleResponseHeaderPayload> for RuleResponseHeader {
    fn from(value: RuleResponseHeaderPayload) -> Self {
        Self {
            key: value.key.trim().to_string(),
            value: value.value,
        }
    }
}

fn parse_rule_response_body_source(value: &str) -> RuleResponseBodySource {
    match value.trim().to_ascii_lowercase().as_str() {
        "file" => RuleResponseBodySource::File,
        _ => RuleResponseBodySource::InlineText,
    }
}

impl From<Rule> for RuleResponse {
    fn from(rule: Rule) -> Self {
        Self::from_rule(rule)
    }
}

impl From<crate::storage::RuleActionPluginEntry> for RuleActionPluginResponse {
    fn from(value: crate::storage::RuleActionPluginEntry) -> Self {
        Self {
            plugin_id: value.plugin_id,
            name: value.name,
            version: value.version,
            description: value.description,
            enabled: value.enabled,
            installed_at: value.installed_at,
            updated_at: value.updated_at,
        }
    }
}

impl TryFrom<crate::storage::RuleActionTemplateEntry> for RuleActionTemplateResponse {
    type Error = anyhow::Error;

    fn try_from(value: crate::storage::RuleActionTemplateEntry) -> Result<Self, Self::Error> {
        let response_template =
            serde_json::from_str::<RuleResponseTemplate>(&value.response_template_json)?;
        Ok(Self {
            template_id: value.template_id,
            plugin_id: value.plugin_id,
            name: value.name,
            description: value.description,
            layer: value.layer,
            action: value.action,
            pattern: value.pattern,
            severity: value.severity,
            response_template: RuleResponseTemplatePayload::from_template(response_template),
            updated_at: value.updated_at,
        })
    }
}

impl From<crate::storage::SecurityEventEntry> for SecurityEventResponse {
    fn from(event: crate::storage::SecurityEventEntry) -> Self {
        Self {
            id: event.id,
            layer: event.layer,
            provider: event.provider,
            provider_event_id: event.provider_event_id,
            provider_site_id: event.provider_site_id,
            provider_site_name: event.provider_site_name,
            provider_site_domain: event.provider_site_domain,
            action: event.action,
            reason: event.reason,
            details_json: event.details_json,
            source_ip: event.source_ip,
            dest_ip: event.dest_ip,
            source_port: event.source_port,
            dest_port: event.dest_port,
            protocol: event.protocol,
            http_method: event.http_method,
            uri: event.uri,
            http_version: event.http_version,
            created_at: event.created_at,
            handled: event.handled,
            handled_at: event.handled_at,
        }
    }
}

impl From<crate::storage::BlockedIpEntry> for BlockedIpResponse {
    fn from(entry: crate::storage::BlockedIpEntry) -> Self {
        Self {
            id: entry.id,
            provider: entry.provider,
            provider_remote_id: entry.provider_remote_id,
            ip: entry.ip,
            reason: entry.reason,
            blocked_at: entry.blocked_at,
            expires_at: entry.expires_at,
        }
    }
}

impl EventsQueryParams {
    pub(crate) fn into_query(self) -> Result<crate::storage::SecurityEventQuery, String> {
        Ok(crate::storage::SecurityEventQuery {
            limit: self.limit.unwrap_or(50),
            offset: self.offset.unwrap_or(0),
            layer: self.layer,
            provider: self.provider,
            provider_site_id: self.provider_site_id,
            source_ip: self.source_ip,
            action: self.action,
            blocked_only: self.blocked_only.unwrap_or(false),
            handled_only: self.handled_only,
            created_from: self.created_from,
            created_to: self.created_to,
            sort_by: parse_event_sort_field(self.sort_by.as_deref())?,
            sort_direction: parse_sort_direction(self.sort_direction.as_deref())?,
        })
    }
}

impl BlockedIpsQueryParams {
    pub(crate) fn into_query(self) -> Result<crate::storage::BlockedIpQuery, String> {
        Ok(crate::storage::BlockedIpQuery {
            limit: self.limit.unwrap_or(50),
            offset: self.offset.unwrap_or(0),
            source_scope: parse_blocked_ip_source_scope(self.source_scope.as_deref())?,
            provider: self.provider,
            ip: self.ip,
            keyword: normalize_optional_query_value(self.keyword),
            active_only: self.active_only.unwrap_or(false),
            blocked_from: self.blocked_from,
            blocked_to: self.blocked_to,
            sort_by: parse_blocked_ip_sort_field(self.sort_by.as_deref())?,
            sort_direction: parse_sort_direction(self.sort_direction.as_deref())?,
        })
    }
}

fn parse_blocked_ip_source_scope(
    value: Option<&str>,
) -> Result<crate::storage::BlockedIpSourceScope, String> {
    match value.unwrap_or("all").trim().to_ascii_lowercase().as_str() {
        "all" => Ok(crate::storage::BlockedIpSourceScope::All),
        "local" => Ok(crate::storage::BlockedIpSourceScope::Local),
        "remote" => Ok(crate::storage::BlockedIpSourceScope::Remote),
        other => Err(format!("Unsupported blocked IP source_scope '{}'", other)),
    }
}

fn normalize_optional_query_value(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let normalized = value.trim().to_string();
        (!normalized.is_empty()).then_some(normalized)
    })
}

pub(crate) fn default_generated_certificate_name(primary_domain: &str) -> String {
    let random_suffix: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(6)
        .map(char::from)
        .collect();
    format!(
        "fake-{}-{}",
        sanitize_certificate_name(primary_domain),
        random_suffix
    )
}

fn sanitize_certificate_name(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' => ch.to_ascii_lowercase(),
            '.' | '-' | '_' => ch,
            _ => '-',
        })
        .collect::<String>();
    let sanitized = sanitized.trim_matches('-').to_string();
    if sanitized.is_empty() {
        "generated-cert".to_string()
    } else {
        sanitized
    }
}

pub(crate) fn normalize_string_list(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::new();

    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        if seen.insert(value.to_string()) {
            normalized.push(value.to_string());
        }
    }

    normalized
}

pub(crate) fn required_string(value: String, message: &str) -> Result<String, String> {
    non_empty_string(value).ok_or_else(|| message.to_string())
}

pub(crate) fn parse_json_string_vec(value: &str) -> Result<Vec<String>, anyhow::Error> {
    Ok(serde_json::from_str::<Vec<String>>(value)?)
}

pub(crate) fn parse_json_value(value: &str) -> Result<serde_json::Value, anyhow::Error> {
    Ok(serde_json::from_str::<serde_json::Value>(value)?)
}

pub(crate) async fn ensure_local_certificate_exists(
    store: &crate::storage::SqliteStore,
    id: i64,
) -> Result<(), String> {
    let exists = store
        .load_local_certificate(id)
        .await
        .map_err(|err| err.to_string())?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(format!("本地证书 '{}' 不存在", id))
    }
}

pub(crate) async fn ensure_local_site_exists(
    store: &crate::storage::SqliteStore,
    id: i64,
) -> Result<(), String> {
    let exists = store
        .load_local_site(id)
        .await
        .map_err(|err| err.to_string())?
        .is_some();
    if exists {
        Ok(())
    } else {
        Err(format!("本地站点 '{}' 不存在", id))
    }
}
