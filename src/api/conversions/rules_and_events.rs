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
        let decision_summary = build_security_event_decision_summary(
            event.reason.as_str(),
            event.details_json.as_deref(),
        );
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
            decision_summary,
        }
    }
}

fn build_security_event_decision_summary(
    reason: &str,
    details_json: Option<&str>,
) -> Option<SecurityEventDecisionSummary> {
    let details = details_json.and_then(|raw| serde_json::from_str::<serde_json::Value>(raw).ok());

    let identity_state = details
        .as_ref()
        .and_then(|value| nested_str(value, &["client_identity", "identity_state"]))
        .map(ToOwned::to_owned);
    let client_ip_source = details
        .as_ref()
        .and_then(|value| nested_str(value, &["client_identity", "client_ip_source"]))
        .map(ToOwned::to_owned);
    let forward_header_valid = details
        .as_ref()
        .and_then(|value| nested_bool(value, &["client_identity", "forward_header_valid"]));
    let l4_overload_level = details
        .as_ref()
        .and_then(|value| nested_str(value, &["l4_runtime", "overload_level"]))
        .map(ToOwned::to_owned);
    let l7_rule_inspection_mode = details
        .as_ref()
        .and_then(|value| nested_str(value, &["inspection_runtime", "rule_inspection_mode"]))
        .map(ToOwned::to_owned);
    let cc_action = details
        .as_ref()
        .and_then(|value| nested_str(value, &["l7_cc", "action"]))
        .map(ToOwned::to_owned);
    let behavior_action = details
        .as_ref()
        .and_then(|value| nested_str(value, &["l7_behavior", "action"]))
        .map(ToOwned::to_owned);

    let primary_signal =
        derive_primary_signal(reason, cc_action.as_deref(), behavior_action.as_deref());
    let labels = derive_security_event_labels(
        reason,
        identity_state.as_deref(),
        forward_header_valid,
        l4_overload_level.as_deref(),
        l7_rule_inspection_mode.as_deref(),
        cc_action.as_deref(),
        behavior_action.as_deref(),
    );

    if identity_state.is_none()
        && client_ip_source.is_none()
        && forward_header_valid.is_none()
        && l4_overload_level.is_none()
        && l7_rule_inspection_mode.is_none()
        && cc_action.is_none()
        && behavior_action.is_none()
        && labels.is_empty()
    {
        return None;
    }

    Some(SecurityEventDecisionSummary {
        primary_signal,
        identity_state,
        client_ip_source,
        forward_header_valid,
        l4_overload_level,
        l7_rule_inspection_mode,
        cc_action,
        behavior_action,
        labels,
    })
}

fn nested_str<'a>(value: &'a serde_json::Value, path: &[&str]) -> Option<&'a str> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str()
}

fn nested_bool(value: &serde_json::Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for key in path {
        current = current.get(*key)?;
    }
    match current {
        serde_json::Value::Bool(value) => Some(*value),
        serde_json::Value::String(value) => match value.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn derive_primary_signal(
    reason: &str,
    cc_action: Option<&str>,
    behavior_action: Option<&str>,
) -> String {
    if let Some(action) = behavior_action {
        return format!("l7_behavior:{action}");
    }
    if let Some(action) = cc_action {
        return format!("l7_cc:{action}");
    }

    let lower = reason.to_ascii_lowercase();
    if lower.contains("slow attack") {
        "slow_attack".to_string()
    } else if lower.contains("safeline") {
        "safeline".to_string()
    } else if lower.contains("rule") {
        "rule_engine".to_string()
    } else if lower.contains("blocked ip") {
        "blocked_ip".to_string()
    } else {
        "inspection".to_string()
    }
}

fn derive_security_event_labels(
    reason: &str,
    identity_state: Option<&str>,
    forward_header_valid: Option<bool>,
    l4_overload_level: Option<&str>,
    l7_rule_inspection_mode: Option<&str>,
    cc_action: Option<&str>,
    behavior_action: Option<&str>,
) -> Vec<String> {
    let mut labels = Vec::new();

    if let Some(identity_state) = identity_state {
        labels.push(format!("identity:{identity_state}"));
    }
    if matches!(forward_header_valid, Some(false)) {
        labels.push("forward_header:invalid".to_string());
    }
    if let Some(level) = l4_overload_level {
        labels.push(format!("l4_overload:{level}"));
    }
    if let Some(mode) = l7_rule_inspection_mode {
        labels.push(format!("l7_rules:{mode}"));
    }
    if let Some(action) = cc_action {
        labels.push(format!("cc:{action}"));
    }
    if let Some(action) = behavior_action {
        labels.push(format!("behavior:{action}"));
    }

    let lower = reason.to_ascii_lowercase();
    if lower.contains("slow attack") {
        labels.push("trigger:slow_attack".to_string());
    }
    if lower.contains("safeline") {
        labels.push("trigger:safeline".to_string());
    }
    if lower.contains("rule") {
        labels.push("trigger:rule_engine".to_string());
    }
    if lower.contains("spoofed forwarded header") {
        labels.push("trigger:spoofed_header".to_string());
    }

    labels.sort();
    labels.dedup();
    labels
}

impl From<crate::l7::behavior_guard::BehaviorProfileSnapshot> for BehaviorProfileResponse {
    fn from(value: crate::l7::behavior_guard::BehaviorProfileSnapshot) -> Self {
        Self {
            identity: value.identity,
            source_ip: value.source_ip,
            latest_seen_at: value.latest_seen_unix,
            score: value.score,
            dominant_route: value.dominant_route,
            focused_document_route: value.focused_document_route,
            focused_api_route: value.focused_api_route,
            distinct_routes: value.distinct_routes,
            repeated_ratio: value.repeated_ratio_percent,
            document_repeated_ratio: value.document_repeated_ratio_percent,
            api_repeated_ratio: value.api_repeated_ratio_percent,
            interval_jitter_ms: value.jitter_ms,
            document_requests: value.document_requests,
            api_requests: value.api_requests,
            non_document_requests: value.non_document_requests,
            challenge_count_window: value.recent_challenges,
            session_span_secs: value.session_span_secs,
            flags: value.flags,
            latest_route: value.latest_route,
            latest_kind: value.latest_kind.to_string(),
            blocked: false,
            blocked_at: None,
            blocked_expires_at: None,
            blocked_reason: None,
        }
    }
}

impl From<crate::storage::FingerprintProfileEntry> for FingerprintProfileResponse {
    fn from(value: crate::storage::FingerprintProfileEntry) -> Self {
        Self {
            identity: value.identity,
            identity_kind: value.identity_kind,
            source_ip: value.source_ip,
            first_seen_at: value.first_seen_at,
            last_seen_at: value.last_seen_at,
            first_site_domain: value.first_site_domain,
            last_site_domain: value.last_site_domain,
            first_user_agent: value.first_user_agent,
            last_user_agent: value.last_user_agent,
            total_security_events: value.total_security_events,
            total_behavior_events: value.total_behavior_events,
            total_challenges: value.total_challenges,
            total_blocks: value.total_blocks,
            latest_score: value.latest_score,
            max_score: value.max_score,
            latest_action: value.latest_action,
            reputation_score: value.reputation_score,
            notes: value.notes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_event_decision_summary_extracts_identity_and_runtime_labels() {
        let details = serde_json::json!({
            "client_identity": {
                "identity_state": "trusted_cdn_forwarded",
                "client_ip_source": "forwarded_header",
                "forward_header_valid": "true"
            },
            "l7_cc": {
                "action": "challenge"
            },
            "l7_behavior": {
                "action": "delay:250ms"
            },
            "l4_runtime": {
                "overload_level": "high"
            },
            "inspection_runtime": {
                "rule_inspection_mode": "lightweight"
            }
        });

        let summary = build_security_event_decision_summary(
            "l7 behavior guard challenged suspicious session",
            Some(&details.to_string()),
        )
        .expect("decision summary");

        assert_eq!(summary.primary_signal, "l7_behavior:delay:250ms");
        assert_eq!(
            summary.identity_state.as_deref(),
            Some("trusted_cdn_forwarded")
        );
        assert_eq!(
            summary.client_ip_source.as_deref(),
            Some("forwarded_header")
        );
        assert_eq!(summary.forward_header_valid, Some(true));
        assert_eq!(summary.l4_overload_level.as_deref(), Some("high"));
        assert_eq!(
            summary.l7_rule_inspection_mode.as_deref(),
            Some("lightweight")
        );
        assert!(summary
            .labels
            .contains(&"identity:trusted_cdn_forwarded".to_string()));
        assert!(summary.labels.contains(&"l7_rules:lightweight".to_string()));
    }

    #[test]
    fn security_event_decision_summary_uses_reason_fallbacks() {
        let summary =
            build_security_event_decision_summary("slow attack detected: kind=slow_headers", None)
                .expect("fallback summary");

        assert_eq!(summary.primary_signal, "slow_attack");
        assert!(summary.labels.contains(&"trigger:slow_attack".to_string()));
    }
}

impl From<crate::storage::BehaviorSessionEntry> for BehaviorSessionResponse {
    fn from(value: crate::storage::BehaviorSessionEntry) -> Self {
        Self {
            session_key: value.session_key,
            identity: value.identity,
            source_ip: value.source_ip,
            site_domain: value.site_domain,
            opened_at: value.opened_at,
            last_seen_at: value.last_seen_at,
            event_count: value.event_count,
            challenge_count: value.challenge_count,
            block_count: value.block_count,
            latest_action: value.latest_action,
            latest_uri: value.latest_uri,
            latest_reason: value.latest_reason,
            dominant_route: value.dominant_route,
            focused_document_route: value.focused_document_route,
            focused_api_route: value.focused_api_route,
            distinct_routes: value.distinct_routes,
            repeated_ratio: value.repeated_ratio,
            document_repeated_ratio: value.document_repeated_ratio,
            api_repeated_ratio: value.api_repeated_ratio,
            document_requests: value.document_requests,
            api_requests: value.api_requests,
            non_document_requests: value.non_document_requests,
            interval_jitter_ms: value.interval_jitter_ms,
            session_span_secs: value.session_span_secs,
            flags: serde_json::from_str::<Vec<String>>(&value.flags_json).unwrap_or_default(),
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
            identity_state: normalize_optional_query_value(self.identity_state),
            primary_signal: normalize_optional_query_value(self.primary_signal),
            labels: normalize_csv_query_values(self.labels),
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

fn normalize_csv_query_values(value: Option<String>) -> Vec<String> {
    value
        .into_iter()
        .flat_map(|value| value.split(',').map(str::to_string).collect::<Vec<_>>())
        .filter_map(|value| {
            let normalized = value.trim().to_string();
            (!normalized.is_empty()).then_some(normalized)
        })
        .collect()
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
