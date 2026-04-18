use anyhow::Result;

use crate::config::{Config, Rule, RuleAction, RuleLayer, RuleResponseTemplate, Severity};

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
pub struct ActionIdeaOverrideEntry {
    pub idea_id: String,
    pub title: Option<String>,
    pub status_code: Option<i64>,
    pub content_type: Option<String>,
    pub response_content: Option<String>,
    pub body_file_path: Option<String>,
    pub uploaded_file_name: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct ActionIdeaOverrideUpsert {
    pub idea_id: String,
    pub title: Option<String>,
    pub status_code: Option<i64>,
    pub content_type: Option<String>,
    pub response_content: Option<String>,
    pub body_file_path: Option<String>,
    pub uploaded_file_name: Option<String>,
}

#[derive(sqlx::FromRow)]
pub(in crate::storage) struct StoredRuleRow {
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
pub(in crate::storage) struct StoredAppConfigRow {
    pub(super) config_json: String,
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

pub(in crate::storage) fn serialize_rule_response_template(
    template: Option<&RuleResponseTemplate>,
) -> Result<Option<String>> {
    template
        .map(serde_json::to_string)
        .transpose()
        .map_err(Into::into)
}

pub(in crate::storage) fn deserialize_rule_response_template(
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

pub(in crate::storage) fn parse_rule_layer(value: &str) -> Result<RuleLayer> {
    RuleLayer::parse(value).map_err(anyhow::Error::msg)
}

pub(in crate::storage) fn parse_rule_action(value: &str) -> Result<RuleAction> {
    RuleAction::parse(value).map_err(anyhow::Error::msg)
}

pub(in crate::storage) fn parse_severity(value: &str) -> Result<Severity> {
    Severity::parse(value).map_err(anyhow::Error::msg)
}
