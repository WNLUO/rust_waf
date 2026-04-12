use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub layer: RuleLayer,
    pub pattern: String,
    pub action: RuleAction,
    pub severity: Severity,
    #[serde(default)]
    pub plugin_template_id: Option<String>,
    #[serde(default)]
    pub response_template: Option<RuleResponseTemplate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResponseTemplate {
    pub status_code: u16,
    #[serde(default = "default_rule_response_content_type")]
    pub content_type: String,
    #[serde(default)]
    pub body_source: RuleResponseBodySource,
    #[serde(default)]
    pub gzip: bool,
    #[serde(default)]
    pub body_text: String,
    #[serde(default)]
    pub body_file_path: String,
    #[serde(default)]
    pub headers: Vec<RuleResponseHeader>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleResponseHeader {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleResponseBodySource {
    #[default]
    InlineText,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleLayer {
    L4,
    L7,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RuleAction {
    Allow,
    Block,
    Alert,
    Respond,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl RuleLayer {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::L4 => "l4",
            Self::L7 => "l7",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "l4" => Ok(Self::L4),
            "l7" => Ok(Self::L7),
            other => Err(format!("Unsupported rule layer '{}'", other)),
        }
    }
}

impl RuleAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
            Self::Alert => "alert",
            Self::Respond => "respond",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "allow" => Ok(Self::Allow),
            "block" => Ok(Self::Block),
            "alert" => Ok(Self::Alert),
            "respond" => Ok(Self::Respond),
            other => Err(format!("Unsupported rule action '{}'", other)),
        }
    }
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }

    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "critical" => Ok(Self::Critical),
            other => Err(format!("Unsupported rule severity '{}'", other)),
        }
    }
}

pub(crate) fn default_rule_response_content_type() -> String {
    "text/plain; charset=utf-8".to_string()
}
