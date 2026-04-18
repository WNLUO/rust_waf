use super::*;
use crate::config::{
    Config, Http3Config, L4Config, L7Config, Rule, RuleAction, RuleLayer, RuntimeProfile, Severity,
};
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_test_db_path(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir()
        .join(format!(
            "{}_core_{}_{}.db",
            env!("CARGO_PKG_NAME"),
            name,
            nanos
        ))
        .display()
        .to_string()
}

fn test_rule(id: &str, pattern: &str) -> Rule {
    Rule {
        id: id.to_string(),
        name: format!("Rule {}", id),
        enabled: true,
        layer: RuleLayer::L7,
        pattern: pattern.to_string(),
        action: RuleAction::Block,
        severity: Severity::High,
        plugin_template_id: None,
        response_template: None,
    }
}

mod ai_route_profiles;
mod policy_effects;
mod storage_runtime;
mod temp_policy_matching;
mod visitor_intelligence;
