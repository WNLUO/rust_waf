use crate::config::{Rule, RuleLayer, RuleAction};
use crate::core::{PacketInfo, InspectionResult, InspectionLayer};
use regex::Regex;
use anyhow::Result;

pub struct RuleEngine {
    rules: Vec<(Rule, Regex)>,
}

impl RuleEngine {
    pub fn new(config_rules: Vec<Rule>) -> Result<Self> {
        let rules: Result<Vec<_>> = config_rules
            .into_iter()
            .filter(|rule| rule.enabled)
            .map(|rule| {
                let regex = Regex::new(&rule.pattern)
                    .map_err(|e| anyhow::anyhow!("Invalid regex in rule {}: {}", rule.id, e))?;
                Ok((rule, regex))
            })
            .collect();

        Ok(Self { rules: rules? })
    }

    pub fn inspect(&self, _packet: &PacketInfo, payload: Option<&str>) -> InspectionResult {
        for (rule, pattern) in &self.rules {
            if self.matches_layer(rule, payload) {
                let content = payload.unwrap_or("");
                if pattern.is_match(content) {
                    return InspectionResult {
                        blocked: matches!(rule.action, RuleAction::Block),
                        reason: format!("Rule '{}' triggered: {}", rule.name, rule.id),
                        layer: match rule.layer {
                            RuleLayer::L4 => InspectionLayer::L4,
                            RuleLayer::L7 => InspectionLayer::L7,
                        },
                    };
                }
            }
        }

        InspectionResult {
            blocked: false,
            reason: String::new(),
            layer: InspectionLayer::L7, // Default to L7
        }
    }

    pub fn has_rules(&self) -> bool {
        !self.rules.is_empty()
    }

    fn matches_layer(&self, rule: &Rule, payload: Option<&str>) -> bool {
        match rule.layer {
            RuleLayer::L4 => payload.is_none(),
            RuleLayer::L7 => payload.is_some(),
        }
    }
}
