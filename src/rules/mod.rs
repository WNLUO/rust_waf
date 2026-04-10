use crate::config::{Rule, RuleAction, RuleLayer};
use crate::core::{InspectionLayer, InspectionResult, PacketInfo};
use anyhow::Result;
use regex::Regex;

pub struct RuleEngine {
    rules: Vec<(Rule, Regex)>,
}

pub fn validate_rule(rule: &Rule) -> Result<()> {
    Regex::new(&rule.pattern)
        .map(|_| ())
        .map_err(|e| anyhow::anyhow!("Invalid regex in rule {}: {}", rule.id, e))
}

impl RuleEngine {
    pub fn new(config_rules: Vec<Rule>) -> Result<Self> {
        let rules: Result<Vec<_>> = config_rules
            .into_iter()
            .filter(|rule| rule.enabled)
            .map(|rule| {
                validate_rule(&rule)?;
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
                let packet_summary;
                let content = if let Some(payload) = payload {
                    payload
                } else {
                    packet_summary = format!(
                        "source_ip={} dest_ip={} source_port={} dest_port={} protocol={:?}",
                        _packet.source_ip,
                        _packet.dest_ip,
                        _packet.source_port,
                        _packet.dest_port,
                        _packet.protocol
                    );
                    &packet_summary
                };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{RuleAction, RuleLayer, Severity};
    use crate::core::Protocol;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn test_l4_rule_matches_packet_summary() {
        let engine = RuleEngine::new(vec![Rule {
            id: "l4-block-port".to_string(),
            name: "Block SSH".to_string(),
            enabled: true,
            layer: RuleLayer::L4,
            pattern: r"dest_port=22".to_string(),
            action: RuleAction::Block,
            severity: Severity::High,
        }])
        .unwrap();

        let packet = PacketInfo {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            source_port: 40000,
            dest_port: 22,
            protocol: Protocol::TCP,
            timestamp: 0,
        };

        let result = engine.inspect(&packet, None);
        assert!(result.blocked);
        assert_eq!(result.layer, InspectionLayer::L4);
    }

    #[test]
    fn test_validate_rule_rejects_invalid_regex() {
        let rule = Rule {
            id: "invalid".to_string(),
            name: "Invalid".to_string(),
            enabled: false,
            layer: RuleLayer::L4,
            pattern: "(".to_string(),
            action: RuleAction::Block,
            severity: Severity::High,
        };

        let error = validate_rule(&rule).unwrap_err().to_string();
        assert!(error.contains("Invalid regex"));
        assert!(error.contains("invalid"));
    }
}
