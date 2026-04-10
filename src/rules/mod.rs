use crate::config::{Rule, RuleAction, RuleLayer, RuleResponseTemplate};
use crate::core::{
    CustomHttpResponse, InspectionAction, InspectionLayer, InspectionResult, PacketInfo,
};
use anyhow::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use regex::Regex;
use std::io::Write;

pub struct RuleEngine {
    rules: Vec<(Rule, Regex)>,
}

pub fn validate_rule(rule: &Rule) -> Result<()> {
    Regex::new(&rule.pattern)
        .map_err(|e| anyhow::anyhow!("Invalid regex in rule {}: {}", rule.id, e))?;

    if matches!(rule.action, RuleAction::Respond) {
        if !matches!(rule.layer, RuleLayer::L7) {
            anyhow::bail!("Respond action is only supported for L7 rules");
        }

        let template = rule
            .response_template
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Respond action requires response_template"))?;
        validate_response_template(template)?;
    }

    Ok(())
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
        let default_layer = if payload.is_some() {
            InspectionLayer::L7
        } else {
            InspectionLayer::L4
        };

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
                    let layer = match rule.layer {
                        RuleLayer::L4 => InspectionLayer::L4,
                        RuleLayer::L7 => InspectionLayer::L7,
                    };
                    let reason = format!("Rule '{}' triggered: {}", rule.name, rule.id);
                    return match rule.action {
                        RuleAction::Block => InspectionResult::block(layer, reason),
                        RuleAction::Allow => InspectionResult::allow_with_reason(layer, reason),
                        RuleAction::Alert => InspectionResult::alert(layer, reason),
                        RuleAction::Respond => InspectionResult::respond(
                            layer,
                            reason,
                            build_custom_response(
                                rule.response_template
                                    .as_ref()
                                    .expect("respond rule should have response template"),
                            )
                            .expect("validated response template should build"),
                        ),
                    };
                }
            }
        }

        InspectionResult {
            action: InspectionAction::Allow,
            ..InspectionResult::allow(default_layer)
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

fn validate_response_template(template: &RuleResponseTemplate) -> Result<()> {
    if !(100..=599).contains(&template.status_code) {
        anyhow::bail!("Response status code must be between 100 and 599");
    }

    if template.content_type.trim().is_empty() {
        anyhow::bail!("Response content_type cannot be empty");
    }

    for header in &template.headers {
        if header.key.trim().is_empty() {
            anyhow::bail!("Response header key cannot be empty");
        }
    }

    Ok(())
}

fn build_custom_response(template: &RuleResponseTemplate) -> Result<CustomHttpResponse> {
    let body = if template.gzip {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(template.body_text.as_bytes())?;
        encoder.finish()?
    } else {
        template.body_text.as_bytes().to_vec()
    };

    let mut headers = Vec::with_capacity(template.headers.len() + 2);
    headers.push(("content-type".to_string(), template.content_type.clone()));
    if template.gzip {
        headers.push(("content-encoding".to_string(), "gzip".to_string()));
    }
    headers.extend(template.headers.iter().filter_map(|header| {
        let key = header.key.trim().to_string();
        if key.eq_ignore_ascii_case("content-length")
            || key.eq_ignore_ascii_case("content-type")
            || key.eq_ignore_ascii_case("content-encoding")
        {
            return None;
        }
        Some((key, header.value.trim().to_string()))
    }));

    Ok(CustomHttpResponse {
        status_code: template.status_code,
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        RuleAction, RuleLayer, RuleResponseHeader, RuleResponseTemplate, Severity,
    };
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
            response_template: None,
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
            response_template: None,
        };

        let error = validate_rule(&rule).unwrap_err().to_string();
        assert!(error.contains("Invalid regex"));
        assert!(error.contains("invalid"));
    }

    #[test]
    fn test_l7_respond_rule_builds_gzip_response() {
        let engine = RuleEngine::new(vec![Rule {
            id: "respond-1".to_string(),
            name: "Respond".to_string(),
            enabled: true,
            layer: RuleLayer::L7,
            pattern: "attack".to_string(),
            action: RuleAction::Respond,
            severity: Severity::High,
            response_template: Some(RuleResponseTemplate {
                status_code: 200,
                content_type: "text/html; charset=utf-8".to_string(),
                gzip: true,
                body_text: "<h1>blocked</h1>".to_string(),
                headers: vec![RuleResponseHeader {
                    key: "x-test".to_string(),
                    value: "yes".to_string(),
                }],
            }),
        }])
        .unwrap();

        let packet = PacketInfo {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            source_port: 40000,
            dest_port: 443,
            protocol: Protocol::TCP,
            timestamp: 0,
        };

        let result = engine.inspect(&packet, Some("attack"));
        assert!(result.blocked);
        assert_eq!(result.action, InspectionAction::Respond);
        let response = result.custom_response.expect("custom response");
        assert_eq!(response.status_code, 200);
        assert!(response
            .headers
            .iter()
            .any(|(key, value)| key == "content-encoding" && value == "gzip"));
        assert!(!response.body.is_empty());
    }
}
