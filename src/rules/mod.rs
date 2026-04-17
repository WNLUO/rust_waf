use crate::config::{Rule, RuleAction, RuleLayer, RuleResponseBodySource, RuleResponseTemplate};
use crate::core::{
    CustomHttpResponse, InspectionAction, InspectionLayer, InspectionResult, PacketInfo,
    RandomStatusConfig, TarpitConfig,
};
use anyhow::Result;
use flate2::write::GzEncoder;
use flate2::Compression;
use regex::Regex;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};

pub const RULE_RESPONSE_FILES_DIR: &str = "data/rule_responses";
const INTERNAL_TARPIT_BYTES_PER_CHUNK_HEADER: &str = "x-rust-waf-tarpit-bytes-per-chunk";
const INTERNAL_TARPIT_INTERVAL_MS_HEADER: &str = "x-rust-waf-tarpit-interval-ms";
const INTERNAL_RANDOM_STATUSES_HEADER: &str = "x-rust-waf-random-statuses";

#[derive(Debug, Clone, serde::Deserialize)]
struct RandomResponseBodyConfig {
    #[serde(default)]
    success_rate_percent: Option<u8>,
    #[serde(default)]
    success_body: Option<String>,
    #[serde(default)]
    failure_body: Option<String>,
}

pub struct RuleEngine {
    rules: Vec<CompiledRule>,
}

struct CompiledRule {
    rule: Rule,
    pattern: Regex,
    custom_response: Option<CustomHttpResponse>,
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
                let custom_response = if matches!(rule.action, RuleAction::Respond) {
                    Some(build_custom_response(
                        rule.response_template
                            .as_ref()
                            .expect("respond rule should have response template"),
                    )?)
                } else {
                    None
                };
                Ok(CompiledRule {
                    rule,
                    pattern: regex,
                    custom_response,
                })
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

        for compiled in &self.rules {
            if self.matches_layer(&compiled.rule, payload) {
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
                if compiled.pattern.is_match(content) {
                    let layer = match compiled.rule.layer {
                        RuleLayer::L4 => InspectionLayer::L4,
                        RuleLayer::L7 => InspectionLayer::L7,
                    };
                    let reason = format!(
                        "Rule '{}' triggered: {}",
                        compiled.rule.name, compiled.rule.id
                    );
                    return match compiled.rule.action {
                        RuleAction::Block => InspectionResult::block(layer, reason),
                        RuleAction::Allow => InspectionResult::allow_with_reason(layer, reason),
                        RuleAction::Alert => InspectionResult::alert(layer, reason),
                        RuleAction::Respond => InspectionResult::respond(
                            layer,
                            reason,
                            compiled
                                .custom_response
                                .clone()
                                .expect("respond rule should have cached response"),
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

pub(crate) fn validate_response_template(template: &RuleResponseTemplate) -> Result<()> {
    if !(100..=599).contains(&template.status_code) {
        anyhow::bail!("Response status code must be between 100 and 599");
    }

    if template.content_type.trim().is_empty() {
        anyhow::bail!("Response content_type cannot be empty");
    }

    match template.body_source {
        RuleResponseBodySource::InlineText => {}
        RuleResponseBodySource::File => {
            let path = resolve_response_file_path(template.body_file_path.trim())?;
            let metadata = fs::metadata(&path).map_err(|err| {
                anyhow::anyhow!(
                    "Failed to access response file '{}': {}",
                    path.display(),
                    err
                )
            })?;
            if !metadata.is_file() {
                anyhow::bail!("Response file '{}' is not a regular file", path.display());
            }
        }
    }

    for header in &template.headers {
        if header.key.trim().is_empty() {
            anyhow::bail!("Response header key cannot be empty");
        }
    }

    Ok(())
}

pub(crate) fn build_custom_response(template: &RuleResponseTemplate) -> Result<CustomHttpResponse> {
    let raw_body = match template.body_source {
        RuleResponseBodySource::InlineText => template.body_text.as_bytes().to_vec(),
        RuleResponseBodySource::File => {
            let path = resolve_response_file_path(template.body_file_path.trim())?;
            fs::read(&path).map_err(|err| {
                anyhow::anyhow!("Failed to read response file '{}': {}", path.display(), err)
            })?
        }
    };

    let body = if template.gzip {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&raw_body)?;
        encoder.finish()?
    } else {
        raw_body
    };

    let tarpit = extract_tarpit_config(&template.headers)?;
    let random_status = extract_random_status_config(&template.headers, &body)?;

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
            || key.eq_ignore_ascii_case(INTERNAL_TARPIT_BYTES_PER_CHUNK_HEADER)
            || key.eq_ignore_ascii_case(INTERNAL_TARPIT_INTERVAL_MS_HEADER)
            || key.eq_ignore_ascii_case(INTERNAL_RANDOM_STATUSES_HEADER)
        {
            return None;
        }
        Some((key, header.value.trim().to_string()))
    }));

    Ok(CustomHttpResponse {
        status_code: template.status_code,
        headers,
        body,
        tarpit,
        random_status,
    })
}

fn extract_tarpit_config(
    headers: &[crate::config::RuleResponseHeader],
) -> Result<Option<TarpitConfig>> {
    let mut bytes_per_chunk = None;
    let mut chunk_interval_ms = None;

    for header in headers {
        let key = header.key.trim();
        let value = header.value.trim();
        if key.eq_ignore_ascii_case(INTERNAL_TARPIT_BYTES_PER_CHUNK_HEADER) {
            bytes_per_chunk = Some(value.parse::<usize>().map_err(|_| {
                anyhow::anyhow!(
                    "Invalid tarpit bytes-per-chunk '{}', expected positive integer",
                    value
                )
            })?);
        } else if key.eq_ignore_ascii_case(INTERNAL_TARPIT_INTERVAL_MS_HEADER) {
            chunk_interval_ms = Some(value.parse::<u64>().map_err(|_| {
                anyhow::anyhow!(
                    "Invalid tarpit interval '{}', expected positive integer milliseconds",
                    value
                )
            })?);
        }
    }

    match (bytes_per_chunk, chunk_interval_ms) {
        (None, None) => Ok(None),
        (Some(bytes_per_chunk), Some(chunk_interval_ms))
            if bytes_per_chunk > 0 && chunk_interval_ms > 0 =>
        {
            Ok(Some(TarpitConfig {
                bytes_per_chunk,
                chunk_interval_ms,
            }))
        }
        (Some(_), Some(_)) => Err(anyhow::anyhow!(
            "Tarpit bytes-per-chunk and interval must be greater than zero"
        )),
        _ => Err(anyhow::anyhow!(
            "Tarpit response requires both bytes-per-chunk and interval headers"
        )),
    }
}

fn extract_random_status_config(
    headers: &[crate::config::RuleResponseHeader],
    body: &[u8],
) -> Result<Option<RandomStatusConfig>> {
    let Some(raw) = headers.iter().find_map(|header| {
        header
            .key
            .trim()
            .eq_ignore_ascii_case(INTERNAL_RANDOM_STATUSES_HEADER)
            .then(|| header.value.trim())
    }) else {
        return Ok(None);
    };

    let failure_statuses: Result<Vec<_>> = raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            let parsed = value.parse::<u16>().map_err(|_| {
                anyhow::anyhow!(
                    "Invalid random status '{}', expected HTTP status code",
                    value
                )
            })?;
            if !(100..=599).contains(&parsed) {
                anyhow::bail!("Random status '{}' must be between 100 and 599", value);
            }
            Ok(parsed)
        })
        .collect();
    let failure_statuses = failure_statuses?;
    if failure_statuses.is_empty() {
        anyhow::bail!("Random status response requires at least one status code");
    }

    let parsed_body = std::str::from_utf8(body)
        .ok()
        .and_then(|text| serde_json::from_str::<RandomResponseBodyConfig>(text).ok());

    let success_rate_percent = parsed_body
        .as_ref()
        .and_then(|item| item.success_rate_percent)
        .unwrap_or(25)
        .min(100);
    let success_body = parsed_body
        .as_ref()
        .and_then(|item| item.success_body.clone())
        .unwrap_or_else(|| "request completed successfully".to_string())
        .into_bytes();
    let failure_body = parsed_body
        .as_ref()
        .and_then(|item| item.failure_body.clone())
        .unwrap_or_else(|| String::from_utf8_lossy(body).to_string())
        .into_bytes();

    Ok(Some(RandomStatusConfig {
        failure_statuses,
        success_rate_percent,
        success_body,
        failure_body,
    }))
}

pub(crate) fn resolve_response_file_path(value: &str) -> Result<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Response body_file_path cannot be empty when body_source=file");
    }

    let relative = Path::new(trimmed);
    if relative.is_absolute() {
        anyhow::bail!(
            "Response file path must be relative to {}",
            RULE_RESPONSE_FILES_DIR
        );
    }

    for component in relative.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            anyhow::bail!(
                "Response file path must stay within {}",
                RULE_RESPONSE_FILES_DIR
            );
        }
    }

    let base_dir = PathBuf::from(RULE_RESPONSE_FILES_DIR);
    fs::create_dir_all(&base_dir)?;
    Ok(base_dir.join(relative))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        RuleAction, RuleLayer, RuleResponseBodySource, RuleResponseHeader, RuleResponseTemplate,
        Severity,
    };
    use crate::core::Protocol;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{SystemTime, UNIX_EPOCH};

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
            plugin_template_id: None,
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
            plugin_template_id: None,
            response_template: None,
        };

        let error = validate_rule(&rule).unwrap_err().to_string();
        assert!(error.contains("Invalid regex"));
        assert!(error.contains("invalid"));
    }

    #[test]
    fn test_rule_engine_action_matrix_for_l4_and_l7_rules() {
        let packet = PacketInfo {
            source_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            source_port: 40000,
            dest_port: 22,
            protocol: Protocol::TCP,
            timestamp: 0,
        };

        for (action, expected, blocked, event_action) in [
            (RuleAction::Allow, InspectionAction::Allow, false, "allow"),
            (RuleAction::Alert, InspectionAction::Alert, false, "alert"),
            (RuleAction::Block, InspectionAction::Block, true, "block"),
        ] {
            let engine = RuleEngine::new(vec![Rule {
                id: format!("l4-{}", action.as_str()),
                name: format!("L4 {}", action.as_str()),
                enabled: true,
                layer: RuleLayer::L4,
                pattern: r"dest_port=22".to_string(),
                action,
                severity: Severity::High,
                plugin_template_id: None,
                response_template: None,
            }])
            .unwrap();

            let result = engine.inspect(&packet, None);
            assert_eq!(result.layer, InspectionLayer::L4);
            assert_eq!(result.action, expected);
            assert_eq!(result.blocked, blocked);
            assert_eq!(result.event_action(), event_action);
            assert!(result.custom_response.is_none());
        }

        for (action, expected, blocked, event_action) in [
            (RuleAction::Allow, InspectionAction::Allow, false, "allow"),
            (RuleAction::Alert, InspectionAction::Alert, false, "alert"),
            (RuleAction::Block, InspectionAction::Block, true, "block"),
        ] {
            let engine = RuleEngine::new(vec![Rule {
                id: format!("l7-{}", action.as_str()),
                name: format!("L7 {}", action.as_str()),
                enabled: true,
                layer: RuleLayer::L7,
                pattern: "attack".to_string(),
                action,
                severity: Severity::High,
                plugin_template_id: None,
                response_template: None,
            }])
            .unwrap();

            let result = engine.inspect(&packet, Some("GET /attack"));
            assert_eq!(result.layer, InspectionLayer::L7);
            assert_eq!(result.action, expected);
            assert_eq!(result.blocked, blocked);
            assert_eq!(result.event_action(), event_action);
            assert!(result.custom_response.is_none());
        }
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
            plugin_template_id: None,
            response_template: Some(RuleResponseTemplate {
                status_code: 200,
                content_type: "text/html; charset=utf-8".to_string(),
                body_source: RuleResponseBodySource::InlineText,
                gzip: true,
                body_text: "<h1>blocked</h1>".to_string(),
                body_file_path: String::new(),
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
        assert!(response.tarpit.is_none());
    }

    #[test]
    fn test_l7_respond_rule_reads_body_from_file() {
        let temp_name = format!(
            "waf_rule_response_{}.txt",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let base_dir = PathBuf::from(RULE_RESPONSE_FILES_DIR);
        fs::create_dir_all(&base_dir).unwrap();
        let stored_path = base_dir.join(&temp_name);
        fs::write(&stored_path, b"hello from file").unwrap();

        let engine = RuleEngine::new(vec![Rule {
            id: "respond-file".to_string(),
            name: "Respond File".to_string(),
            enabled: true,
            layer: RuleLayer::L7,
            pattern: "file".to_string(),
            action: RuleAction::Respond,
            severity: Severity::High,
            plugin_template_id: None,
            response_template: Some(RuleResponseTemplate {
                status_code: 200,
                content_type: "text/plain".to_string(),
                body_source: RuleResponseBodySource::File,
                gzip: false,
                body_text: String::new(),
                body_file_path: temp_name.clone(),
                headers: vec![],
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

        let result = engine.inspect(&packet, Some("file"));
        let response = result.custom_response.expect("custom response");
        assert_eq!(response.body, b"hello from file".to_vec());
        assert!(response.tarpit.is_none());

        let _ = fs::remove_file(stored_path);
    }

    #[test]
    fn test_l7_respond_rule_preserves_redirect_location_header() {
        let engine = RuleEngine::new(vec![Rule {
            id: "respond-redirect".to_string(),
            name: "Redirect".to_string(),
            enabled: true,
            layer: RuleLayer::L7,
            pattern: "jump".to_string(),
            action: RuleAction::Respond,
            severity: Severity::Medium,
            plugin_template_id: None,
            response_template: Some(RuleResponseTemplate {
                status_code: 302,
                content_type: "text/html; charset=utf-8".to_string(),
                body_source: RuleResponseBodySource::InlineText,
                gzip: false,
                body_text: "<p>redirecting</p>".to_string(),
                body_file_path: String::new(),
                headers: vec![RuleResponseHeader {
                    key: "location".to_string(),
                    value: "https://example.com/blocked".to_string(),
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

        let result = engine.inspect(&packet, Some("jump"));
        let response = result.custom_response.expect("custom response");
        assert_eq!(response.status_code, 302);
        assert!(response
            .headers
            .iter()
            .any(|(key, value)| key == "location" && value == "https://example.com/blocked"));
        assert!(response.tarpit.is_none());
    }

    #[test]
    fn test_build_custom_response_extracts_tarpit_config() {
        let response = build_custom_response(&RuleResponseTemplate {
            status_code: 200,
            content_type: "text/plain; charset=utf-8".to_string(),
            body_source: RuleResponseBodySource::InlineText,
            gzip: false,
            body_text: "processing request, please wait...".to_string(),
            body_file_path: String::new(),
            headers: vec![
                RuleResponseHeader {
                    key: "x-rust-waf-tarpit-bytes-per-chunk".to_string(),
                    value: "1".to_string(),
                },
                RuleResponseHeader {
                    key: "x-rust-waf-tarpit-interval-ms".to_string(),
                    value: "1000".to_string(),
                },
                RuleResponseHeader {
                    key: "cache-control".to_string(),
                    value: "no-store".to_string(),
                },
            ],
        })
        .expect("response should build");

        let tarpit = response.tarpit.expect("tarpit config");
        assert_eq!(tarpit.bytes_per_chunk, 1);
        assert_eq!(tarpit.chunk_interval_ms, 1000);
        assert!(response.headers.iter().all(|(key, _)| {
            !key.eq_ignore_ascii_case("x-rust-waf-tarpit-bytes-per-chunk")
                && !key.eq_ignore_ascii_case("x-rust-waf-tarpit-interval-ms")
        }));
    }
}
