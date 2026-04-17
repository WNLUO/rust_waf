use super::types::AiAuditModelOutput;
use super::*;

pub(super) fn model_output_needs_chinese_localization(output: &AiAuditModelOutput) -> bool {
    text_needs_chinese_localization(&output.headline)
        || output
            .executive_summary
            .iter()
            .any(|item| text_needs_chinese_localization(item))
        || output.findings.iter().any(|item| {
            text_needs_chinese_localization(&item.title)
                || text_needs_chinese_localization(&item.detail)
                || item
                    .evidence
                    .iter()
                    .any(|evidence| text_needs_chinese_localization(evidence))
        })
        || output.recommendations.iter().any(|item| {
            text_needs_chinese_localization(&item.title)
                || text_needs_chinese_localization(&item.action)
                || text_needs_chinese_localization(&item.rationale)
        })
        || output.suggested_local_rules.iter().any(|item| {
            text_needs_chinese_localization(&item.title)
                || text_needs_chinese_localization(&item.rationale)
        })
}

pub(super) fn text_needs_chinese_localization(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }

    let ascii_alpha_count = trimmed
        .chars()
        .filter(|ch| ch.is_ascii_alphabetic())
        .count();
    let cjk_count = trimmed
        .chars()
        .filter(|ch| matches!(*ch as u32, 0x4E00..=0x9FFF | 0x3400..=0x4DBF))
        .count();

    ascii_alpha_count >= 6 && cjk_count * 2 < ascii_alpha_count
}

pub(super) fn parse_model_output(content: &str) -> anyhow::Result<AiAuditModelOutput> {
    let normalized = strip_markdown_fences(content);
    let mut value = serde_json::from_str::<serde_json::Value>(normalized.trim())?;
    normalize_model_output_value(&mut value);
    Ok(serde_json::from_value::<AiAuditModelOutput>(value)?)
}

fn normalize_model_output_value(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };

    normalize_scalar_string_field(object, "risk_level");
    normalize_scalar_string_field(object, "headline");
    normalize_string_or_array_field(object, "executive_summary");

    if let Some(findings) = object
        .get_mut("findings")
        .and_then(|item| item.as_array_mut())
    {
        for finding in findings {
            if let Some(finding_object) = finding.as_object_mut() {
                normalize_scalar_string_field(finding_object, "key");
                normalize_scalar_string_field(finding_object, "severity");
                normalize_scalar_string_field(finding_object, "title");
                normalize_scalar_string_field(finding_object, "detail");
                normalize_string_or_array_field(finding_object, "evidence");
            }
        }
    }
    if let Some(recommendations) = object
        .get_mut("recommendations")
        .and_then(|item| item.as_array_mut())
    {
        for recommendation in recommendations {
            if let Some(recommendation_object) = recommendation.as_object_mut() {
                normalize_scalar_string_field(recommendation_object, "key");
                normalize_scalar_string_field(recommendation_object, "priority");
                normalize_scalar_string_field(recommendation_object, "title");
                normalize_scalar_string_field(recommendation_object, "action");
                normalize_scalar_string_field(recommendation_object, "rationale");
                if !recommendation_object.contains_key("action_type") {
                    recommendation_object.insert(
                        "action_type".to_string(),
                        serde_json::Value::String("observe".to_string()),
                    );
                }
                normalize_scalar_string_field(recommendation_object, "action_type");
                if !recommendation_object.contains_key("rule_suggestion_key") {
                    recommendation_object
                        .insert("rule_suggestion_key".to_string(), serde_json::Value::Null);
                }
                normalize_optional_string_field(recommendation_object, "rule_suggestion_key");
            }
        }
    }
    if !object.contains_key("suggested_local_rules") {
        object.insert(
            "suggested_local_rules".to_string(),
            serde_json::Value::Array(Vec::new()),
        );
    }
    if let Some(rules) = object
        .get_mut("suggested_local_rules")
        .and_then(|item| item.as_array_mut())
    {
        for rule in rules {
            if let Some(rule_object) = rule.as_object_mut() {
                normalize_scalar_string_field(rule_object, "key");
                normalize_scalar_string_field(rule_object, "title");
                normalize_scalar_string_field(rule_object, "policy_type");
                normalize_scalar_string_field(rule_object, "layer");
                normalize_scalar_string_field(rule_object, "scope_type");
                normalize_scalar_string_field(rule_object, "scope_value");
                normalize_scalar_string_field(rule_object, "target");
                normalize_scalar_string_field(rule_object, "action");
                normalize_scalar_string_field(rule_object, "operator");
                normalize_scalar_string_field(rule_object, "suggested_value");
                normalize_scalar_string_field(rule_object, "rationale");
                normalize_u64_field(rule_object, "ttl_secs");
                normalize_bool_field(rule_object, "auto_apply");
            }
        }
    }
}

fn normalize_string_or_array_field(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    let Some(value) = object.get_mut(key) else {
        return;
    };

    match value {
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                *value = serde_json::Value::Array(Vec::new());
            } else {
                *value =
                    serde_json::Value::Array(vec![serde_json::Value::String(trimmed.to_string())]);
            }
        }
        serde_json::Value::Array(items) => {
            let normalized = items
                .drain(..)
                .filter_map(|item| match item {
                    serde_json::Value::String(text) => {
                        let trimmed = text.trim().to_string();
                        (!trimmed.is_empty()).then(|| serde_json::Value::String(trimmed))
                    }
                    serde_json::Value::Null => None,
                    other => Some(serde_json::Value::String(
                        other.to_string().trim_matches('"').to_string(),
                    )),
                })
                .collect::<Vec<_>>();
            *items = normalized;
        }
        serde_json::Value::Null => {
            *value = serde_json::Value::Array(Vec::new());
        }
        other => {
            *other = serde_json::Value::Array(vec![serde_json::Value::String(other.to_string())]);
        }
    }
}

fn normalize_scalar_string_field(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    let Some(value) = object.get_mut(key) else {
        return;
    };

    match value {
        serde_json::Value::String(text) => {
            *text = text.trim().to_string();
        }
        serde_json::Value::Null => {
            *value = serde_json::Value::String(String::new());
        }
        other => {
            *other = serde_json::Value::String(other.to_string().trim_matches('"').to_string());
        }
    }
}

fn normalize_optional_string_field(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
) {
    let Some(value) = object.get_mut(key) else {
        return;
    };

    match value {
        serde_json::Value::Null => {}
        serde_json::Value::String(text) => {
            let trimmed = text.trim();
            if trimmed.is_empty() {
                *value = serde_json::Value::Null;
            } else {
                *text = trimmed.to_string();
            }
        }
        _ => {
            let normalized = value.to_string().trim_matches('"').trim().to_string();
            if normalized.is_empty() {
                *value = serde_json::Value::Null;
            } else {
                *value = serde_json::Value::String(normalized);
            }
        }
    }
}

fn normalize_u64_field(object: &mut serde_json::Map<String, serde_json::Value>, key: &str) {
    let Some(value) = object.get_mut(key) else {
        return;
    };

    let normalized = match value {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => text.trim().parse::<u64>().ok(),
        serde_json::Value::Bool(flag) => Some(u64::from(*flag)),
        _ => None,
    }
    .unwrap_or(0);

    *value = serde_json::Value::Number(serde_json::Number::from(normalized));
}

fn normalize_bool_field(object: &mut serde_json::Map<String, serde_json::Value>, key: &str) {
    let Some(value) = object.get_mut(key) else {
        return;
    };

    let normalized = match value {
        serde_json::Value::Bool(flag) => *flag,
        serde_json::Value::Number(number) => number.as_u64().map(|raw| raw != 0).unwrap_or(false),
        serde_json::Value::String(text) => matches!(
            text.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        _ => false,
    };

    *value = serde_json::Value::Bool(normalized);
}

pub(super) fn provider_from_config(config: &AiAuditConfig) -> AiAuditProvider {
    match config.provider {
        AiAuditProviderConfig::StubModel => AiAuditProvider::StubModel,
        AiAuditProviderConfig::OpenAiCompatible => AiAuditProvider::OpenAiCompatible,
        AiAuditProviderConfig::XiaomiMimo => AiAuditProvider::XiaomiMimo,
        AiAuditProviderConfig::LocalRules => AiAuditProvider::LocalRules,
    }
}

pub(super) fn normalize_risk_level(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" | "medium" | "high" | "critical" => value.trim().to_ascii_lowercase(),
        _ => "medium".to_string(),
    }
}

pub(super) fn normalize_action_type(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "observe" | "tune_threshold" | "add_rule" | "investigate" => {
            value.trim().to_ascii_lowercase()
        }
        _ => "observe".to_string(),
    }
}

pub(super) fn normalize_rule_layer(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "l4" | "l7" => value.trim().to_ascii_lowercase(),
        _ => "l7".to_string(),
    }
}

pub(super) fn normalize_policy_action(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "tighten_route_cc"
        | "tighten_host_cc"
        | "raise_identity_risk"
        | "add_behavior_watch"
        | "add_temp_block"
        | "increase_challenge"
        | "increase_delay"
        | "watch_only" => value.trim().to_ascii_lowercase(),
        _ => "watch_only".to_string(),
    }
}

pub(super) fn normalize_severity(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" | "medium" | "high" | "critical" => value.trim().to_ascii_lowercase(),
        _ => "medium".to_string(),
    }
}

pub(super) fn normalize_priority(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "low" | "medium" | "high" | "urgent" => value.trim().to_ascii_lowercase(),
        _ => "medium".to_string(),
    }
}

fn strip_markdown_fences(content: &str) -> &str {
    let trimmed = content.trim();
    if let Some(stripped) = trimmed.strip_prefix("```json") {
        return stripped.strip_suffix("```").unwrap_or(stripped).trim();
    }
    if let Some(stripped) = trimmed.strip_prefix("```") {
        return stripped.strip_suffix("```").unwrap_or(stripped).trim();
    }
    trimmed
}

pub(super) fn non_empty(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

pub(super) fn truncate_for_error(body: &str) -> String {
    const MAX_LEN: usize = 240;
    let body = body.trim();
    if body.chars().count() <= MAX_LEN {
        body.to_string()
    } else {
        format!("{}...", body.chars().take(MAX_LEN).collect::<String>())
    }
}
