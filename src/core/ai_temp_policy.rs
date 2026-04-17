use crate::protocol::UnifiedHttpRequest;
use crate::storage::AiTempPolicyEntry;
use std::net::IpAddr;

pub(super) fn ai_request_identity(request: &UnifiedHttpRequest) -> Option<String> {
    fn cookie_value(request: &UnifiedHttpRequest, name: &str) -> Option<String> {
        let raw = request.get_header("cookie")?;
        raw.split(';').find_map(|segment| {
            let mut parts = segment.trim().splitn(2, '=');
            let key = parts.next()?.trim();
            let value = parts.next()?.trim();
            (key.eq_ignore_ascii_case(name) && !value.is_empty()).then(|| value.to_string())
        })
    }

    if let Some(value) = cookie_value(request, "rwaf_fp") {
        return Some(format!("fp:{value}"));
    }
    if let Some(value) = request.get_header("x-browser-fingerprint-id") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(format!("fp:{trimmed}"));
        }
    }
    let ip = request.client_ip.as_deref()?.trim();
    if ip.is_empty() {
        return None;
    }
    let ua = request
        .get_header("user-agent")
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .unwrap_or("-");
    Some(format!("ipua:{ip}|{ua}"))
}

pub(super) fn parse_scale_percent(value: &str) -> Option<u32> {
    let digits = value
        .chars()
        .filter(|char| char.is_ascii_digit())
        .collect::<String>();
    let parsed = digits.parse::<u32>().ok()?;
    (parsed > 0).then_some(parsed.min(100))
}

pub(super) fn parse_suggested_delay_ms(value: &str) -> Option<u64> {
    let digits = value
        .chars()
        .filter(|char| char.is_ascii_digit())
        .collect::<String>();
    digits.parse::<u64>().ok()
}

#[derive(Debug, Clone)]
pub(super) struct AiTempPolicyMatch {
    pub(super) match_mode: String,
    pub(super) matched_value: String,
}

pub(super) fn match_ai_temp_policy(
    policy: &AiTempPolicyEntry,
    host: &str,
    route: &str,
    client_ip: &str,
    identity: Option<&str>,
) -> Option<AiTempPolicyMatch> {
    let operator = policy.operator.trim().to_ascii_lowercase();
    match policy.scope_type.as_str() {
        "host" => match_string_scope(host, &policy.scope_value, &operator, true),
        "route" => match_string_scope(route, &policy.scope_value, &operator, false),
        "source_ip" => match_ip_scope(client_ip, &policy.scope_value, &operator),
        "identity" => match_string_scope(
            identity.unwrap_or_default(),
            &policy.scope_value,
            &operator,
            false,
        ),
        _ => None,
    }
}

fn match_string_scope(
    actual: &str,
    expected: &str,
    operator: &str,
    case_insensitive: bool,
) -> Option<AiTempPolicyMatch> {
    let actual = actual.trim();
    let expected = expected.trim();
    if actual.is_empty() || expected.is_empty() {
        return None;
    }

    let actual_cmp = if case_insensitive {
        actual.to_ascii_lowercase()
    } else {
        actual.to_string()
    };
    let expected_cmp = if case_insensitive {
        expected.to_ascii_lowercase()
    } else {
        expected.to_string()
    };

    if expected_cmp == actual_cmp {
        return Some(AiTempPolicyMatch {
            match_mode: "exact".to_string(),
            matched_value: actual.to_string(),
        });
    }

    let prefix_enabled =
        operator == "prefix" || operator == "starts_with" || expected_cmp.ends_with('*');
    if prefix_enabled {
        let prefix = expected_cmp.trim_end_matches('*').trim_end();
        if !prefix.is_empty() && actual_cmp.starts_with(prefix) {
            return Some(AiTempPolicyMatch {
                match_mode: "prefix".to_string(),
                matched_value: actual.to_string(),
            });
        }
    }

    let suffix_enabled = operator == "suffix"
        || operator == "ends_with"
        || expected_cmp.starts_with("*.")
        || expected_cmp.starts_with('.');
    if suffix_enabled {
        let suffix = expected_cmp.trim_start_matches('*').trim_start();
        if !suffix.is_empty() && actual_cmp.ends_with(suffix) {
            return Some(AiTempPolicyMatch {
                match_mode: "suffix".to_string(),
                matched_value: actual.to_string(),
            });
        }
    }

    let contains_enabled = operator == "contains";
    if contains_enabled && actual_cmp.contains(&expected_cmp) {
        return Some(AiTempPolicyMatch {
            match_mode: "contains".to_string(),
            matched_value: actual.to_string(),
        });
    }

    None
}

fn match_ip_scope(actual: &str, expected: &str, operator: &str) -> Option<AiTempPolicyMatch> {
    let actual = actual.trim();
    let expected = expected.trim();
    if actual.is_empty() || expected.is_empty() {
        return None;
    }
    if actual == expected {
        return Some(AiTempPolicyMatch {
            match_mode: "exact".to_string(),
            matched_value: actual.to_string(),
        });
    }
    if operator == "cidr" || expected.contains('/') {
        if ip_matches_cidr(actual, expected) {
            return Some(AiTempPolicyMatch {
                match_mode: "cidr".to_string(),
                matched_value: actual.to_string(),
            });
        }
    }
    None
}

fn ip_matches_cidr(actual: &str, cidr: &str) -> bool {
    let (base, prefix) = match cidr.split_once('/') {
        Some(parts) => parts,
        None => return false,
    };
    let Ok(actual_ip) = actual.parse::<IpAddr>() else {
        return false;
    };
    let Ok(base_ip) = base.trim().parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix_len) = prefix.trim().parse::<u8>() else {
        return false;
    };
    match (actual_ip, base_ip) {
        (IpAddr::V4(actual_v4), IpAddr::V4(base_v4)) if prefix_len <= 32 => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(prefix_len))
            };
            (u32::from(actual_v4) & mask) == (u32::from(base_v4) & mask)
        }
        (IpAddr::V6(actual_v6), IpAddr::V6(base_v6)) if prefix_len <= 128 => {
            let actual_value = u128::from_be_bytes(actual_v6.octets());
            let base_value = u128::from_be_bytes(base_v6.octets());
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(prefix_len))
            };
            (actual_value & mask) == (base_value & mask)
        }
        _ => false,
    }
}
