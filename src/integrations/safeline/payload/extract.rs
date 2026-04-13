use super::*;

pub(crate) fn extract_sites(payload: &Value) -> Result<Vec<SafeLineSiteSummary>> {
    let candidates = find_array_candidates(payload);
    for candidate in candidates {
        let sites = candidate
            .iter()
            .filter_map(parse_site_summary)
            .collect::<Vec<_>>();
        if !sites.is_empty() {
            return Ok(sites);
        }
    }

    Err(anyhow!(
        "已拿到雷池响应，但未能从 JSON 中识别站点数组。请检查 site_list_path 是否正确，或根据目标实例实际返回结构补充解析规则。"
    ))
}

pub(crate) fn extract_security_events(
    payload: &Value,
) -> Result<Vec<SafeLineSecurityEventSummary>> {
    let candidates = find_array_candidates(payload);
    for candidate in candidates {
        let events = candidate
            .iter()
            .filter_map(parse_security_event_summary)
            .collect::<Vec<_>>();
        if !events.is_empty() {
            return Ok(events);
        }
    }

    Err(anyhow!(
        "已拿到雷池响应，但未能从 JSON 中识别事件数组。请检查 event_list_path 是否正确，或根据目标实例实际返回结构补充解析规则。"
    ))
}

pub(crate) fn extract_blocked_ips(payload: &Value) -> Result<Vec<SafeLineBlockedIpSummary>> {
    let candidates = find_array_candidates(payload);
    for candidate in candidates {
        let recognized_candidate = candidate.iter().any(looks_like_blocked_ip_summary);
        let records = candidate
            .iter()
            .flat_map(parse_blocked_ip_summaries)
            .collect::<Vec<_>>();
        if !records.is_empty() || recognized_candidate {
            return Ok(records);
        }
    }

    Err(anyhow!(
        "已拿到雷池响应，但未能从 JSON 中识别封禁列表数组。请检查 blocklist_sync_path 是否正确，或根据目标实例实际返回结构补充解析规则。"
    ))
}

pub(crate) fn extract_certificates(payload: &Value) -> Result<Vec<SafeLineCertificateSummary>> {
    let candidates = find_array_candidates(payload);
    for candidate in candidates {
        let certificates = candidate
            .iter()
            .filter_map(parse_certificate_summary)
            .collect::<Vec<_>>();
        if !certificates.is_empty() {
            return Ok(certificates);
        }
    }

    Err(anyhow!(
        "已拿到雷池响应，但未能从 JSON 中识别证书数组。请检查 /api/open/cert 的返回结构。"
    ))
}

pub(crate) fn parse_certificate_detail(payload: &Value) -> Option<SafeLineCertificateDetail> {
    let object = find_object_candidates(payload)
        .into_iter()
        .find(|candidate| candidate.contains_key("manual") || candidate.contains_key("acme"))?;
    let id = pick_string(object, &["id", "cert_id", "uuid", "uid"])?;
    let manual = object.get("manual").and_then(Value::as_object);
    let acme = object.get("acme").and_then(Value::as_object);
    let domains = pick_array_strings(object, &["domains"])
        .or_else(|| acme.and_then(|item| pick_array_strings(item, &["domains"])))
        .unwrap_or_default();

    Some(SafeLineCertificateDetail {
        id,
        domains,
        cert_type: pick_i64(object, &["type", "cert_type"]),
        certificate_pem: manual.and_then(|item| pick_string(item, &["crt", "cert", "fullchain"])),
        private_key_pem: manual.and_then(|item| pick_string(item, &["key", "private_key"])),
        raw: payload.clone(),
    })
}

fn find_array_candidates(value: &Value) -> Vec<&Vec<Value>> {
    let mut candidates = Vec::new();
    collect_array_candidates(value, &mut candidates);
    candidates
}

fn collect_array_candidates<'a>(value: &'a Value, candidates: &mut Vec<&'a Vec<Value>>) {
    if let Some(array) = value.as_array() {
        candidates.push(array);
        for item in array {
            collect_array_candidates(item, candidates);
        }
        return;
    }

    let Some(object) = value.as_object() else {
        return;
    };

    for key in [
        "data", "list", "items", "nodes", "results", "rows", "records", "objs", "objects",
    ] {
        if let Some(child) = object.get(key) {
            collect_array_candidates(child, candidates);
        }
    }

    for child in object.values() {
        if child.is_object() {
            collect_array_candidates(child, candidates);
        }
    }
}

fn find_object_candidates(value: &Value) -> Vec<&serde_json::Map<String, Value>> {
    let mut candidates = Vec::new();
    collect_object_candidates(value, &mut candidates);
    candidates
}

fn collect_object_candidates<'a>(
    value: &'a Value,
    candidates: &mut Vec<&'a serde_json::Map<String, Value>>,
) {
    if let Some(object) = value.as_object() {
        candidates.push(object);
        for child in object.values() {
            collect_object_candidates(child, candidates);
        }
        return;
    }

    if let Some(array) = value.as_array() {
        for item in array {
            collect_object_candidates(item, candidates);
        }
    }
}
