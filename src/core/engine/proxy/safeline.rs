use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
struct SafeLineInterceptMatch {
    event_id: Option<String>,
    evidence: &'static str,
}

#[derive(Debug, Clone)]
pub(crate) enum UpstreamResponseDisposition {
    Forward(UpstreamHttpResponse),
    Custom(CustomHttpResponse),
    Drop,
}

pub(crate) fn apply_safeline_upstream_action(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    matched_site: Option<&GatewaySiteRuntime>,
    intercept_config: &SafeLineInterceptConfig,
    response: UpstreamHttpResponse,
) -> UpstreamResponseDisposition {
    if !intercept_config.enabled {
        return UpstreamResponseDisposition::Forward(response);
    }

    let Some(matched) = detect_safeline_block_response(
        &response,
        intercept_config.max_body_bytes,
        intercept_config.match_mode,
    ) else {
        return UpstreamResponseDisposition::Forward(response);
    };
    let response_status = response.status_code;

    let (local_action, disposition) = match intercept_config.action {
        SafeLineInterceptAction::Pass => ("pass", UpstreamResponseDisposition::Forward(response)),
        SafeLineInterceptAction::Replace => {
            match crate::rules::build_custom_response(&intercept_config.response_template) {
                Ok(custom) => ("replace", UpstreamResponseDisposition::Custom(custom)),
                Err(err) => {
                    warn!(
                        "Failed to build SafeLine replacement response, falling back to upstream response: {}",
                        err
                    );
                    ("pass", UpstreamResponseDisposition::Forward(response))
                }
            }
        }
        SafeLineInterceptAction::Drop => ("drop", UpstreamResponseDisposition::Drop),
        SafeLineInterceptAction::ReplaceAndBlockIp => {
            match crate::rules::build_custom_response(&intercept_config.response_template) {
                Ok(custom) => {
                    persist_safeline_intercept_blocked_ip(
                        context,
                        packet,
                        request,
                        intercept_config.block_duration_secs,
                        matched.event_id.as_deref(),
                    );
                    (
                        "replace_and_block_ip",
                        UpstreamResponseDisposition::Custom(custom),
                    )
                }
                Err(err) => {
                    warn!(
                        "Failed to build SafeLine replacement response for replace_and_block_ip, falling back to upstream response: {}",
                        err
                    );
                    ("pass", UpstreamResponseDisposition::Forward(response))
                }
            }
        }
    };

    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_block(InspectionLayer::L7);
    }
    if let Some(inspector) = context.l4_inspector() {
        inspector.record_l7_feedback(
            packet,
            request,
            crate::l4::behavior::FeedbackSource::SafeLine,
        );
    }
    persist_safeline_intercept_event(
        context,
        packet,
        request,
        matched_site,
        matched.event_id.as_deref(),
        matched.evidence,
        response_status,
        local_action,
    );

    disposition
}

fn detect_safeline_block_response(
    response: &UpstreamHttpResponse,
    max_body_bytes: usize,
    match_mode: SafeLineInterceptMatchMode,
) -> Option<SafeLineInterceptMatch> {
    let body = decode_response_body_for_matching(response, max_body_bytes)?;
    let has_body_signature = body_has_safeline_signature(&body);
    let has_header_signature = headers_have_safeline_signature(&response.headers);
    let has_signature = has_body_signature || has_header_signature;

    if let Some(event_id) = extract_html_comment_event_id(&body) {
        return Some(SafeLineInterceptMatch {
            event_id: Some(event_id),
            evidence: "html_event_comment",
        });
    }

    let json_event_id = extract_json_event_id(&body);
    if has_signature && json_event_id.is_some() {
        return Some(SafeLineInterceptMatch {
            event_id: json_event_id,
            evidence: "json_signature",
        });
    }

    if has_signature && matches!(response.status_code, 403 | 405) {
        return Some(SafeLineInterceptMatch {
            event_id: None,
            evidence: "status_and_signature",
        });
    }

    if matches!(match_mode, SafeLineInterceptMatchMode::Relaxed)
        && matches!(response.status_code, 403 | 405)
    {
        return Some(SafeLineInterceptMatch {
            event_id: None,
            evidence: "status_only_relaxed",
        });
    }

    None
}

fn decode_response_body_for_matching(
    response: &UpstreamHttpResponse,
    max_body_bytes: usize,
) -> Option<String> {
    let limit = max_body_bytes.max(256);
    let mut decoded = Vec::new();

    match upstream_header_value(&response.headers, "content-encoding")
        .map(|value| value.to_ascii_lowercase())
    {
        Some(value) if value.contains("gzip") => {
            let decoder = GzDecoder::new(response.body.as_slice());
            decoder.take(limit as u64).read_to_end(&mut decoded).ok()?;
        }
        Some(value) if value.contains("deflate") => {
            let decoder = ZlibDecoder::new(response.body.as_slice());
            decoder.take(limit as u64).read_to_end(&mut decoded).ok()?;
        }
        Some(value) if value.contains("br") => {
            let decoder = Decompressor::new(response.body.as_slice(), 4096);
            decoder.take(limit as u64).read_to_end(&mut decoded).ok()?;
        }
        Some(_) | None => {
            decoded.extend_from_slice(&response.body[..response.body.len().min(limit)]);
        }
    }

    Some(String::from_utf8_lossy(&decoded).into_owned())
}

fn upstream_header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn extract_json_event_id(body: &str) -> Option<String> {
    let payload = serde_json::from_str::<serde_json::Value>(body).ok()?;
    extract_json_string_by_keys(
        &payload,
        &["event_id", "eventId", "eventID", "log_id", "logId"],
    )
}

fn extract_html_comment_event_id(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    for marker in ["<!-- event_id:", "<!-- event-id:", "<!-- event id:"] {
        let Some(start) = lower.find(marker) else {
            continue;
        };
        let value_start = start + marker.len();
        let Some(remainder) = body.get(value_start..) else {
            continue;
        };
        let Some(end) = remainder.find("-->") else {
            continue;
        };
        let candidate = remainder.get(..end)?.trim();
        let event_id = candidate.split_whitespace().next()?.trim();
        if is_valid_safeline_event_id(event_id) {
            return Some(event_id.to_string());
        }
    }

    None
}

fn body_has_safeline_signature(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    let mentions_safeline = lower.contains("safeline") || lower.contains("chaitin");
    let mentions_block = lower.contains("blocked")
        || lower.contains("forbidden")
        || lower.contains("intercept")
        || lower.contains("web application firewall")
        || lower.contains("\"code\":403")
        || lower.contains("\"status\":403");

    mentions_safeline && mentions_block
}

fn headers_have_safeline_signature(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(key, value)| {
        let key = key.to_ascii_lowercase();
        let value = value.to_ascii_lowercase();
        (matches!(
            key.as_str(),
            "server" | "x-powered-by" | "x-waf" | "x-safeline-event-id" | "x-request-id"
        ) && (value.contains("safeline") || value.contains("chaitin")))
            || (key == "set-cookie" && value.contains("sl-session="))
    })
}

fn extract_json_string_by_keys(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for key in keys {
                if let Some(candidate) = map
                    .get(*key)
                    .and_then(|item| item.as_str())
                    .filter(|item| is_valid_safeline_event_id(item))
                {
                    return Some(candidate.to_string());
                }
            }

            map.values()
                .find_map(|item| extract_json_string_by_keys(item, keys))
        }
        serde_json::Value::Array(items) => items
            .iter()
            .find_map(|item| extract_json_string_by_keys(item, keys)),
        _ => None,
    }
}

fn is_valid_safeline_event_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':'))
}
