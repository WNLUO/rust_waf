use super::*;
use dashmap::DashMap;
use std::sync::OnceLock;

const FINGERPRINT_COOKIE_NAME: &str = "rwaf_fp";
const FINGERPRINT_COOKIE_MAX_AGE_SECS: u64 = 30 * 24 * 3600;
const FINGERPRINT_REPORT_CACHE_MAX_ENTRIES: usize = 4_096;
const FINGERPRINT_REPORT_CACHE_TTL_NORMAL_SECS: i64 = 10 * 60;
const FINGERPRINT_REPORT_CACHE_TTL_ATTACK_SECS: i64 = 30 * 60;
const FINGERPRINT_REPORT_CACHE_KEY_COMPONENT_LIMIT: usize = 96;

static BROWSER_FINGERPRINT_REPORT_CACHE: OnceLock<DashMap<String, FingerprintReportCacheEntry>> =
    OnceLock::new();

#[derive(Debug, Clone)]
struct FingerprintReportCacheEntry {
    provider_event_id: String,
    stored_at: i64,
}

pub(crate) fn try_handle_browser_fingerprint_report(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    matched_site: Option<&GatewaySiteRuntime>,
) -> Option<CustomHttpResponse> {
    if request_path(&request.uri) != BROWSER_FINGERPRINT_REPORT_PATH {
        return None;
    }

    Some(handle_browser_fingerprint_report(
        context,
        packet,
        request,
        matched_site,
    ))
}

fn handle_browser_fingerprint_report(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    matched_site: Option<&GatewaySiteRuntime>,
) -> CustomHttpResponse {
    let pressure = context.runtime_pressure_snapshot();
    if !request.method.eq_ignore_ascii_case("POST") {
        return json_http_response(
            405,
            serde_json::json!({
                "success": false,
                "message": "浏览器指纹上报只接受 POST 请求",
            }),
            &[("allow", "POST")],
        );
    }

    let Some(store) = context.sqlite_store.as_ref() else {
        return json_http_response(
            503,
            serde_json::json!({
                "success": false,
                "message": "SQLite 事件存储未启用，无法落库浏览器指纹",
            }),
            &[],
        );
    };

    if request.body.is_empty() {
        return json_http_response(
            400,
            serde_json::json!({
                "success": false,
                "message": "浏览器指纹上报体不能为空",
            }),
            &[],
        );
    }

    if request.body.len() > MAX_BROWSER_FINGERPRINT_DETAILS_BYTES {
        return json_http_response(
            413,
            serde_json::json!({
                "success": false,
                "message": format!(
                    "浏览器指纹上报体过大，最大允许 {} 字节",
                    MAX_BROWSER_FINGERPRINT_DETAILS_BYTES
                ),
            }),
            &[],
        );
    }

    let challenge_verified = context
        .l7_cc_guard()
        .allows_browser_fingerprint_report(request, packet.source_ip);
    if !challenge_verified {
        let status_code = if matches!(pressure.level, "high" | "attack") {
            204
        } else {
            202
        };
        return json_http_response(
            status_code,
            serde_json::json!({
                "success": true,
                "message": "浏览器指纹上报已忽略，当前请求未绑定有效挑战会话",
            }),
            &[],
        );
    }

    let mut payload = match serde_json::from_slice::<serde_json::Value>(&request.body) {
        Ok(value) => value,
        Err(err) => {
            return json_http_response(
                400,
                serde_json::json!({
                    "success": false,
                    "message": format!("浏览器指纹上报不是合法 JSON: {}", err),
                }),
                &[],
            );
        }
    };

    let provided_provider_event_id = payload
        .get("fingerprintId")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let derived_provider_event_id = derive_browser_fingerprint_id(&payload);
    let provider_event_id = provided_provider_event_id.unwrap_or(derived_provider_event_id);
    context.note_visitor_fingerprint_report(request, &provider_event_id, Some(&payload));

    let Some(payload_object) = payload.as_object_mut() else {
        return json_http_response(
            400,
            serde_json::json!({
                "success": false,
                "message": "浏览器指纹上报必须是 JSON 对象",
            }),
            &[],
        );
    };

    let source_ip = request
        .client_ip
        .clone()
        .unwrap_or_else(|| packet.source_ip.to_string());

    payload_object.insert(
        "fingerprintId".to_string(),
        serde_json::Value::String(provider_event_id.clone()),
    );
    payload_object.insert(
        "server".to_string(),
        serde_json::json!({
            "received_at": unix_timestamp(),
            "client_ip": source_ip.clone(),
            "request_id": request.get_header("x-request-id").cloned(),
            "host": request_hostname(request),
            "uri": request.uri,
            "method": request.method,
            "http_version": request.version.to_string(),
            "listener_port": request.get_metadata("listener_port").cloned(),
            "site_id": matched_site.map(|site| site.id),
            "site_name": matched_site.map(|site| site.name.clone()),
            "site_primary_hostname": matched_site.map(|site| site.primary_hostname.clone()),
        }),
    );

    let details_json = match serde_json::to_string_pretty(&summarize_fingerprint_payload(&payload))
    {
        Ok(serialized) => serialized,
        Err(err) => {
            return json_http_response(
                500,
                serde_json::json!({
                    "success": false,
                    "message": format!("浏览器指纹序列化失败: {}", err),
                }),
                &[],
            );
        }
    };

    if details_json.len() > MAX_BROWSER_FINGERPRINT_DETAILS_BYTES {
        return json_http_response(
            413,
            serde_json::json!({
                "success": false,
                "message": format!(
                    "浏览器指纹详情过大，最大允许 {} 字节",
                    MAX_BROWSER_FINGERPRINT_DETAILS_BYTES
                ),
            }),
            &[],
        );
    }

    let should_persist =
        claim_browser_fingerprint_report_slot(&source_ip, &provider_event_id, pressure.level);
    if should_persist {
        let mut event = SecurityEventRecord::now(
            "L7",
            "respond",
            build_browser_fingerprint_reason(&provider_event_id, &payload),
            source_ip.clone(),
            packet.dest_ip.to_string(),
            packet.source_port,
            packet.dest_port,
            format!("{:?}", packet.protocol),
        );
        event.provider = Some("browser_fingerprint".to_string());
        event.provider_event_id = Some(provider_event_id.clone());
        event.provider_site_id = matched_site.map(|site| site.id.to_string());
        event.provider_site_name = matched_site.map(|site| site.name.clone());
        event.provider_site_domain = request_hostname(request)
            .or_else(|| matched_site.map(|site| site.primary_hostname.clone()));
        event.http_method = Some(request.method.clone());
        event.uri = Some(request.uri.clone());
        event.http_version = Some(request.version.to_string());
        event.details_json = Some(details_json);
        store.enqueue_security_event(event);
    }

    let mut response = json_http_response(
        202,
        serde_json::json!({
            "success": true,
            "message": if should_persist {
                "浏览器指纹已接收并写入事件库"
            } else {
                "浏览器指纹已接收，重复上报已折叠"
            },
            "fingerprint_id": provider_event_id,
        }),
        &[],
    );
    response.headers.push((
        "set-cookie".to_string(),
        format!(
            "{FINGERPRINT_COOKIE_NAME}={}; Path=/; Max-Age={FINGERPRINT_COOKIE_MAX_AGE_SECS}; HttpOnly; SameSite=Lax",
            provider_event_id
        ),
    ));
    response
        .headers
        .push(("x-browser-fingerprint-id".to_string(), provider_event_id));
    if !should_persist {
        response.headers.push((
            "x-browser-fingerprint-deduped".to_string(),
            "true".to_string(),
        ));
    }
    response
}

fn claim_browser_fingerprint_report_slot(
    source_ip: &str,
    provider_event_id: &str,
    pressure_level: &str,
) -> bool {
    let cache = BROWSER_FINGERPRINT_REPORT_CACHE.get_or_init(DashMap::new);
    let now = unix_timestamp();
    let ttl_secs = if matches!(pressure_level, "high" | "attack") {
        FINGERPRINT_REPORT_CACHE_TTL_ATTACK_SECS
    } else {
        FINGERPRINT_REPORT_CACHE_TTL_NORMAL_SECS
    };
    let key = fingerprint_report_cache_key(source_ip, provider_event_id);

    if let Some(entry) = cache.get(&key) {
        if now.saturating_sub(entry.stored_at) < ttl_secs {
            return false;
        }
    }

    cleanup_fingerprint_report_cache(cache, now, ttl_secs);
    if cache.len() >= FINGERPRINT_REPORT_CACHE_MAX_ENTRIES && !cache.contains_key(&key) {
        return false;
    }

    cache.insert(
        key,
        FingerprintReportCacheEntry {
            provider_event_id: provider_event_id.to_string(),
            stored_at: now,
        },
    );
    true
}

fn cleanup_fingerprint_report_cache(
    cache: &DashMap<String, FingerprintReportCacheEntry>,
    now: i64,
    ttl_secs: i64,
) {
    let stale_before = now.saturating_sub(ttl_secs);
    let stale_keys = cache
        .iter()
        .filter(|entry| entry.stored_at < stale_before)
        .map(|entry| entry.key().clone())
        .collect::<Vec<_>>();
    for key in stale_keys {
        cache.remove(&key);
    }

    if cache.len() <= FINGERPRINT_REPORT_CACHE_MAX_ENTRIES {
        return;
    }

    let mut oldest_entries = cache
        .iter()
        .map(|entry| {
            (
                entry.key().clone(),
                entry.stored_at,
                entry.provider_event_id.len(),
            )
        })
        .collect::<Vec<_>>();
    oldest_entries.sort_by(|left, right| {
        left.1
            .cmp(&right.1)
            .then(left.2.cmp(&right.2))
            .then(left.0.cmp(&right.0))
    });

    for (key, _, _) in oldest_entries.into_iter().take(
        cache
            .len()
            .saturating_sub(FINGERPRINT_REPORT_CACHE_MAX_ENTRIES),
    ) {
        cache.remove(&key);
    }
}

fn fingerprint_report_cache_key(source_ip: &str, provider_event_id: &str) -> String {
    format!(
        "{}|{}",
        compact_component(source_ip),
        compact_component(provider_event_id)
    )
}

fn compact_component(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= FINGERPRINT_REPORT_CACHE_KEY_COMPONENT_LIMIT {
        return trimmed.to_string();
    }

    let mut hasher = Sha256::new();
    hasher.update(trimmed.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    let prefix_len = FINGERPRINT_REPORT_CACHE_KEY_COMPONENT_LIMIT.saturating_sub(17);
    let prefix = trimmed.chars().take(prefix_len).collect::<String>();
    format!("{prefix}:{}", &digest[..16])
}

fn build_browser_fingerprint_reason(
    provider_event_id: &str,
    payload: &serde_json::Value,
) -> String {
    let timezone = payload
        .get("timezone")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let platform = payload
        .get("platform")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let fonts = payload
        .get("fonts")
        .and_then(|value| value.as_array())
        .map(|items| items.len())
        .unwrap_or(0);
    format!(
        "浏览器指纹回传 fp={} tz={} platform={} fonts={}",
        provider_event_id, timezone, platform, fonts
    )
}

fn derive_browser_fingerprint_id(payload: &serde_json::Value) -> String {
    let serialized = serde_json::to_vec(payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&serialized);
    format!("{:x}", hasher.finalize())
        .chars()
        .take(24)
        .collect()
}

fn summarize_fingerprint_payload(payload: &serde_json::Value) -> serde_json::Value {
    let fonts = payload
        .get("fonts")
        .and_then(|value| value.as_array())
        .map(|items| items.len())
        .unwrap_or(0);
    let plugins = payload
        .get("plugins")
        .and_then(|value| value.as_array())
        .map(|items| items.len())
        .unwrap_or(0);

    serde_json::json!({
        "fingerprintId": payload.get("fingerprintId").cloned(),
        "user_agent": payload.get("ua").cloned().or_else(|| payload.get("userAgent").cloned()),
        "lang": payload.get("lang").cloned(),
        "langs": payload.get("langs").cloned(),
        "platform": payload.get("platform").cloned(),
        "mobile": payload.get("mobile").cloned(),
        "memory": payload.get("memory").cloned(),
        "cores": payload.get("cores").cloned(),
        "screen": payload.get("screen").cloned(),
        "viewport": payload.get("viewport").cloned(),
        "timezone": payload.get("timezone").cloned(),
        "touch": payload.get("touch").cloned(),
        "fonts_count": fonts,
        "plugins_count": plugins,
        "server": payload.get("server").cloned(),
    })
}

fn json_http_response(
    status_code: u16,
    body: serde_json::Value,
    extra_headers: &[(&str, &str)],
) -> CustomHttpResponse {
    let mut headers = vec![
        (
            "content-type".to_string(),
            "application/json; charset=utf-8".to_string(),
        ),
        ("cache-control".to_string(), "no-store".to_string()),
    ];
    headers.extend(
        extra_headers
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string())),
    );

    CustomHttpResponse {
        status_code,
        headers,
        body: serde_json::to_vec(&body).unwrap_or_else(|_| {
            br#"{"success":false,"message":"response serialization failed"}"#.to_vec()
        }),
        tarpit: None,
        random_status: None,
    }
}

fn request_path(uri: &str) -> &str {
    uri.split('?').next().unwrap_or(uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_fingerprint_reports_are_folded_within_ttl() {
        let cache = BROWSER_FINGERPRINT_REPORT_CACHE.get_or_init(DashMap::new);
        cache.clear();

        assert!(claim_browser_fingerprint_report_slot(
            "203.0.113.10",
            "fp-123",
            "normal"
        ));
        assert!(!claim_browser_fingerprint_report_slot(
            "203.0.113.10",
            "fp-123",
            "normal"
        ));
    }

    #[test]
    fn fingerprint_report_cache_key_compacts_long_components() {
        let key = fingerprint_report_cache_key(&"1".repeat(256), &"a".repeat(256));
        assert!(key.len() < 240);
        assert!(key.contains(':'));
    }
}
