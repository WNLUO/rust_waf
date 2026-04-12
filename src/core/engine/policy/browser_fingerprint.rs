use super::*;

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
    let provider_event_id = provided_provider_event_id.unwrap_or(derived_provider_event_id);

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

    let details_json = match serde_json::to_string_pretty(&payload) {
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

    let mut event = SecurityEventRecord::now(
        "L7",
        "respond",
        build_browser_fingerprint_reason(&provider_event_id, &payload),
        source_ip,
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

    json_http_response(
        202,
        serde_json::json!({
            "success": true,
            "message": "浏览器指纹已接收并写入事件库",
            "fingerprint_id": provider_event_id,
        }),
        &[],
    )
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
