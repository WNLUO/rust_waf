use super::decision::result_should_drop_http1;
use super::feedback::{enforce_and_record_l7_block_feedback, record_l7_block_feedback};
use super::proxy_flow::{handle_http1_proxy_or_local_response, Http1RequestFlow};
use super::response::write_custom_http1_response;
use super::slow_attack::handle_slow_attack_error;
use super::*;
use crate::core::engine::policy::persist_http_identity_debug_event;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub(crate) async fn handle_http1_connection(
    context: Arc<WafContext>,
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
    extra_metadata: Vec<(String, String)>,
    _connection_permit: OwnedSemaphorePermit,
    request_semaphore: Arc<Semaphore>,
) -> Result<()> {
    let config = context.config_snapshot();
    let http1_handler = Http1Handler::new();
    let mut reusable_upstream_connection = None;
    let mut requests_seen = 0u64;
    let connection_id = extra_metadata
        .iter()
        .find(|(key, _)| key == "network.connection_id")
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let opened_at = std::time::Instant::now();
    let mut bucket_key = None;
    let trusted_proxy_peer = peer_is_configured_trusted_proxy(context.as_ref(), packet.source_ip);
    let skip_l4_connection_budget =
        should_skip_l4_connection_budget_for_trusted_proxy(context.as_ref(), packet.source_ip);

    loop {
        let first_byte_timeout_ms = if requests_seen == 0 {
            config.l7_config.first_byte_timeout_ms
        } else {
            config
                .l7_config
                .slow_attack_defense
                .idle_keepalive_timeout_ms
        };
        let (mut request, pending_body) = match http1_handler
            .read_request_head(
                &mut stream,
                config.l7_config.max_request_size,
                first_byte_timeout_ms,
                config.l7_config.read_idle_timeout_ms,
                config
                    .l7_config
                    .slow_attack_defense
                    .header_min_bytes_per_sec,
            )
            .await
        {
            Ok(request) => request,
            Err(err)
                if matches!(
                    err,
                    crate::protocol::ProtocolError::IdleTimeout { .. }
                        | crate::protocol::ProtocolError::SlowHeader { .. }
                ) =>
            {
                handle_slow_attack_error(
                    context.as_ref(),
                    &http1_handler,
                    &mut stream,
                    packet,
                    peer_addr,
                    &err,
                    trusted_proxy_peer,
                )
                .await?;
                if let (Some(inspector), Some(bucket_key)) =
                    (context.l4_inspector(), bucket_key.as_ref())
                {
                    inspector.observe_connection_close(bucket_key, &connection_id, opened_at);
                }
                return Ok(());
            }
            Err(err) => return Err(err.into()),
        };
        requests_seen = requests_seen.saturating_add(1);

        apply_client_identity(context.as_ref(), peer_addr, &mut request);
        request.add_metadata("listener_port".to_string(), packet.dest_port.to_string());
        request.add_metadata("protocol".to_string(), "HTTP/1.1".to_string());
        apply_server_public_ip_metadata(context.as_ref(), packet, &mut request);
        for (key, value) in &extra_metadata {
            request.add_metadata(key.clone(), value.clone());
        }
        if bucket_key.is_none() {
            if let Some(inspector) = context.l4_inspector() {
                let transport = request
                    .get_metadata("transport")
                    .map(String::as_str)
                    .unwrap_or("http");
                bucket_key = Some(inspector.observe_connection_open(
                    connection_id.clone(),
                    packet,
                    request.get_header("host").map(String::as_str),
                    None,
                    transport,
                    "http/1.1",
                    skip_l4_connection_budget,
                ));
            }
        }
        if !skip_l4_connection_budget {
            if let (Some(inspector), Some(bucket_key)) =
                (context.l4_inspector(), bucket_key.as_ref())
            {
                let policy = inspector.connection_admission_policy(bucket_key);
                maybe_delay_policy(context.as_ref(), &policy).await;
                if policy.reject_new_connections {
                    if let Some(metrics) = context.metrics.as_ref() {
                        metrics.record_l4_bucket_budget_rejection();
                    }
                    http1_handler
                        .write_response(
                            &mut stream,
                            429,
                            "Too Many Requests",
                            b"bucket connection budget exceeded",
                        )
                        .await?;
                    inspector.observe_connection_close(bucket_key, &connection_id, opened_at);
                    return Ok(());
                }
            }
        }
        let Some(_request_permit) = crate::core::engine::runtime::acquire_permit_auto(
            context.as_ref(),
            Arc::clone(&request_semaphore),
            peer_addr,
            "HTTP/1.1 request",
        )
        .await
        else {
            http1_handler
                .write_response_with_headers(
                    &mut stream,
                    503,
                    "Service Unavailable",
                    &[("Retry-After".to_string(), "5".to_string())],
                    b"gateway overloaded, retry later",
                )
                .await?;
            if let Some(bucket_key) = bucket_key.as_ref() {
                if let Some(inspector) = context.l4_inspector() {
                    inspector.observe_connection_close(bucket_key, &connection_id, opened_at);
                }
            }
            return Ok(());
        };
        prepare_request_for_routing(context.as_ref(), &mut request);
        context.annotate_runtime_pressure(&mut request);
        let matched_site = resolve_gateway_site(context.as_ref(), &request);
        if let Some(site) = matched_site.as_ref() {
            apply_gateway_site_metadata(&mut request, site);
        }
        context.annotate_site_runtime_budget(&mut request);
        if let Some(inspector) = context.l4_inspector() {
            let policy = inspector.apply_request_policy(packet, &mut request);
            if skip_l4_connection_budget
                && (policy.suggested_delay_ms > 0 || policy.disable_keepalive)
            {
                if let Some(metrics) = context.metrics.as_ref() {
                    metrics.record_trusted_proxy_l4_degrade_action();
                }
                debug!(
                    "Trusted proxy request downgraded by L4 policy on HTTP/1.1: peer_ip={} client_ip={} unresolved_client_ip={} delay_ms={} force_close={}",
                    peer_addr.ip(),
                    request.client_ip.as_deref().unwrap_or("unknown"),
                    request
                        .get_metadata("network.client_ip_unresolved")
                        .map(String::as_str)
                        .unwrap_or("false"),
                    policy.suggested_delay_ms,
                    policy.disable_keepalive
                );
            }
            maybe_delay_request(&request).await;
            if policy.reject_new_connections {
                if let Some(metrics) = context.metrics.as_ref() {
                    metrics.record_l4_request_budget_softened();
                }
                request.add_metadata("l4.force_close".to_string(), "true".to_string());
                request.add_metadata("proxy_connection_mode".to_string(), "close".to_string());
                request.add_metadata("l4.request_budget_softened".to_string(), "true".to_string());
            }
        }

        if let Some(result) = inspect_blocked_client_ip(context.as_ref(), &request).await {
            persist_http_inspection_event(context.as_ref(), packet, &request, &result);
            record_l7_block_feedback(context.as_ref(), packet, &request, &result);
            if result_should_drop_http1(&result, &request) {
                let _ = stream.shutdown().await;
                return Ok(());
            }
            http1_handler
                .write_response(&mut stream, 403, "Forbidden", result.reason.as_bytes())
                .await?;
            if !should_keep_client_connection_open(&request) {
                return Ok(());
            }
            continue;
        }

        if request.uri.is_empty() {
            debug!("Empty request from {}, ignoring", peer_addr);
            return Ok(());
        }

        if let Some(result) = context
            .ip_access_guard()
            .inspect_request(context.as_ref(), &mut request)
        {
            if let Some(metrics) = context.metrics.as_ref() {
                crate::core::engine::network::record_l7_ip_access_metrics(metrics, &request);
            }
            if !result.blocked {
                if result.should_persist_event() {
                    persist_http_inspection_event(context.as_ref(), packet, &request, &result);
                }
            } else {
                if result.should_persist_event() {
                    persist_http_inspection_event(context.as_ref(), packet, &request, &result);
                }
                record_l7_block_feedback(context.as_ref(), packet, &request, &result);
                if result_should_drop_http1(&result, &request) {
                    let _ = stream.shutdown().await;
                    return Ok(());
                }
                if let Some(response) = result.custom_response.as_ref() {
                    write_custom_http1_response(
                        context.as_ref(),
                        &http1_handler,
                        &mut stream,
                        &request,
                        response,
                        true,
                        false,
                    )
                    .await?;
                } else {
                    http1_handler
                        .write_response(&mut stream, 403, "Forbidden", result.reason.as_bytes())
                        .await?;
                }
                if !should_keep_client_connection_open(&request) {
                    return Ok(());
                }
                continue;
            }
        }

        if let Some(result) = inspect_l7_bloom_filter(context.as_ref(), &mut request, false) {
            if result.should_persist_event() {
                persist_http_inspection_event(context.as_ref(), packet, &request, &result);
            }
            record_l7_block_feedback(context.as_ref(), packet, &request, &result);
            if result_should_drop_http1(&result, &request) {
                let _ = stream.shutdown().await;
                return Ok(());
            }
            http1_handler
                .write_response(&mut stream, 403, "Forbidden", result.reason.as_bytes())
                .await?;
            return Ok(());
        }

        if matches!(request.version, HttpVersion::Http1_0) && !config.gateway_config.enable_http1_0
        {
            http1_handler
                .write_response(
                    &mut stream,
                    505,
                    "HTTP Version Not Supported",
                    b"http/1.0 disabled",
                )
                .await?;
            return Ok(());
        }

        if let Some(location) = redirect_to_https_location(context.as_ref(), &request) {
            http1_handler
                .write_response_with_headers(
                    &mut stream,
                    308,
                    "Permanent Redirect",
                    &[("location".to_string(), location)],
                    b"",
                )
                .await?;
            if !should_keep_client_connection_open(&request) {
                return Ok(());
            }
            continue;
        }

        if let Err(err) = enforce_http1_request_safety(context.as_ref(), &request) {
            http1_handler
                .write_response(&mut stream, 400, "Bad Request", err.to_string().as_bytes())
                .await?;
            return Ok(());
        }

        let early_rule_payload = request.to_lightweight_inspection_string();
        let early_inspection_result =
            inspect_application_layers(context.as_ref(), packet, &request, &early_rule_payload);
        if early_inspection_result.blocked {
            if early_inspection_result.should_persist_event() {
                persist_http_inspection_event(
                    context.as_ref(),
                    packet,
                    &request,
                    &early_inspection_result,
                );
            }
            record_l7_block_feedback(context.as_ref(), packet, &request, &early_inspection_result);
            if result_should_drop_http1(&early_inspection_result, &request) {
                let _ = stream.shutdown().await;
                return Ok(());
            }
            if let Some(response) = early_inspection_result.custom_response.as_ref() {
                let status_code = write_custom_http1_response(
                    context.as_ref(),
                    &http1_handler,
                    &mut stream,
                    &request,
                    response,
                    true,
                    false,
                )
                .await?;
                context.note_ai_route_result(
                    &request,
                    AiRouteResultObservation {
                        status_code,
                        latency_ms: None,
                        upstream_error: false,
                        local_response: true,
                        blocked: true,
                    },
                );
            } else {
                http1_handler
                    .write_response(
                        &mut stream,
                        403,
                        "Forbidden",
                        early_inspection_result.reason.as_bytes(),
                    )
                    .await?;
            }
            if !should_keep_client_connection_open(&request) {
                return Ok(());
            }
            continue;
        }

        if let Some(result) = context
            .l7_behavior_guard()
            .inspect_request(&mut request)
            .await
        {
            request.add_metadata("l7.behavior.prechecked".to_string(), "true".to_string());
            if let Some(metrics) = context.metrics.as_ref() {
                crate::core::engine::network::record_l7_behavior_metrics(metrics, &request);
            }
            if result.should_persist_event() {
                persist_http_inspection_event(context.as_ref(), packet, &request, &result);
            }
            enforce_and_record_l7_block_feedback(context.as_ref(), packet, &request, &result);
            if result_should_drop_http1(&result, &request) {
                let _ = stream.shutdown().await;
                return Ok(());
            }
            if let Some(response) = result.custom_response.as_ref() {
                write_custom_http1_response(
                    context.as_ref(),
                    &http1_handler,
                    &mut stream,
                    &request,
                    response,
                    true,
                    false,
                )
                .await?;
            } else {
                http1_handler
                    .write_response(
                        &mut stream,
                        429,
                        "Too Many Requests",
                        result.reason.as_bytes(),
                    )
                    .await?;
            }
            if !should_keep_client_connection_open(&request) {
                return Ok(());
            }
            continue;
        }
        request.add_metadata("l7.behavior.prechecked".to_string(), "true".to_string());

        let cc_result = context.l7_cc_guard().inspect_request(&mut request).await;
        request.add_metadata("l7.cc.prechecked".to_string(), "true".to_string());
        if let Some(metrics) = context.metrics.as_ref() {
            record_l7_cc_metrics(metrics, &request);
        }
        if let Some(result) = cc_result {
            if result.should_persist_event() {
                persist_http_inspection_event(context.as_ref(), packet, &request, &result);
            }
            enforce_and_record_l7_block_feedback(context.as_ref(), packet, &request, &result);
            if result_should_drop_http1(&result, &request) {
                let _ = stream.shutdown().await;
                return Ok(());
            }
            if let Some(response) = result.custom_response.as_ref() {
                write_custom_http1_response(
                    context.as_ref(),
                    &http1_handler,
                    &mut stream,
                    &request,
                    response,
                    true,
                    false,
                )
                .await?;
            } else {
                http1_handler
                    .write_response(
                        &mut stream,
                        429,
                        "Too Many Requests",
                        result.reason.as_bytes(),
                    )
                    .await?;
            }
            if !should_keep_client_connection_open(&request) {
                return Ok(());
            }
            continue;
        }

        if let Err(err) = http1_handler
            .read_request_body(
                &mut stream,
                &mut request,
                pending_body,
                config.l7_config.max_request_size,
                config.l7_config.read_idle_timeout_ms,
                config.l7_config.slow_attack_defense.body_min_bytes_per_sec,
            )
            .await
        {
            if matches!(err, crate::protocol::ProtocolError::SlowBody { .. }) {
                handle_slow_attack_error(
                    context.as_ref(),
                    &http1_handler,
                    &mut stream,
                    packet,
                    peer_addr,
                    &err,
                    trusted_proxy_peer,
                )
                .await?;
                if let (Some(inspector), Some(bucket_key)) =
                    (context.l4_inspector(), bucket_key.as_ref())
                {
                    inspector.observe_connection_close(bucket_key, &connection_id, opened_at);
                }
                return Ok(());
            }
            return Err(err.into());
        }

        if let Some(result) = inspect_l7_bloom_filter(context.as_ref(), &mut request, true) {
            if result.should_persist_event() {
                persist_http_inspection_event(context.as_ref(), packet, &request, &result);
            }
            record_l7_block_feedback(context.as_ref(), packet, &request, &result);
            if result_should_drop_http1(&result, &request) {
                let _ = stream.shutdown().await;
                return Ok(());
            }
            http1_handler
                .write_response(&mut stream, 403, "Forbidden", result.reason.as_bytes())
                .await?;
            return Ok(());
        }

        if let Some(response) = try_handle_browser_fingerprint_report(
            context.as_ref(),
            packet,
            &request,
            matched_site.as_ref(),
        ) {
            let body = body_for_request(&request, &response.body);
            http1_handler
                .write_response_with_headers(
                    &mut stream,
                    response.status_code,
                    http_status_text(response.status_code),
                    &response.headers,
                    &body,
                )
                .await?;
            if !should_keep_client_connection_open(&request) {
                return Ok(());
            }
            continue;
        }

        if let Some(result) = context.apply_ai_temp_policies_to_request(&mut request) {
            if result.should_persist_event() {
                persist_http_inspection_event(context.as_ref(), packet, &request, &result);
            }
            enforce_and_record_l7_block_feedback(context.as_ref(), packet, &request, &result);
            if result_should_drop_http1(&result, &request) {
                let _ = stream.shutdown().await;
                return Ok(());
            }
            if let Some(response) = result.custom_response.as_ref() {
                write_custom_http1_response(
                    context.as_ref(),
                    &http1_handler,
                    &mut stream,
                    &request,
                    response,
                    false,
                    false,
                )
                .await?;
            }
            if !should_keep_client_connection_open(&request) {
                return Ok(());
            }
            continue;
        }

        if request
            .get_metadata("l7.behavior.prechecked")
            .map(String::as_str)
            != Some("true")
        {
            if let Some(result) = context
                .l7_behavior_guard()
                .inspect_request(&mut request)
                .await
            {
                if let Some(metrics) = context.metrics.as_ref() {
                    crate::core::engine::network::record_l7_behavior_metrics(metrics, &request);
                }
                if result.should_persist_event() {
                    persist_http_inspection_event(context.as_ref(), packet, &request, &result);
                }
                enforce_and_record_l7_block_feedback(context.as_ref(), packet, &request, &result);
                if result_should_drop_http1(&result, &request) {
                    let _ = stream.shutdown().await;
                    return Ok(());
                }
                if let Some(response) = result.custom_response.as_ref() {
                    write_custom_http1_response(
                        context.as_ref(),
                        &http1_handler,
                        &mut stream,
                        &request,
                        response,
                        false,
                        false,
                    )
                    .await?;
                } else {
                    http1_handler
                        .write_response(
                            &mut stream,
                            429,
                            "Too Many Requests",
                            result.reason.as_bytes(),
                        )
                        .await?;
                }
                if !should_keep_client_connection_open(&request) {
                    return Ok(());
                }
                continue;
            }
            if let Some(metrics) = context.metrics.as_ref() {
                crate::core::engine::network::record_l7_behavior_metrics(metrics, &request);
            }
        }

        if request.get_metadata("l7.cc.prechecked").map(String::as_str) != Some("true") {
            let cc_result = context.l7_cc_guard().inspect_request(&mut request).await;
            if let Some(metrics) = context.metrics.as_ref() {
                record_l7_cc_metrics(metrics, &request);
            }
            if let Some(result) = cc_result {
                if result.should_persist_event() {
                    persist_http_inspection_event(context.as_ref(), packet, &request, &result);
                }
                enforce_and_record_l7_block_feedback(context.as_ref(), packet, &request, &result);
                if result_should_drop_http1(&result, &request) {
                    let _ = stream.shutdown().await;
                    return Ok(());
                }
                if let Some(response) = result.custom_response.as_ref() {
                    write_custom_http1_response(
                        context.as_ref(),
                        &http1_handler,
                        &mut stream,
                        &request,
                        response,
                        true,
                        false,
                    )
                    .await?;
                } else {
                    context.note_ai_route_result(
                        &request,
                        AiRouteResultObservation {
                            status_code: 429,
                            latency_ms: None,
                            upstream_error: false,
                            local_response: true,
                            blocked: true,
                        },
                    );
                    http1_handler
                        .write_response(
                            &mut stream,
                            429,
                            "Too Many Requests",
                            result.reason.as_bytes(),
                        )
                        .await?;
                }
                if !should_keep_client_connection_open(&request) {
                    return Ok(());
                }
                continue;
            }
        }

        prepare_request_for_proxy(context.as_ref(), &mut request);
        persist_http_identity_debug_event(context.as_ref(), packet, &request);

        debug!("HTTP/1.1 request: {} {}", request.method, request.uri);

        let request_dump = request.to_inspection_string();
        let critical_overload = request_in_critical_overload(&request);
        let rule_inspection_mode = if critical_overload {
            "lightweight"
        } else {
            "full"
        };
        request.add_metadata(
            "l7.rule_inspection_mode".to_string(),
            rule_inspection_mode.to_string(),
        );
        let rule_payload = if critical_overload {
            request.to_lightweight_inspection_string()
        } else {
            request_dump.clone()
        };
        let traffic_source_ip = request
            .client_ip
            .clone()
            .unwrap_or_else(|| packet.source_ip.to_string());
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_packet(request_dump.len());
        }

        let inspection_result =
            inspect_application_layers(context.as_ref(), packet, &request, &rule_payload);

        if inspection_result.should_persist_event() {
            persist_http_inspection_event(context.as_ref(), packet, &request, &inspection_result);
        }
        if inspection_result.blocked && inspection_result.layer == crate::core::InspectionLayer::L7
        {
            if let Some(inspector) = context.l4_inspector() {
                inspector.record_l7_feedback(
                    packet,
                    &request,
                    crate::l4::behavior::FeedbackSource::L7Block,
                );
            }
        }

        if inspection_result.blocked {
            context
                .traffic_map
                .record_ingress(traffic_source_ip.clone(), request_dump.len(), true);
            if let Some(metrics) = context.metrics.as_ref() {
                metrics.record_block(inspection_result.layer.clone());
            }
            if result_should_drop_http1(&inspection_result, &request) {
                context.note_ai_route_result(
                    &request,
                    AiRouteResultObservation {
                        status_code: 499,
                        latency_ms: None,
                        upstream_error: false,
                        local_response: true,
                        blocked: true,
                    },
                );
                let _ = stream.shutdown().await;
                return Ok(());
            }
            if let Some(response) = inspection_result.custom_response.as_ref() {
                write_custom_http1_response(
                    context.as_ref(),
                    &http1_handler,
                    &mut stream,
                    &request,
                    response,
                    true,
                    false,
                )
                .await?;
            } else {
                context.note_ai_route_result(
                    &request,
                    AiRouteResultObservation {
                        status_code: 403,
                        latency_ms: None,
                        upstream_error: false,
                        local_response: true,
                        blocked: true,
                    },
                );
                http1_handler
                    .write_response(
                        &mut stream,
                        403,
                        "Forbidden",
                        inspection_result.reason.as_bytes(),
                    )
                    .await?;
            }
        } else if matches!(
            handle_http1_proxy_or_local_response(
                context.as_ref(),
                &http1_handler,
                &mut stream,
                packet,
                peer_addr,
                &config,
                matched_site.as_ref(),
                &request,
                &traffic_source_ip,
                request_dump.len(),
                &mut reusable_upstream_connection,
            )
            .await?,
            Http1RequestFlow::Close
        ) {
            return Ok(());
        }

        if !should_keep_client_connection_open(&request) {
            if let (Some(inspector), Some(bucket_key)) =
                (context.l4_inspector(), bucket_key.as_ref())
            {
                inspector.observe_connection_close(bucket_key, &connection_id, opened_at);
            }
            return Ok(());
        }
    }
}
