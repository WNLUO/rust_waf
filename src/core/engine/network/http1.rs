use super::*;
use crate::core::engine::network::helpers::should_hard_reject_l4_request_budget;
use crate::core::engine::policy::persist_http_identity_debug_event;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

pub(crate) async fn handle_http1_connection(
    context: Arc<WafContext>,
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
    extra_metadata: Vec<(String, String)>,
    connection_semaphore: Arc<Semaphore>,
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
        let mut request = match http1_handler
            .read_request(
                &mut stream,
                config.l7_config.max_request_size,
                first_byte_timeout_ms,
                config.l7_config.read_idle_timeout_ms,
                config
                    .l7_config
                    .slow_attack_defense
                    .header_min_bytes_per_sec,
                config.l7_config.slow_attack_defense.body_min_bytes_per_sec,
            )
            .await
        {
            Ok(request) => request,
            Err(err)
                if matches!(
                    err,
                    crate::protocol::ProtocolError::IdleTimeout { .. }
                        | crate::protocol::ProtocolError::SlowHeader { .. }
                        | crate::protocol::ProtocolError::SlowBody { .. }
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
                maybe_delay_policy(&policy).await;
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
            Arc::clone(&connection_semaphore),
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
        let matched_site = resolve_gateway_site(context.as_ref(), &request);
        if let Some(site) = matched_site.as_ref() {
            apply_gateway_site_metadata(&mut request, site);
        }
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
                if should_hard_reject_l4_request_budget(&request) {
                    if let Some(metrics) = context.metrics.as_ref() {
                        metrics.record_l4_bucket_budget_rejection();
                    }
                    http1_handler
                        .write_response(
                            &mut stream,
                            429,
                            "Too Many Requests",
                            b"bucket request budget exceeded",
                        )
                        .await?;
                    if let Some(bucket_key) = bucket_key.as_ref() {
                        inspector.observe_connection_close(bucket_key, &connection_id, opened_at);
                    }
                    return Ok(());
                }
                request.add_metadata("l4.force_close".to_string(), "true".to_string());
                request.add_metadata("proxy_connection_mode".to_string(), "close".to_string());
                request.add_metadata(
                    "l4.request_budget_softened".to_string(),
                    "true".to_string(),
                );
            }
        }

        if let Some(result) = inspect_blocked_client_ip(context.as_ref(), &request).await {
            persist_http_inspection_event(context.as_ref(), packet, &request, &result);
            if let Some(metrics) = context.metrics.as_ref() {
                metrics.record_block(result.layer.clone());
            }
            if let Some(inspector) = context.l4_inspector() {
                inspector.record_l7_feedback(
                    packet,
                    &request,
                    crate::l4::behavior::FeedbackSource::L7Block,
                );
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
            crate::core::engine::policy::enforce_runtime_http_block_if_needed(
                context.as_ref(),
                packet,
                &request,
                &result,
            );
            if let Some(metrics) = context.metrics.as_ref() {
                metrics.record_block(result.layer.clone());
            }
            if let Some(inspector) = context.l4_inspector() {
                inspector.record_l7_feedback(
                    packet,
                    &request,
                    crate::l4::behavior::FeedbackSource::L7Block,
                );
            }
            if let Some(response) = result.custom_response.as_ref() {
                let response = resolve_runtime_custom_response(response);
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

        let cc_result = context.l7_cc_guard().inspect_request(&mut request).await;
        if let Some(metrics) = context.metrics.as_ref() {
            record_l7_cc_metrics(metrics, &request);
        }
        if let Some(result) = cc_result {
            if result.should_persist_event() {
                persist_http_inspection_event(context.as_ref(), packet, &request, &result);
            }
            crate::core::engine::policy::enforce_runtime_http_block_if_needed(
                context.as_ref(),
                packet,
                &request,
                &result,
            );
            if let Some(metrics) = context.metrics.as_ref() {
                metrics.record_block(result.layer.clone());
            }
            if let Some(inspector) = context.l4_inspector() {
                inspector.record_l7_feedback(
                    packet,
                    &request,
                    crate::l4::behavior::FeedbackSource::L7Block,
                );
            }
            if let Some(response) = result.custom_response.as_ref() {
                let response = resolve_runtime_custom_response(response);
                let body = body_for_request(&request, &response.body);
                if let Some(tarpit) = response.tarpit.as_ref() {
                    http1_handler
                        .write_response_with_headers_tarpit(
                            &mut stream,
                            response.status_code,
                            http_status_text(response.status_code),
                            &response.headers,
                            &body,
                            tarpit,
                        )
                        .await?;
                } else {
                    http1_handler
                        .write_response_with_headers(
                            &mut stream,
                            response.status_code,
                            http_status_text(response.status_code),
                            &response.headers,
                            &body,
                        )
                        .await?;
                }
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
            if let Some(response) = inspection_result.custom_response.as_ref() {
                let response = resolve_runtime_custom_response(response);
                let body = body_for_request(&request, &response.body);
                if let Some(tarpit) = response.tarpit.as_ref() {
                    http1_handler
                        .write_response_with_headers_tarpit(
                            &mut stream,
                            response.status_code,
                            http_status_text(response.status_code),
                            &response.headers,
                            &body,
                            tarpit,
                        )
                        .await?;
                } else {
                    http1_handler
                        .write_response_with_headers(
                            &mut stream,
                            response.status_code,
                            http_status_text(response.status_code),
                            &response.headers,
                            &body,
                        )
                        .await?;
                }
            } else {
                http1_handler
                    .write_response(
                        &mut stream,
                        403,
                        "Forbidden",
                        inspection_result.reason.as_bytes(),
                    )
                    .await?;
            }
        } else {
            let upstream_addr = select_upstream_target(matched_site.as_ref());
            if let Some(upstream_addr) = upstream_addr.as_deref() {
                if let Err(reason) = enforce_upstream_policy(context.as_ref()) {
                    context.traffic_map.record_ingress(
                        traffic_source_ip.clone(),
                        request_dump.len(),
                        false,
                    );
                    if let Some(metrics) = context.metrics.as_ref() {
                        metrics.record_fail_close_rejection();
                    }
                    http1_handler
                        .write_response(
                            &mut stream,
                            503,
                            "Service Unavailable",
                            reason.to_string().as_bytes(),
                        )
                        .await?;
                    return Ok(());
                }
                if let Some(metrics) = context.metrics.as_ref() {
                    let labels = proxy_metric_labels(&request);
                    metrics.record_proxy_attempt_with_labels(proxy_traffic_kind(&request), &labels);
                }
                let proxy_started_at = Instant::now();
                let proxy_result = if config.gateway_config.enable_ntlm
                    && config.l7_config.upstream_http1_allow_connection_reuse
                    && !config.l7_config.upstream_http1_strict_mode
                {
                    proxy_http_request_with_session_affinity(
                        context.as_ref(),
                        &request,
                        upstream_addr,
                        config.l7_config.proxy_connect_timeout_ms,
                        config.l7_config.proxy_write_timeout_ms,
                        config.l7_config.proxy_read_timeout_ms,
                        &mut reusable_upstream_connection,
                    )
                    .await
                } else {
                    proxy_http_request(
                        context.as_ref(),
                        &request,
                        upstream_addr,
                        config.l7_config.proxy_connect_timeout_ms,
                        config.l7_config.proxy_write_timeout_ms,
                        config.l7_config.proxy_read_timeout_ms,
                    )
                    .await
                };
                match proxy_result {
                    Ok(response) => {
                        if let Some(metrics) = context.metrics.as_ref() {
                            let labels = proxy_metric_labels(&request);
                            metrics.record_proxy_success_with_labels(
                                proxy_traffic_kind(&request),
                                proxy_started_at.elapsed(),
                                &labels,
                            );
                        }
                        context.traffic_map.record_egress(
                            traffic_source_ip.clone(),
                            response.body.len(),
                            proxy_started_at.elapsed(),
                        );
                        match apply_safeline_upstream_action(
                            context.as_ref(),
                            packet,
                            &request,
                            matched_site.as_ref(),
                            resolve_safeline_intercept_config(&config, matched_site.as_ref()),
                            response,
                        ) {
                            UpstreamResponseDisposition::Forward(response) => {
                                context.traffic_map.record_ingress(
                                    traffic_source_ip.clone(),
                                    request_dump.len(),
                                    false,
                                );
                                write_http1_upstream_response(
                                    context.as_ref(),
                                    &mut stream,
                                    &response,
                                )
                                .await?;
                            }
                            UpstreamResponseDisposition::Custom(response) => {
                                context.traffic_map.record_ingress(
                                    traffic_source_ip.clone(),
                                    request_dump.len(),
                                    true,
                                );
                                let response = resolve_runtime_custom_response(&response);
                                let body = body_for_request(&request, &response.body);
                                let mut headers = response.headers.clone();
                                apply_response_policies(
                                    context.as_ref(),
                                    &mut headers,
                                    response.status_code,
                                );
                                if let Some(tarpit) = response.tarpit.as_ref() {
                                    http1_handler
                                        .write_response_with_headers_tarpit(
                                            &mut stream,
                                            response.status_code,
                                            http_status_text(response.status_code),
                                            &headers,
                                            &body,
                                            tarpit,
                                        )
                                        .await?;
                                } else {
                                    http1_handler
                                        .write_response_with_headers(
                                            &mut stream,
                                            response.status_code,
                                            http_status_text(response.status_code),
                                            &headers,
                                            &body,
                                        )
                                        .await?;
                                }
                            }
                            UpstreamResponseDisposition::Drop => {
                                context.traffic_map.record_ingress(
                                    traffic_source_ip.clone(),
                                    request_dump.len(),
                                    true,
                                );
                                let _ = stream.shutdown().await;
                                return Ok(());
                            }
                        }
                    }
                    Err(err) => {
                        context.traffic_map.record_ingress(
                            traffic_source_ip.clone(),
                            request_dump.len(),
                            false,
                        );
                        if let Some(metrics) = context.metrics.as_ref() {
                            let labels = proxy_metric_labels(&request);
                            metrics.record_proxy_failure_with_labels(
                                proxy_traffic_kind(&request),
                                &labels,
                            );
                        }
                        context.set_upstream_health(false, Some(err.to_string()));
                        warn!(
                            "Failed to proxy HTTP/1.1 request from {} to {}: {}",
                            peer_addr, upstream_addr, err
                        );
                        http1_handler
                            .write_response(
                                &mut stream,
                                502,
                                "Bad Gateway",
                                b"upstream proxy failed",
                            )
                            .await?;
                    }
                }
            } else if matched_site.is_some() {
                context.traffic_map.record_ingress(
                    traffic_source_ip.clone(),
                    request_dump.len(),
                    false,
                );
                http1_handler
                    .write_response(
                        &mut stream,
                        502,
                        "Bad Gateway",
                        b"site upstream not configured",
                    )
                    .await?;
            } else if should_reject_unmatched_site(context.as_ref(), &request) {
                context.traffic_map.record_ingress(
                    traffic_source_ip.clone(),
                    request_dump.len(),
                    false,
                );
                if config.console_settings.drop_unmatched_requests {
                    let _ = stream.shutdown().await;
                    return Ok(());
                }
                http1_handler
                    .write_response(&mut stream, 404, "Not Found", b"site not found")
                    .await?;
            } else {
                context.traffic_map.record_ingress(
                    traffic_source_ip.clone(),
                    request_dump.len(),
                    false,
                );
                let metrics = context.metrics_snapshot();
                let metrics_line = metrics
                    .map(|snapshot| {
                        format!(
                            "packets={},blocked={},blocked_l4={},blocked_l7={},bytes={}",
                            snapshot.total_packets,
                            snapshot.blocked_packets,
                            snapshot.blocked_l4,
                            snapshot.blocked_l7,
                            snapshot.total_bytes
                        )
                    })
                    .unwrap_or_else(|| "metrics=disabled".to_string());

                let body = format!("allowed\n{}\n", metrics_line);
                http1_handler
                    .write_response(&mut stream, 200, "OK", body.as_bytes())
                    .await?;
            }
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

async fn handle_slow_attack_error(
    context: &WafContext,
    http1_handler: &Http1Handler,
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    packet: &PacketInfo,
    peer_addr: std::net::SocketAddr,
    err: &crate::protocol::ProtocolError,
    trusted_proxy_peer: bool,
) -> Result<()> {
    let (kind, detail) = match err {
        crate::protocol::ProtocolError::IdleTimeout { elapsed_ms } => (
            crate::l7::SlowAttackKind::IdleConnection,
            format!("elapsed_ms={elapsed_ms}"),
        ),
        crate::protocol::ProtocolError::SlowHeader {
            bytes_read,
            elapsed_ms,
        } => (
            crate::l7::SlowAttackKind::SlowHeaders,
            format!("bytes_read={bytes_read} elapsed_ms={elapsed_ms}"),
        ),
        crate::protocol::ProtocolError::SlowBody {
            bytes_read,
            expected_bytes,
            elapsed_ms,
        } => (
            crate::l7::SlowAttackKind::SlowBody,
            format!(
                "bytes_read={bytes_read} expected_bytes={expected_bytes} elapsed_ms={elapsed_ms}"
            ),
        ),
        _ => return Ok(()),
    };

    let assessment = context
        .slow_attack_guard()
        .assess(crate::l7::SlowAttackObservation {
            kind,
            peer_ip: packet.source_ip,
            client_ip: None,
            trusted_proxy_peer,
            identity_state: if trusted_proxy_peer {
                "trusted_cdn_unresolved"
            } else {
                "direct_client"
            },
            client_identity_unresolved: trusted_proxy_peer,
            host: None,
            detail,
        });
    if let Some(metrics) = context.metrics.as_ref() {
        match kind {
            crate::l7::SlowAttackKind::IdleConnection => metrics.record_slow_attack_idle_timeout(),
            crate::l7::SlowAttackKind::SlowHeaders => metrics.record_slow_attack_header_timeout(),
            crate::l7::SlowAttackKind::SlowBody => metrics.record_slow_attack_body_timeout(),
            crate::l7::SlowAttackKind::SlowTlsHandshake => {
                metrics.record_slow_attack_tls_handshake()
            }
        }
        if assessment.should_block_ip {
            metrics.record_slow_attack_block();
        }
        metrics.record_block(crate::core::InspectionLayer::L7);
    }

    persist_http1_slow_attack_event(context, packet, peer_addr, kind, &assessment);
    if let Some(inspector) = context.l4_inspector() {
        let mut slow_request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http1_1,
            "SLOW".to_string(),
            format!("/slow-attack/{}", kind.as_str()),
        );
        slow_request.set_client_ip(packet.source_ip.to_string());
        inspector.record_l7_feedback(
            packet,
            &slow_request,
            crate::l4::behavior::FeedbackSource::SlowAttack,
        );
    }

    if assessment.should_block_ip {
        if let Some(ip) = assessment.block_ip {
            if let Some(inspector) = context.l4_inspector() {
                inspector.block_ip(
                    &ip,
                    &assessment.reason,
                    std::time::Duration::from_secs(assessment.block_duration_secs),
                );
            }
            if let Some(store) = context.sqlite_store.as_ref() {
                let blocked_at = current_unix_timestamp();
                store.enqueue_blocked_ip(crate::storage::BlockedIpRecord::new(
                    ip.to_string(),
                    assessment.reason.clone(),
                    blocked_at,
                    blocked_at + assessment.block_duration_secs as i64,
                ));
            }
        }
    }

    let response = context
        .slow_attack_guard()
        .build_response(&assessment, kind);
    http1_handler
        .write_response_with_headers(
            stream,
            response.status_code,
            http_status_text(response.status_code),
            &response.headers,
            &response.body,
        )
        .await?;
    let _ = stream.shutdown().await;
    warn!(
        "Slow attack defense terminated HTTP/1.1 connection from {}: {}",
        peer_addr, assessment.reason
    );
    Ok(())
}

fn persist_http1_slow_attack_event(
    context: &WafContext,
    packet: &PacketInfo,
    peer_addr: std::net::SocketAddr,
    kind: crate::l7::SlowAttackKind,
    assessment: &crate::l7::slow_attack_guard::SlowAttackAssessment,
) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    let mut event = crate::storage::SecurityEventRecord::now(
        "L7",
        if assessment.should_block_ip {
            "block"
        } else {
            "respond"
        },
        assessment.reason.clone(),
        assessment.block_ip.unwrap_or(packet.source_ip).to_string(),
        packet.dest_ip.to_string(),
        packet.source_port,
        packet.dest_port,
        format!("{:?}", packet.protocol),
    );
    event.http_version = Some("HTTP/1.1".to_string());
    event.details_json = serde_json::to_string_pretty(&serde_json::json!({
        "slow_attack": {
            "kind": kind.as_str(),
            "event_count": assessment.event_count,
            "block_ip": assessment.block_ip.map(|ip| ip.to_string()),
            "peer_ip": peer_addr.ip().to_string(),
        }
    }))
    .ok();
    store.enqueue_security_event(event);
}

fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn request_level_permit_exhaustion_returns_503() {
        let context = Arc::new(
            WafContext::new(crate::config::Config::default())
                .await
                .unwrap(),
        );
        let peer_addr: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
        let local_addr: std::net::SocketAddr = "127.0.0.1:660".parse().unwrap();
        let connection_semaphore = Arc::new(Semaphore::new(0));
        let (mut client, server) = duplex(4096);

        let task = tokio::spawn({
            let context = Arc::clone(&context);
            async move {
                let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::TCP);
                handle_http1_connection(
                    context,
                    server,
                    peer_addr,
                    &packet,
                    Vec::new(),
                    connection_semaphore,
                )
                .await
            }
        });

        client
            .write_all(b"GET / HTTP/1.1\r\nHost: wnluo.com\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        client.shutdown().await.unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        task.await.unwrap().unwrap();

        let response = String::from_utf8_lossy(&response);
        assert!(response.contains("HTTP/1.1 503 Service Unavailable"));
        assert!(response.contains("gateway overloaded, retry later"));
        assert!(response.contains("Retry-After: 5"));
    }
}
