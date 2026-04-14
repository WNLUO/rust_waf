use super::*;

pub(crate) async fn handle_http1_connection(
    context: Arc<WafContext>,
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
    extra_metadata: Vec<(String, String)>,
) -> Result<()> {
    let config = context.config_snapshot();
    let http1_handler = Http1Handler::new();
    let mut reusable_upstream_connection = None;
    let connection_id = extra_metadata
        .iter()
        .find(|(key, _)| key == "network.connection_id")
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let opened_at = std::time::Instant::now();
    let mut bucket_key = None;

    loop {
        let mut request = http1_handler
            .read_request(
                &mut stream,
                config.l7_config.max_request_size,
                config.l7_config.first_byte_timeout_ms,
                config.l7_config.read_idle_timeout_ms,
            )
            .await?;

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
                ));
            }
        }
        if let (Some(inspector), Some(bucket_key)) = (context.l4_inspector(), bucket_key.as_ref()) {
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
        prepare_request_for_routing(context.as_ref(), &mut request);
        let matched_site = resolve_gateway_site(context.as_ref(), &request);
        if let Some(site) = matched_site.as_ref() {
            apply_gateway_site_metadata(&mut request, site);
        }
        if let Some(inspector) = context.l4_inspector() {
            let policy = inspector.apply_request_policy(packet, &mut request);
            maybe_delay_request(&request).await;
            if policy.reject_new_connections {
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

        let cc_result = context.l7_cc_guard().inspect_request(&mut request).await;
        if let Some(metrics) = context.metrics.as_ref() {
            record_l7_cc_metrics(metrics, &request);
        }
        if let Some(result) = cc_result {
            if result.should_persist_event() {
                persist_http_inspection_event(context.as_ref(), packet, &request, &result);
            }
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

        debug!("HTTP/1.1 request: {} {}", request.method, request.uri);

        let request_dump = request.to_inspection_string();
        let traffic_source_ip = request
            .client_ip
            .clone()
            .unwrap_or_else(|| packet.source_ip.to_string());
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_packet(request_dump.len());
        }

        let inspection_result = if request_in_critical_overload(&request) {
            InspectionResult::allow(InspectionLayer::L7)
        } else {
            inspect_application_layers(context.as_ref(), packet, &request, &request_dump)
        };

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
                    metrics.record_proxy_attempt();
                }
                let proxy_started_at = Instant::now();
                let proxy_result = if config.gateway_config.enable_ntlm {
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
                            metrics.record_proxy_success(proxy_started_at.elapsed());
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
                            metrics.record_proxy_failure();
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
