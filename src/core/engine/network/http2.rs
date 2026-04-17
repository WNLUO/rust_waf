use super::*;
use crate::core::engine::policy::persist_http_identity_debug_event;

pub(crate) async fn handle_http2_connection(
    context: Arc<WafContext>,
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
    extra_metadata: Vec<(String, String)>,
    _connection_permit: OwnedSemaphorePermit,
    request_semaphore: Arc<Semaphore>,
) -> Result<()> {
    let config = context.config_snapshot();
    let http2_config = &config.l7_config.http2_config;
    let http2_handler = Http2Handler::new()
        .with_max_concurrent_streams(
            context.effective_http2_max_concurrent_streams(http2_config.max_concurrent_streams),
        )
        .with_max_frame_size(http2_config.max_frame_size)
        .with_priorities(http2_config.enable_priorities)
        .with_initial_window_size(http2_config.initial_window_size);

    let packet = packet.clone();
    let context_for_service = Arc::clone(&context);
    let context_for_error = Arc::clone(&context);
    let packet_for_error = packet.clone();
    let peer_ip = peer_addr.ip().to_string();
    let max_request_size = config.l7_config.max_request_size;
    let request_metadata = extra_metadata.clone();
    let connection_id = extra_metadata
        .iter()
        .find(|(key, _)| key == "network.connection_id")
        .map(|(_, value)| value.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let connection_id_for_callback = connection_id.clone();
    let registered = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let bucket_key = Arc::new(std::sync::Mutex::new(None));
    let bucket_key_for_callback = Arc::clone(&bucket_key);
    let opened_at = std::time::Instant::now();
    let skip_l4_connection_budget =
        should_skip_l4_connection_budget_for_trusted_proxy(context.as_ref(), packet.source_ip);

    http2_handler
        .serve_connection(
            stream,
            peer_ip,
            packet.dest_port,
            move |request, body| {
                let context = Arc::clone(&context_for_service);
                let packet = packet.clone();
                let request_metadata = request_metadata.clone();
                let connection_id = connection_id_for_callback.clone();
                let registered = Arc::clone(&registered);
                let bucket_key = Arc::clone(&bucket_key_for_callback);
                let request_semaphore = Arc::clone(&request_semaphore);

                async move {
                    let config = context.config_snapshot();
                    let mut request = request;
                    let mut body = Some(body);
                    apply_client_identity(context.as_ref(), peer_addr, &mut request);
                    for (key, value) in request_metadata {
                        request.add_metadata(key, value);
                    }
                    let mut first_registration = false;
                    if !registered.swap(true, std::sync::atomic::Ordering::Relaxed) {
                        first_registration = true;
                        if let Some(inspector) = context.l4_inspector() {
                            let key = inspector.observe_connection_open(
                                connection_id.clone(),
                                &packet,
                                request.get_header("host").map(String::as_str),
                                request.get_metadata("tls.alpn").map(String::as_str),
                                request
                                    .get_metadata("transport")
                                    .map(String::as_str)
                                    .unwrap_or("http"),
                                "h2",
                                skip_l4_connection_budget,
                            );
                            bucket_key
                                .lock()
                                .expect("bucket key mutex poisoned")
                                .replace(key);
                        }
                    }
                    if first_registration && !skip_l4_connection_budget {
                        if let Some(inspector) = context.l4_inspector() {
                            let current_bucket_key = {
                                bucket_key
                                    .lock()
                                    .expect("bucket key mutex poisoned")
                                    .clone()
                            };
                            if let Some(bucket_key) = current_bucket_key {
                                let policy = inspector.connection_admission_policy(&bucket_key);
                                maybe_delay_policy(context.as_ref(), &policy).await;
                                if policy.reject_new_connections {
                                    if let Some(metrics) = context.metrics.as_ref() {
                                        metrics.record_l4_bucket_budget_rejection();
                                    }
                                    return Ok(Http2Response {
                                        status_code: 429,
                                        headers: vec![],
                                        body: b"bucket connection budget exceeded".to_vec(),
                                    });
                                }
                            }
                        }
                    }
                    let Some(_request_permit) = crate::core::engine::runtime::acquire_permit_auto(
                        context.as_ref(),
                        Arc::clone(&request_semaphore),
                        peer_addr,
                        "HTTP/2 request",
                    )
                    .await
                    else {
                        return Ok(Http2Response {
                            status_code: 503,
                            headers: vec![("retry-after".to_string(), "5".to_string())],
                            body: b"gateway overloaded, retry later".to_vec(),
                        });
                    };
                    prepare_request_for_routing(context.as_ref(), &mut request);
                    context.annotate_runtime_pressure(&mut request);
                    let matched_site = resolve_gateway_site(context.as_ref(), &request);
                    if let Some(site) = matched_site.as_ref() {
                        apply_gateway_site_metadata(&mut request, site);
                    }
                    context.annotate_site_runtime_budget(&mut request);
                    if let Some(inspector) = context.l4_inspector() {
                        let policy = inspector.apply_request_policy(&packet, &mut request);
                        if skip_l4_connection_budget
                            && (policy.suggested_delay_ms > 0 || policy.disable_keepalive)
                        {
                            if let Some(metrics) = context.metrics.as_ref() {
                                metrics.record_trusted_proxy_l4_degrade_action();
                            }
                            debug!(
                                "Trusted proxy request downgraded by L4 policy on HTTP/2: peer_ip={} client_ip={} unresolved_client_ip={} delay_ms={} force_close={}",
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
                            request.add_metadata(
                                "proxy_connection_mode".to_string(),
                                "close".to_string(),
                            );
                            request.add_metadata(
                                "l4.request_budget_softened".to_string(),
                                "true".to_string(),
                            );
                        }
                    }

                    if let Some(result) = inspect_blocked_client_ip(context.as_ref(), &request).await
                    {
                        persist_http_inspection_event(
                            context.as_ref(),
                            &packet,
                            &request,
                            &result,
                        );
                        if let Some(metrics) = context.metrics.as_ref() {
                            metrics.record_block(result.layer.clone());
                        }
                        if let Some(inspector) = context.l4_inspector() {
                            inspector.record_l7_feedback(
                                &packet,
                                &request,
                                crate::l4::behavior::FeedbackSource::L7Block,
                            );
                        }
                        if result_should_drop_http2(&result, &request) {
                            return Err(drop_http2_result(&result.reason));
                        }
                        return Ok(Http2Response {
                            status_code: 403,
                            headers: vec![],
                            body: body_for_request(&request, result.reason.as_bytes()),
                        });
                    }

                    let early_rule_payload = request.to_lightweight_inspection_string();
                    let early_inspection_result = inspect_application_layers(
                        context.as_ref(),
                        &packet,
                        &request,
                        &early_rule_payload,
                    );
                    if early_inspection_result.blocked {
                        if early_inspection_result.should_persist_event() {
                            persist_http_inspection_event(
                                context.as_ref(),
                                &packet,
                                &request,
                                &early_inspection_result,
                            );
                        }
                        if let Some(metrics) = context.metrics.as_ref() {
                            metrics.record_block(early_inspection_result.layer.clone());
                        }
                        if let Some(inspector) = context.l4_inspector() {
                            inspector.record_l7_feedback(
                                &packet,
                                &request,
                                crate::l4::behavior::FeedbackSource::L7Block,
                            );
                        }
                        if result_should_drop_http2(&early_inspection_result, &request) {
                            return Err(drop_http2_result(&early_inspection_result.reason));
                        }
                        if let Some(response) = early_inspection_result.custom_response.as_ref() {
                            let response = resolve_runtime_custom_response(response);
                            let body = body_for_request(&request, &response.body);
                            let mut headers = response.headers.clone();
                            apply_response_policies(
                                context.as_ref(),
                                &mut headers,
                                response.status_code,
                            );
                            return Ok(Http2Response {
                                status_code: response.status_code,
                                headers,
                                body,
                            });
                        }
                        return Ok(Http2Response {
                            status_code: 403,
                            headers: vec![],
                            body: body_for_request(
                                &request,
                                format!("blocked: {}", early_inspection_result.reason).as_bytes(),
                            ),
                        });
                    }

                    if let Some(result) =
                        context.l7_behavior_guard().inspect_request(&mut request).await
                    {
                        request.add_metadata("l7.behavior.prechecked".to_string(), "true".to_string());
                        if let Some(metrics) = context.metrics.as_ref() {
                            crate::core::engine::network::record_l7_behavior_metrics(
                                metrics, &request,
                            );
                        }
                        if result.should_persist_event() {
                            persist_http_inspection_event(
                                context.as_ref(),
                                &packet,
                                &request,
                                &result,
                            );
                        }
                        crate::core::engine::policy::enforce_runtime_http_block_if_needed(
                            context.as_ref(),
                            &packet,
                            &request,
                            &result,
                        );
                        if let Some(metrics) = context.metrics.as_ref() {
                            metrics.record_block(result.layer.clone());
                        }
                        if let Some(inspector) = context.l4_inspector() {
                            inspector.record_l7_feedback(
                                &packet,
                                &request,
                                crate::l4::behavior::FeedbackSource::L7Block,
                            );
                        }
                        if result_should_drop_http2(&result, &request) {
                            return Err(drop_http2_result(&result.reason));
                        }
                        if let Some(response) = result.custom_response.as_ref() {
                            let response = resolve_runtime_custom_response(response);
                            let body = body_for_request(&request, &response.body);
                            let mut headers = response.headers.clone();
                            apply_response_policies(
                                context.as_ref(),
                                &mut headers,
                                response.status_code,
                            );
                            return Ok(Http2Response {
                                status_code: response.status_code,
                                headers,
                                body,
                            });
                        }
                        return Ok(Http2Response {
                            status_code: 429,
                            headers: vec![],
                            body: body_for_request(&request, result.reason.as_bytes()),
                        });
                    }
                    request.add_metadata("l7.behavior.prechecked".to_string(), "true".to_string());

                    let cc_result = context.l7_cc_guard().inspect_request(&mut request).await;
                    request.add_metadata("l7.cc.prechecked".to_string(), "true".to_string());
                    if let Some(metrics) = context.metrics.as_ref() {
                        record_l7_cc_metrics(metrics, &request);
                    }
                    if let Some(result) = cc_result {
                        if result.should_persist_event() {
                            persist_http_inspection_event(
                                context.as_ref(),
                                &packet,
                                &request,
                                &result,
                            );
                        }
                        crate::core::engine::policy::enforce_runtime_http_block_if_needed(
                            context.as_ref(),
                            &packet,
                            &request,
                            &result,
                        );
                        if let Some(metrics) = context.metrics.as_ref() {
                            metrics.record_block(result.layer.clone());
                        }
                        if let Some(inspector) = context.l4_inspector() {
                            inspector.record_l7_feedback(
                                &packet,
                                &request,
                                crate::l4::behavior::FeedbackSource::L7Block,
                            );
                        }
                        if result_should_drop_http2(&result, &request) {
                            return Err(drop_http2_result(&result.reason));
                        }
                        if let Some(response) = result.custom_response.as_ref() {
                            let response = resolve_runtime_custom_response(response);
                            let body = body_for_request(&request, &response.body);
                            let mut headers = response.headers.clone();
                            apply_response_policies(
                                context.as_ref(),
                                &mut headers,
                                response.status_code,
                            );
                            return Ok(Http2Response {
                                status_code: response.status_code,
                                headers,
                                body,
                            });
                        }
                        return Ok(Http2Response {
                            status_code: 429,
                            headers: vec![],
                            body: body_for_request(&request, result.reason.as_bytes()),
                        });
                    }

                    let request_body = match Http2Handler::read_request_body(
                        body.take().expect("http2 request body missing"),
                        max_request_size,
                        config.l7_config.read_idle_timeout_ms,
                        config.l7_config.slow_attack_defense.body_min_bytes_per_sec,
                    )
                    .await
                    {
                        Ok(body) => body,
                        Err(err)
                            if matches!(
                                err,
                                crate::protocol::ProtocolError::SlowBody { .. }
                                    | crate::protocol::ProtocolError::IdleTimeout { .. }
                            ) =>
                        {
                            return handle_http2_slow_attack_error(
                                context.as_ref(),
                                &packet,
                                err,
                            )
                            .await;
                        }
                        Err(err) => return Err(err),
                    };
                    request.body = request_body.to_vec();

                    if let Some(response) = try_handle_browser_fingerprint_report(
                        context.as_ref(),
                        &packet,
                        &request,
                        matched_site.as_ref(),
                    ) {
                        let body = body_for_request(&request, &response.body);
                        let mut headers = response.headers.clone();
                        apply_response_policies(
                            context.as_ref(),
                            &mut headers,
                            response.status_code,
                        );
                        return Ok(Http2Response {
                            status_code: response.status_code,
                            headers,
                            body,
                        });
                    }

                    if let Some(result) = context.apply_ai_temp_policies_to_request(&mut request) {
                        if result.should_persist_event() {
                            persist_http_inspection_event(
                                context.as_ref(),
                                &packet,
                                &request,
                                &result,
                            );
                        }
                        crate::core::engine::policy::enforce_runtime_http_block_if_needed(
                            context.as_ref(),
                            &packet,
                            &request,
                            &result,
                        );
                        if let Some(metrics) = context.metrics.as_ref() {
                            metrics.record_block(result.layer.clone());
                        }
                        if let Some(inspector) = context.l4_inspector() {
                            inspector.record_l7_feedback(
                                &packet,
                                &request,
                                crate::l4::behavior::FeedbackSource::L7Block,
                            );
                        }
                        if result_should_drop_http2(&result, &request) {
                            return Err(drop_http2_result(&result.reason));
                        }
                        if let Some(response) = result.custom_response.as_ref() {
                            let response = resolve_runtime_custom_response(response);
                            let body = body_for_request(&request, &response.body);
                            let mut headers = response.headers.clone();
                            apply_response_policies(
                                context.as_ref(),
                                &mut headers,
                                response.status_code,
                            );
                            return Ok(Http2Response {
                                status_code: response.status_code,
                                headers,
                                body,
                            });
                        }
                    }

                    if request
                        .get_metadata("l7.behavior.prechecked")
                        .map(String::as_str)
                        != Some("true")
                    {
                        if let Some(result) =
                            context.l7_behavior_guard().inspect_request(&mut request).await
                        {
                            if let Some(metrics) = context.metrics.as_ref() {
                                crate::core::engine::network::record_l7_behavior_metrics(
                                    metrics, &request,
                                );
                            }
                            if result.should_persist_event() {
                                persist_http_inspection_event(
                                    context.as_ref(),
                                    &packet,
                                    &request,
                                    &result,
                                );
                            }
                            crate::core::engine::policy::enforce_runtime_http_block_if_needed(
                                context.as_ref(),
                                &packet,
                                &request,
                                &result,
                            );
                            if let Some(metrics) = context.metrics.as_ref() {
                                metrics.record_block(result.layer.clone());
                            }
                            if let Some(inspector) = context.l4_inspector() {
                                inspector.record_l7_feedback(
                                    &packet,
                                    &request,
                                    crate::l4::behavior::FeedbackSource::L7Block,
                                );
                            }
                            if result_should_drop_http2(&result, &request) {
                                return Err(drop_http2_result(&result.reason));
                            }
                            if let Some(response) = result.custom_response.as_ref() {
                                let response = resolve_runtime_custom_response(response);
                                let body = body_for_request(&request, &response.body);
                                let mut headers = response.headers.clone();
                                apply_response_policies(
                                    context.as_ref(),
                                    &mut headers,
                                    response.status_code,
                                );
                                return Ok(Http2Response {
                                    status_code: response.status_code,
                                    headers,
                                    body,
                                });
                            }
                            return Ok(Http2Response {
                                status_code: 429,
                                headers: vec![],
                                body: body_for_request(&request, result.reason.as_bytes()),
                            });
                        }
                        if let Some(metrics) = context.metrics.as_ref() {
                            crate::core::engine::network::record_l7_behavior_metrics(
                                metrics, &request,
                            );
                        }
                    }

                    if request
                        .get_metadata("l7.cc.prechecked")
                        .map(String::as_str)
                        != Some("true")
                    {
                        let cc_result = context.l7_cc_guard().inspect_request(&mut request).await;
                        if let Some(metrics) = context.metrics.as_ref() {
                            record_l7_cc_metrics(metrics, &request);
                        }
                        if let Some(result) = cc_result {
                            if result.should_persist_event() {
                                persist_http_inspection_event(
                                    context.as_ref(),
                                    &packet,
                                    &request,
                                    &result,
                                );
                            }
                            crate::core::engine::policy::enforce_runtime_http_block_if_needed(
                                context.as_ref(),
                                &packet,
                                &request,
                                &result,
                            );
                            if let Some(metrics) = context.metrics.as_ref() {
                                metrics.record_block(result.layer.clone());
                            }
                            if let Some(inspector) = context.l4_inspector() {
                                inspector.record_l7_feedback(
                                    &packet,
                                    &request,
                                    crate::l4::behavior::FeedbackSource::L7Block,
                                );
                            }
                            if result_should_drop_http2(&result, &request) {
                                return Err(drop_http2_result(&result.reason));
                            }
                            if let Some(response) = result.custom_response.as_ref() {
                                let response = resolve_runtime_custom_response(response);
                                let body = body_for_request(&request, &response.body);
                                let mut headers = response.headers.clone();
                                apply_response_policies(
                                    context.as_ref(),
                                    &mut headers,
                                    response.status_code,
                                );
                                return Ok(Http2Response {
                                    status_code: response.status_code,
                                    headers,
                                    body,
                                });
                            }
                            return Ok(Http2Response {
                                status_code: 429,
                                headers: vec![],
                                body: body_for_request(&request, result.reason.as_bytes()),
                            });
                        }
                    }

                    prepare_request_for_proxy(context.as_ref(), &mut request);
                    persist_http_identity_debug_event(context.as_ref(), &packet, &request);

                    debug!("HTTP/2.0 request: {} {}", request.method, request.uri);

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

                    let inspection_result = inspect_application_layers(
                        context.as_ref(),
                        &packet,
                        &request,
                        &rule_payload,
                    );

                    if inspection_result.should_persist_event() {
                        persist_http_inspection_event(
                            context.as_ref(),
                            &packet,
                            &request,
                            &inspection_result,
                        );
                    }
                    if inspection_result.blocked
                        && inspection_result.layer == crate::core::InspectionLayer::L7
                    {
                        if let Some(inspector) = context.l4_inspector() {
                            inspector.record_l7_feedback(
                                &packet,
                                &request,
                                crate::l4::behavior::FeedbackSource::L7Block,
                            );
                        }
                    }

                    if inspection_result.blocked {
                        context.traffic_map.record_ingress(
                            traffic_source_ip.clone(),
                            request_dump.len(),
                            true,
                        );
                        if let Some(metrics) = context.metrics.as_ref() {
                            metrics.record_block(inspection_result.layer.clone());
                        }
                        if result_should_drop_http2(&inspection_result, &request) {
                            return Err(drop_http2_result(&inspection_result.reason));
                        }
                        if let Some(response) = inspection_result.custom_response.as_ref() {
                            let response = resolve_runtime_custom_response(response);
                            let body = body_for_request(&request, &response.body);
                            let mut headers = response.headers.clone();
                            apply_response_policies(
                                context.as_ref(),
                                &mut headers,
                                response.status_code,
                            );
                            return Ok(Http2Response {
                                status_code: response.status_code,
                                headers,
                                body,
                            });
                        }
                        return Ok(Http2Response {
                            status_code: 403,
                            headers: vec![],
                            body: body_for_request(
                                &request,
                                format!("blocked: {}", inspection_result.reason).as_bytes(),
                            ),
                        });
                    }

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
                            return Ok(Http2Response {
                                status_code: 503,
                                headers: vec![],
                                body: reason.to_string().into_bytes(),
                            });
                        }
                        if let Some(metrics) = context.metrics.as_ref() {
                            let labels = proxy_metric_labels(&request);
                            metrics.record_proxy_attempt_with_labels(
                                proxy_traffic_kind(&request),
                                &labels,
                            );
                        }
                        let proxy_started_at = Instant::now();
                        match proxy_http_request(
                            context.as_ref(),
                            &request,
                            upstream_addr,
                            config.l7_config.proxy_connect_timeout_ms,
                            config.l7_config.proxy_write_timeout_ms,
                            config.l7_config.proxy_read_timeout_ms,
                        )
                        .await
                        {
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
                                return match apply_safeline_upstream_action(
                                    context.as_ref(),
                                    &packet,
                                    &request,
                                    matched_site.as_ref(),
                                    resolve_safeline_intercept_config(
                                        &config,
                                        matched_site.as_ref(),
                                    ),
                                    response,
                                ) {
                                    UpstreamResponseDisposition::Forward(response) => {
                                        context.traffic_map.record_ingress(
                                            traffic_source_ip.clone(),
                                            request_dump.len(),
                                            false,
                                        );
                                        let mut headers = response.headers.clone();
                                        apply_response_policies(
                                            context.as_ref(),
                                            &mut headers,
                                            response.status_code,
                                        );
                                        Ok(Http2Response {
                                            status_code: response.status_code,
                                            headers,
                                            body: response.body,
                                        })
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
                                        Ok(Http2Response {
                                            status_code: response.status_code,
                                            headers,
                                            body,
                                        })
                                    }
                                    UpstreamResponseDisposition::Drop => {
                                        context.traffic_map.record_ingress(
                                            traffic_source_ip.clone(),
                                            request_dump.len(),
                                            true,
                                        );
                                        Err(crate::protocol::ProtocolError::ParseError(
                                            "SafeLine blocked upstream response dropped"
                                                .to_string(),
                                        ))
                                    }
                                };
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
                                    "Failed to proxy HTTP/2 request from {} to {}: {}",
                                    request.client_ip.as_deref().unwrap_or("unknown"),
                                    upstream_addr,
                                    err
                                );
                                return Ok(Http2Response {
                                    status_code: 502,
                                    headers: vec![],
                                    body: b"upstream proxy failed".to_vec(),
                                });
                            }
                        }
                    } else if matched_site.is_some() {
                        context.traffic_map.record_ingress(
                            traffic_source_ip.clone(),
                            request_dump.len(),
                            false,
                        );
                        return Ok(Http2Response {
                            status_code: 502,
                            headers: vec![],
                            body: b"site upstream not configured".to_vec(),
                        });
                    } else if should_reject_unmatched_site(context.as_ref(), &request) {
                        context.traffic_map.record_ingress(
                            traffic_source_ip.clone(),
                            request_dump.len(),
                            false,
                        );
                        if config.console_settings.drop_unmatched_requests {
                            return Err(crate::protocol::ProtocolError::ParseError(
                                "unmatched site dropped".to_string(),
                            ));
                        }
                        return Ok(Http2Response {
                            status_code: 404,
                            headers: vec![],
                            body: b"site not found".to_vec(),
                        });
                    }

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

                    Ok(Http2Response {
                        status_code: 200,
                        headers: vec![],
                        body: format!("allowed\n{}\n", metrics_line).into_bytes(),
                    })
                }
            },
            {
                let context = Arc::clone(&context_for_error);
                let packet = packet_for_error.clone();
                move |err| {
                    let context = Arc::clone(&context);
                    let packet = packet.clone();
                    async move {
                        handle_http2_slow_attack_error(context.as_ref(), &packet, err).await
                    }
                }
            },
        )
        .await?;

    if let (Some(inspector), Some(bucket_key)) = (
        context.l4_inspector(),
        bucket_key
            .lock()
            .expect("bucket key mutex poisoned")
            .clone(),
    ) {
        inspector.observe_connection_close(&bucket_key, &connection_id, opened_at);
    }

    Ok(())
}

fn result_should_drop_http2(
    result: &crate::core::InspectionResult,
    request: &UnifiedHttpRequest,
) -> bool {
    matches!(result.action, crate::core::InspectionAction::Drop)
        || request
            .get_metadata("l7.enforcement")
            .map(|value| value == "drop")
            .unwrap_or(false)
}

fn drop_http2_result(reason: &str) -> crate::protocol::ProtocolError {
    crate::protocol::ProtocolError::ParseError(format!("HTTP/2 request dropped: {reason}"))
}

async fn handle_http2_slow_attack_error(
    context: &WafContext,
    packet: &PacketInfo,
    err: crate::protocol::ProtocolError,
) -> Result<Http2Response, crate::protocol::ProtocolError> {
    let (kind, detail) = match err {
        crate::protocol::ProtocolError::SlowBody {
            bytes_read,
            expected_bytes,
            elapsed_ms,
        } => (
            crate::l7::SlowAttackKind::SlowBody,
            format!(
                "http2 bytes_read={bytes_read} expected_bytes={expected_bytes} elapsed_ms={elapsed_ms}"
            ),
        ),
        crate::protocol::ProtocolError::IdleTimeout { elapsed_ms } => (
            crate::l7::SlowAttackKind::IdleConnection,
            format!("http2 elapsed_ms={elapsed_ms}"),
        ),
        crate::protocol::ProtocolError::SlowHeader {
            bytes_read,
            elapsed_ms,
        } => (
            crate::l7::SlowAttackKind::SlowHeaders,
            format!("http2 bytes_read={bytes_read} elapsed_ms={elapsed_ms}"),
        ),
        other => return Err(other),
    };

    let trusted_proxy_peer = peer_is_configured_trusted_proxy(context, packet.source_ip);
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

    persist_http2_slow_attack_event(context, packet, kind, &assessment);
    if let Some(inspector) = context.l4_inspector() {
        let slow_request = crate::protocol::UnifiedHttpRequest::new(
            crate::protocol::HttpVersion::Http2_0,
            "SLOW".to_string(),
            format!("/slow-attack/{}", kind.as_str()),
        );
        inspector.record_l7_feedback(
            &packet,
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
    Ok(Http2Response {
        status_code: response.status_code,
        headers: response.headers,
        body: response.body,
    })
}

fn persist_http2_slow_attack_event(
    context: &WafContext,
    packet: &PacketInfo,
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
    event.http_version = Some("HTTP/2.0".to_string());
    event.details_json = serde_json::to_string_pretty(&serde_json::json!({
        "slow_attack": {
            "kind": kind.as_str(),
            "event_count": assessment.event_count,
            "block_ip": assessment.block_ip.map(|ip| ip.to_string()),
            "peer_ip": packet.source_ip.to_string(),
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
    use http_body_util::{BodyExt, Empty};
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::sync::Arc;
    use tokio::io::duplex;
    use tokio::sync::Semaphore;

    #[tokio::test]
    async fn request_level_permit_exhaustion_returns_503() {
        let context = Arc::new(
            WafContext::new(crate::config::Config::default())
                .await
                .unwrap(),
        );
        let peer_addr: std::net::SocketAddr = "127.0.0.1:54322".parse().unwrap();
        let local_addr: std::net::SocketAddr = "127.0.0.1:660".parse().unwrap();
        let request_semaphore = Arc::new(Semaphore::new(0));
        let connection_permit = Arc::new(Semaphore::new(1)).acquire_owned().await.unwrap();
        let (client, server) = duplex(16 * 1024);

        let server_task = tokio::spawn({
            let context = Arc::clone(&context);
            let request_semaphore = Arc::clone(&request_semaphore);
            async move {
                let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::TCP);
                handle_http2_connection(
                    context,
                    server,
                    peer_addr,
                    &packet,
                    Vec::new(),
                    connection_permit,
                    request_semaphore,
                )
                .await
            }
        });

        let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(client))
            .await
            .unwrap();
        let client_task = tokio::spawn(async move { conn.await });

        let request = http::Request::builder()
            .method("GET")
            .uri("https://wnluo.com/")
            .header("host", "wnluo.com")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = sender.send_request(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.unwrap().to_bytes();

        assert_eq!(status, http::StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            headers
                .get("retry-after")
                .and_then(|value| value.to_str().ok()),
            Some("5")
        );
        assert_eq!(body.as_ref(), b"gateway overloaded, retry later");

        drop(sender);
        client_task.abort();
        let _ = client_task.await;
        server_task.await.unwrap().unwrap();
    }
}
