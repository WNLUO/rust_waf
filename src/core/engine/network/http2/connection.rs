use super::decision::{drop_http2_result, result_should_drop_http2};
use super::feedback::{enforce_and_record_l7_block_feedback, record_l7_block_feedback};
use super::proxy_flow::handle_http2_proxy_or_local_response;
use super::slow_attack::handle_http2_slow_attack_error;
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
                    context.resource_sentinel.note_http_request(packet.source_ip);
                    apply_client_identity(context.as_ref(), peer_addr, &mut request);
                    for (key, value) in request_metadata {
                        request.add_metadata(key, value);
                    }
                    apply_server_public_ip_metadata(context.as_ref(), &packet, &mut request);
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

                    if let Some(result) = evaluate_early_defense(&mut request) {
                        if result.should_persist_event() {
                            persist_http_inspection_event(
                                context.as_ref(),
                                &packet,
                                &request,
                                &result,
                            );
                        }
                        enforce_and_record_l7_block_feedback(
                            context.as_ref(),
                            &packet,
                            &request,
                            &result,
                        );
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
                        return Err(drop_http2_result(&result.reason));
                    }

                    if let Some(result) = inspect_blocked_client_ip(context.as_ref(), &request).await
                    {
                        persist_http_inspection_event(
                            context.as_ref(),
                            &packet,
                            &request,
                            &result,
                        );
                        record_l7_block_feedback(context.as_ref(), &packet, &request, &result);
                        if result_should_drop_http2(&result, &request) {
                            return Err(drop_http2_result(&result.reason));
                        }
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
                        return Ok(Http2Response {
                            status_code: 403,
                            headers: vec![],
                            body: body_for_request(&request, result.reason.as_bytes()),
                        });
                    }

                    if let Some(result) = context
                        .ip_access_guard()
                        .inspect_request(context.as_ref(), &mut request)
                    {
                        if let Some(metrics) = context.metrics.as_ref() {
                            crate::core::engine::network::record_l7_ip_access_metrics(
                                metrics, &request,
                            );
                        }
                        if !result.blocked {
                            if result.should_persist_event() {
                                persist_http_inspection_event(
                                    context.as_ref(),
                                    &packet,
                                    &request,
                                    &result,
                                );
                            }
                        } else {
                            if result.should_persist_event() {
                                persist_http_inspection_event(
                                    context.as_ref(),
                                    &packet,
                                    &request,
                                    &result,
                                );
                            }
                            record_l7_block_feedback(context.as_ref(), &packet, &request, &result);
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
                                status_code: 403,
                                headers: vec![],
                                body: body_for_request(&request, result.reason.as_bytes()),
                            });
                        }
                    }

                    if let Some(result) =
                        inspect_l7_bloom_filter(context.as_ref(), &mut request, false)
                    {
                        if result.should_persist_event() {
                            persist_http_inspection_event(
                                context.as_ref(),
                                &packet,
                                &request,
                                &result,
                            );
                        }
                        record_l7_block_feedback(context.as_ref(), &packet, &request, &result);
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
                        record_l7_block_feedback(context.as_ref(), &packet, &request, &early_inspection_result);
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
                        enforce_and_record_l7_block_feedback(context.as_ref(), &packet, &request, &result);
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
                        enforce_and_record_l7_block_feedback(context.as_ref(), &packet, &request, &result);
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

                    if let Some(result) =
                        inspect_l7_bloom_filter(context.as_ref(), &mut request, true)
                    {
                        if result.should_persist_event() {
                            persist_http_inspection_event(
                                context.as_ref(),
                                &packet,
                                &request,
                                &result,
                            );
                        }
                        record_l7_block_feedback(context.as_ref(), &packet, &request, &result);
                        if result_should_drop_http2(&result, &request) {
                            return Err(drop_http2_result(&result.reason));
                        }
                        return Ok(Http2Response {
                            status_code: 403,
                            headers: vec![],
                            body: body_for_request(&request, result.reason.as_bytes()),
                        });
                    }

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
                        enforce_and_record_l7_block_feedback(context.as_ref(), &packet, &request, &result);
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
                            enforce_and_record_l7_block_feedback(context.as_ref(), &packet, &request, &result);
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
                            enforce_and_record_l7_block_feedback(context.as_ref(), &packet, &request, &result);
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
                            return Err(drop_http2_result(&inspection_result.reason));
                        }
                        if let Some(response) = inspection_result.custom_response.as_ref() {
                            let response = resolve_runtime_custom_response(response);
                            context.note_ai_route_result(
                                &request,
                                AiRouteResultObservation {
                                    status_code: response.status_code,
                                    latency_ms: None,
                                    upstream_error: false,
                                    local_response: true,
                                    blocked: true,
                                },
                            );
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

                    handle_http2_proxy_or_local_response(
                        context.as_ref(),
                        &packet,
                        &config,
                        matched_site.as_ref(),
                        &request,
                        &traffic_source_ip,
                        request_dump.len(),
                    )
                    .await
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
