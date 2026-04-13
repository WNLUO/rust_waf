use super::*;

pub(crate) async fn handle_http2_connection(
    context: Arc<WafContext>,
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
    extra_metadata: Vec<(String, String)>,
) -> Result<()> {
    let config = context.config_snapshot();
    let http2_config = &config.l7_config.http2_config;
    let http2_handler = Http2Handler::new()
        .with_max_concurrent_streams(http2_config.max_concurrent_streams)
        .with_max_frame_size(http2_config.max_frame_size)
        .with_priorities(http2_config.enable_priorities)
        .with_initial_window_size(http2_config.initial_window_size);

    let packet = packet.clone();
    let context_for_service = Arc::clone(&context);
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

    http2_handler
        .serve_connection(
            stream,
            peer_ip,
            packet.dest_port,
            max_request_size,
            move |request| {
                let context = Arc::clone(&context_for_service);
                let packet = packet.clone();
                let request_metadata = request_metadata.clone();
                let connection_id = connection_id_for_callback.clone();
                let registered = Arc::clone(&registered);
                let bucket_key = Arc::clone(&bucket_key_for_callback);

                async move {
                    let config = context.config_snapshot();
                    let mut request = request;
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
                            );
                            bucket_key
                                .lock()
                                .expect("bucket key mutex poisoned")
                                .replace(key);
                        }
                    }
                    if first_registration {
                        if let Some(inspector) = context.l4_inspector() {
                            let current_bucket_key = {
                                bucket_key
                                    .lock()
                                    .expect("bucket key mutex poisoned")
                                    .clone()
                            };
                            if let Some(bucket_key) = current_bucket_key {
                                let policy = inspector.connection_admission_policy(&bucket_key);
                                maybe_delay_policy(&policy).await;
                                if policy.reject_new_connections {
                                    return Ok(Http2Response {
                                        status_code: 429,
                                        headers: vec![],
                                        body: b"bucket connection budget exceeded".to_vec(),
                                    });
                                }
                            }
                        }
                    }
                    prepare_request_for_routing(context.as_ref(), &mut request);
                    let matched_site = resolve_gateway_site(context.as_ref(), &request);
                    if let Some(site) = matched_site.as_ref() {
                        apply_gateway_site_metadata(&mut request, site);
                    }
                    if let Some(inspector) = context.l4_inspector() {
                        let policy = inspector.apply_request_policy(&packet, &mut request);
                        maybe_delay_request(&request).await;
                        if policy.reject_new_connections {
                            return Ok(Http2Response {
                                status_code: 429,
                                headers: vec![],
                                body: b"bucket request budget exceeded".to_vec(),
                            });
                        }
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

                    prepare_request_for_proxy(context.as_ref(), &mut request);

                    debug!("HTTP/2.0 request: {} {}", request.method, request.uri);

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
                        inspect_application_layers(
                            context.as_ref(),
                            &packet,
                            &request,
                            &request_dump,
                        )
                    };

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
                    context.traffic_map.record_ingress(
                        traffic_source_ip.clone(),
                        request_dump.len(),
                        false,
                    );
                    if let Some(upstream_addr) = upstream_addr.as_deref() {
                        if let Err(reason) = enforce_upstream_policy(context.as_ref()) {
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
                            metrics.record_proxy_attempt();
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
                                    metrics.record_proxy_success(proxy_started_at.elapsed());
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
                                        Err(crate::protocol::ProtocolError::ParseError(
                                            "SafeLine blocked upstream response dropped"
                                                .to_string(),
                                        ))
                                    }
                                };
                            }
                            Err(err) => {
                                if let Some(metrics) = context.metrics.as_ref() {
                                    metrics.record_proxy_failure();
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
                        return Ok(Http2Response {
                            status_code: 502,
                            headers: vec![],
                            body: b"site upstream not configured".to_vec(),
                        });
                    } else if should_reject_unmatched_site(context.as_ref(), &request) {
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
