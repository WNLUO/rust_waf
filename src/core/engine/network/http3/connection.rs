use super::body::read_http3_request_body;
use super::decision::result_should_drop_http3;
use super::feedback::{enforce_and_record_l7_block_feedback, record_l7_block_feedback};
use super::proxy_flow::handle_http3_proxy_or_local_response;
use super::response::send_http3_response;
use super::slow_attack::handle_http3_slow_attack_error;
use super::*;
use crate::core::engine::policy::persist_http_identity_debug_event;

pub(crate) async fn handle_http3_quic_connection(
    context: Arc<WafContext>,
    incoming: QuinnIncoming,
    local_addr: SocketAddr,
    _connection_permit: OwnedSemaphorePermit,
    request_semaphore: Arc<Semaphore>,
) -> Result<()> {
    let connection = incoming.await?;
    let peer_addr = connection.remote_address();
    let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::UDP);
    let trusted_proxy_peer = peer_is_configured_trusted_proxy(context.as_ref(), packet.source_ip);
    let skip_l4_connection_budget =
        should_skip_l4_connection_budget_for_trusted_proxy(context.as_ref(), packet.source_ip);
    let connection_id = next_connection_id(peer_addr, local_addr, "h3");
    let opened_at = std::time::Instant::now();

    let l4_result = inspect_transport_layers(context.as_ref(), &packet, trusted_proxy_peer);
    if l4_result.should_persist_event() {
        persist_l4_inspection_event(context.as_ref(), &packet, &l4_result);
    }
    if l4_result.blocked {
        debug!(
            "L4 inspection blocked HTTP/3 connection from {}: {}",
            peer_addr, l4_result.reason
        );
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_block(l4_result.layer.clone());
        }
        connection.close(0u32.into(), b"blocked by l4 policy");
        return Ok(());
    }

    if !skip_l4_connection_budget {
        if let Some(inspector) = context.l4_inspector() {
            let policy = inspector.coarse_connection_admission_policy(
                packet.source_ip,
                "udp",
                skip_l4_connection_budget,
            );
            if policy.reject_new_connections {
                debug!(
                    "Dropping UDP datagram from {} due to coarse admission pressure",
                    peer_addr
                );
                return Ok(());
            }
        }
    }

    let l4_bucket = context.l4_inspector().map(|inspector| {
        inspector.observe_connection_open(
            connection_id.clone(),
            &packet,
            None,
            Some("h3"),
            "udp",
            "h3",
            skip_l4_connection_budget,
        )
    });

    let mut h3_connection = h3::server::builder()
        .build(H3QuinnConnection::new(connection))
        .await?;
    loop {
        match h3_connection.accept().await {
            Ok(Some(resolver)) => {
                let context = Arc::clone(&context);
                let packet = packet.clone();
                let mut http3_config = context.config_snapshot().http3_config;
                context.apply_http3_runtime_budget(&mut http3_config);
                let http3_handler = Http3Handler::new(http3_config);
                let request_semaphore = Arc::clone(&request_semaphore);
                tokio::spawn(async move {
                    if let Err(err) = handle_http3_request(
                        context,
                        packet,
                        http3_handler,
                        resolver,
                        request_semaphore,
                    )
                    .await
                    {
                        warn!("HTTP/3 request failed: {}", err);
                    }
                });
            }
            Ok(None) => break,
            Err(err) => {
                warn!("HTTP/3 connection accept loop ended: {}", err);
                break;
            }
        }
    }

    if let (Some(inspector), Some(bucket_key)) = (context.l4_inspector(), l4_bucket.as_ref()) {
        inspector.observe_connection_close(bucket_key, &connection_id, opened_at);
    }

    Ok(())
}

async fn handle_http3_request(
    context: Arc<WafContext>,
    packet: PacketInfo,
    http3_handler: Http3Handler,
    resolver: h3::server::RequestResolver<H3QuinnConnection, Bytes>,
    request_semaphore: Arc<Semaphore>,
) -> Result<()> {
    let config = context.config_snapshot();
    let peer_addr = std::net::SocketAddr::new(packet.source_ip, packet.source_port);
    let skip_l4_connection_budget =
        should_skip_l4_connection_budget_for_trusted_proxy(context.as_ref(), packet.source_ip);
    let (request, mut stream) = resolver.resolve_request().await?;
    let mut unified = http3_handler.request_to_unified(
        &request,
        Vec::new(),
        &packet.source_ip.to_string(),
        packet.dest_port,
    );
    unified.add_metadata("udp.peer".to_string(), packet.source_ip.to_string());
    unified.add_metadata("udp.local".to_string(), packet.dest_ip.to_string());
    apply_client_identity(context.as_ref(), peer_addr, &mut unified);
    apply_server_public_ip_metadata(context.as_ref(), &packet, &mut unified);
    let Some(_request_permit) = crate::core::engine::runtime::acquire_permit_auto(
        context.as_ref(),
        Arc::clone(&request_semaphore),
        peer_addr,
        "HTTP/3 request",
    )
    .await
    else {
        send_http3_response(
            &mut stream,
            503,
            &[("retry-after".to_string(), "5".to_string())],
            b"gateway overloaded, retry later".to_vec(),
            None,
        )
        .await?;
        return Ok(());
    };
    prepare_request_for_routing(context.as_ref(), &mut unified);
    context.annotate_runtime_pressure(&mut unified);
    let matched_site = resolve_gateway_site(context.as_ref(), &unified);
    if let Some(site) = matched_site.as_ref() {
        apply_gateway_site_metadata(&mut unified, site);
    }
    context.annotate_site_runtime_budget(&mut unified);
    if let Some(inspector) = context.l4_inspector() {
        let policy = inspector.apply_request_policy(&packet, &mut unified);
        if skip_l4_connection_budget && (policy.suggested_delay_ms > 0 || policy.disable_keepalive)
        {
            if let Some(metrics) = context.metrics.as_ref() {
                metrics.record_trusted_proxy_l4_degrade_action();
            }
            debug!(
                "Trusted proxy request downgraded by L4 policy on HTTP/3: peer_ip={} client_ip={} unresolved_client_ip={} delay_ms={} force_close={}",
                peer_addr.ip(),
                unified.client_ip.as_deref().unwrap_or("unknown"),
                unified
                    .get_metadata("network.client_ip_unresolved")
                    .map(String::as_str)
                    .unwrap_or("false"),
                policy.suggested_delay_ms,
                policy.disable_keepalive
            );
        }
        maybe_delay_request(&unified).await;
    }

    if let Some(result) = evaluate_early_defense(&mut unified) {
        if result.should_persist_event() {
            persist_http_inspection_event(context.as_ref(), &packet, &unified, &result);
        }
        enforce_and_record_l7_block_feedback(context.as_ref(), &packet, &unified, &result);
        context.note_ai_route_result(
            &unified,
            AiRouteResultObservation {
                status_code: 499,
                latency_ms: None,
                upstream_error: false,
                local_response: true,
                blocked: true,
            },
        );
        return Ok(());
    }

    if let Some(result) = inspect_blocked_client_ip(context.as_ref(), &unified).await {
        persist_http_inspection_event(context.as_ref(), &packet, &unified, &result);
        record_l7_block_feedback(context.as_ref(), &packet, &unified, &result);
        if result_should_drop_http3(&result, &unified) {
            return Ok(());
        }
        send_http3_response(
            &mut stream,
            403,
            &[],
            body_for_request(&unified, result.reason.as_bytes()),
            None,
        )
        .await?;
        return Ok(());
    }

    if let Some(result) = context
        .ip_access_guard()
        .inspect_request(context.as_ref(), &mut unified)
    {
        if let Some(metrics) = context.metrics.as_ref() {
            crate::core::engine::network::record_l7_ip_access_metrics(metrics, &unified);
        }
        if !result.blocked {
            if result.should_persist_event() {
                persist_http_inspection_event(context.as_ref(), &packet, &unified, &result);
            }
        } else {
            if result.should_persist_event() {
                persist_http_inspection_event(context.as_ref(), &packet, &unified, &result);
            }
            record_l7_block_feedback(context.as_ref(), &packet, &unified, &result);
            if result_should_drop_http3(&result, &unified) {
                return Ok(());
            }
            if let Some(response) = result.custom_response.as_ref() {
                let response =
                    crate::core::engine::network::helpers::soften_explicit_response_for_runtime(
                        context.as_ref(),
                        &resolve_runtime_custom_response(response),
                    );
                send_http3_response(
                    &mut stream,
                    response.status_code,
                    &response.headers,
                    body_for_request(&unified, &response.body),
                    response.tarpit.as_ref(),
                )
                .await?;
            } else {
                send_http3_response(
                    &mut stream,
                    403,
                    &[],
                    body_for_request(&unified, result.reason.as_bytes()),
                    None,
                )
                .await?;
            }
            return Ok(());
        }
    }

    if let Some(result) = inspect_l7_bloom_filter(context.as_ref(), &mut unified, false) {
        if result.should_persist_event() {
            persist_http_inspection_event(context.as_ref(), &packet, &unified, &result);
        }
        record_l7_block_feedback(context.as_ref(), &packet, &unified, &result);
        if result_should_drop_http3(&result, &unified) {
            return Ok(());
        }
        send_http3_response(
            &mut stream,
            403,
            &[],
            body_for_request(&unified, result.reason.as_bytes()),
            None,
        )
        .await?;
        return Ok(());
    }

    let early_rule_payload = unified.to_lightweight_inspection_string();
    let early_inspection_result =
        inspect_application_layers(context.as_ref(), &packet, &unified, &early_rule_payload);
    if early_inspection_result.blocked {
        if early_inspection_result.should_persist_event() {
            persist_http_inspection_event(
                context.as_ref(),
                &packet,
                &unified,
                &early_inspection_result,
            );
        }
        record_l7_block_feedback(
            context.as_ref(),
            &packet,
            &unified,
            &early_inspection_result,
        );
        if result_should_drop_http3(&early_inspection_result, &unified) {
            return Ok(());
        }
        if let Some(response) = early_inspection_result.custom_response.as_ref() {
            let response =
                crate::core::engine::network::helpers::soften_explicit_response_for_runtime(
                    context.as_ref(),
                    &resolve_runtime_custom_response(response),
                );
            send_http3_response(
                &mut stream,
                response.status_code,
                &response.headers,
                body_for_request(&unified, &response.body),
                response.tarpit.as_ref(),
            )
            .await?;
        } else {
            send_http3_response(
                &mut stream,
                403,
                &[],
                body_for_request(&unified, early_inspection_result.reason.as_bytes()),
                None,
            )
            .await?;
        }
        return Ok(());
    }

    if let Some(result) = context
        .l7_behavior_guard()
        .inspect_request(&mut unified)
        .await
    {
        unified.add_metadata("l7.behavior.prechecked".to_string(), "true".to_string());
        if let Some(metrics) = context.metrics.as_ref() {
            crate::core::engine::network::record_l7_behavior_metrics(metrics, &unified);
        }
        if result.should_persist_event() {
            persist_http_inspection_event(context.as_ref(), &packet, &unified, &result);
        }
        enforce_and_record_l7_block_feedback(context.as_ref(), &packet, &unified, &result);
        if result_should_drop_http3(&result, &unified) {
            return Ok(());
        }
        if let Some(response) = result.custom_response.as_ref() {
            let response =
                crate::core::engine::network::helpers::soften_explicit_response_for_runtime(
                    context.as_ref(),
                    &resolve_runtime_custom_response(response),
                );
            send_http3_response(
                &mut stream,
                response.status_code,
                &response.headers,
                response.body,
                response.tarpit.as_ref(),
            )
            .await?;
            return Ok(());
        }
        send_http3_response(&mut stream, 429, &[], result.reason.into_bytes(), None).await?;
        return Ok(());
    }
    unified.add_metadata("l7.behavior.prechecked".to_string(), "true".to_string());

    let cc_result = context.l7_cc_guard().inspect_request(&mut unified).await;
    unified.add_metadata("l7.cc.prechecked".to_string(), "true".to_string());
    if let Some(metrics) = context.metrics.as_ref() {
        record_l7_cc_metrics(metrics, &unified);
    }
    if let Some(result) = cc_result {
        if result.should_persist_event() {
            persist_http_inspection_event(context.as_ref(), &packet, &unified, &result);
        }
        enforce_and_record_l7_block_feedback(context.as_ref(), &packet, &unified, &result);
        if result_should_drop_http3(&result, &unified) {
            return Ok(());
        }
        if let Some(response) = result.custom_response.as_ref() {
            let response =
                crate::core::engine::network::helpers::soften_explicit_response_for_runtime(
                    context.as_ref(),
                    &resolve_runtime_custom_response(response),
                );
            send_http3_response(
                &mut stream,
                response.status_code,
                &response.headers,
                response.body,
                response.tarpit.as_ref(),
            )
            .await?;
            return Ok(());
        }
        send_http3_response(&mut stream, 429, &[], result.reason.into_bytes(), None).await?;
        return Ok(());
    }

    let body = match read_http3_request_body(
        &mut stream,
        config.l7_config.max_request_size,
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
            handle_http3_slow_attack_error(context.as_ref(), &packet, &mut stream, err).await?;
            return Ok(());
        }
        Err(err) => return Err(err.into()),
    };
    unified.body = body;

    if let Some(result) = inspect_l7_bloom_filter(context.as_ref(), &mut unified, true) {
        if result.should_persist_event() {
            persist_http_inspection_event(context.as_ref(), &packet, &unified, &result);
        }
        record_l7_block_feedback(context.as_ref(), &packet, &unified, &result);
        if result_should_drop_http3(&result, &unified) {
            return Ok(());
        }
        send_http3_response(
            &mut stream,
            403,
            &[],
            body_for_request(&unified, result.reason.as_bytes()),
            None,
        )
        .await?;
        return Ok(());
    }

    if let Some(response) = try_handle_browser_fingerprint_report(
        context.as_ref(),
        &packet,
        &unified,
        matched_site.as_ref(),
    ) {
        send_http3_response(
            &mut stream,
            response.status_code,
            &response.headers,
            response.body,
            None,
        )
        .await?;
        return Ok(());
    }

    if let Some(result) = context.apply_ai_temp_policies_to_request(&mut unified) {
        if result.should_persist_event() {
            persist_http_inspection_event(context.as_ref(), &packet, &unified, &result);
        }
        enforce_and_record_l7_block_feedback(context.as_ref(), &packet, &unified, &result);
        if result_should_drop_http3(&result, &unified) {
            return Ok(());
        }
        if let Some(response) = result.custom_response.as_ref() {
            let response =
                crate::core::engine::network::helpers::soften_explicit_response_for_runtime(
                    context.as_ref(),
                    &resolve_runtime_custom_response(response),
                );
            send_http3_response(
                &mut stream,
                response.status_code,
                &response.headers,
                response.body,
                response.tarpit.as_ref(),
            )
            .await?;
        }
        return Ok(());
    }

    if unified
        .get_metadata("l7.behavior.prechecked")
        .map(String::as_str)
        != Some("true")
    {
        if let Some(result) = context
            .l7_behavior_guard()
            .inspect_request(&mut unified)
            .await
        {
            if let Some(metrics) = context.metrics.as_ref() {
                crate::core::engine::network::record_l7_behavior_metrics(metrics, &unified);
            }
            if result.should_persist_event() {
                persist_http_inspection_event(context.as_ref(), &packet, &unified, &result);
            }
            enforce_and_record_l7_block_feedback(context.as_ref(), &packet, &unified, &result);
            if result_should_drop_http3(&result, &unified) {
                return Ok(());
            }
            if let Some(response) = result.custom_response.as_ref() {
                let response =
                    crate::core::engine::network::helpers::soften_explicit_response_for_runtime(
                        context.as_ref(),
                        &resolve_runtime_custom_response(response),
                    );
                send_http3_response(
                    &mut stream,
                    response.status_code,
                    &response.headers,
                    response.body,
                    response.tarpit.as_ref(),
                )
                .await?;
                return Ok(());
            }
            send_http3_response(&mut stream, 429, &[], result.reason.into_bytes(), None).await?;
            return Ok(());
        }
        if let Some(metrics) = context.metrics.as_ref() {
            crate::core::engine::network::record_l7_behavior_metrics(metrics, &unified);
        }
    }

    if unified.get_metadata("l7.cc.prechecked").map(String::as_str) != Some("true") {
        let cc_result = context.l7_cc_guard().inspect_request(&mut unified).await;
        if let Some(metrics) = context.metrics.as_ref() {
            record_l7_cc_metrics(metrics, &unified);
        }
        if let Some(result) = cc_result {
            if result.should_persist_event() {
                persist_http_inspection_event(context.as_ref(), &packet, &unified, &result);
            }
            enforce_and_record_l7_block_feedback(context.as_ref(), &packet, &unified, &result);
            if result_should_drop_http3(&result, &unified) {
                return Ok(());
            }
            if let Some(response) = result.custom_response.as_ref() {
                let response =
                    crate::core::engine::network::helpers::soften_explicit_response_for_runtime(
                        context.as_ref(),
                        &resolve_runtime_custom_response(response),
                    );
                send_http3_response(
                    &mut stream,
                    response.status_code,
                    &response.headers,
                    response.body,
                    response.tarpit.as_ref(),
                )
                .await?;
                return Ok(());
            }
            send_http3_response(&mut stream, 429, &[], result.reason.into_bytes(), None).await?;
            return Ok(());
        }
    }

    prepare_request_for_proxy(context.as_ref(), &mut unified);
    persist_http_identity_debug_event(context.as_ref(), &packet, &unified);

    let request_dump = unified.to_inspection_string();
    let critical_overload = request_in_critical_overload(&unified);
    let rule_inspection_mode = if critical_overload {
        "lightweight"
    } else {
        "full"
    };
    unified.add_metadata(
        "l7.rule_inspection_mode".to_string(),
        rule_inspection_mode.to_string(),
    );
    let rule_payload = if critical_overload {
        unified.to_lightweight_inspection_string()
    } else {
        request_dump.clone()
    };
    let traffic_source_ip = unified
        .client_ip
        .clone()
        .unwrap_or_else(|| packet.source_ip.to_string());
    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_packet(request_dump.len());
    }

    let inspection_result =
        inspect_application_layers(context.as_ref(), &packet, &unified, &rule_payload);

    if inspection_result.should_persist_event() {
        persist_http_inspection_event(context.as_ref(), &packet, &unified, &inspection_result);
    }
    if inspection_result.blocked && inspection_result.layer == crate::core::InspectionLayer::L7 {
        if let Some(inspector) = context.l4_inspector() {
            inspector.record_l7_feedback(
                &packet,
                &unified,
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
        if result_should_drop_http3(&inspection_result, &unified) {
            return Ok(());
        }
        if let Some(response) = inspection_result.custom_response.as_ref() {
            let response =
                crate::core::engine::network::helpers::soften_explicit_response_for_runtime(
                    context.as_ref(),
                    &resolve_runtime_custom_response(response),
                );
            send_http3_response(
                &mut stream,
                response.status_code,
                &response.headers,
                response.body,
                response.tarpit.as_ref(),
            )
            .await?;
            return Ok(());
        }
        send_http3_response(
            &mut stream,
            403,
            &[],
            format!("blocked: {}", inspection_result.reason).into_bytes(),
            None,
        )
        .await?;
        return Ok(());
    }

    handle_http3_proxy_or_local_response(
        context.as_ref(),
        &mut stream,
        &config,
        matched_site.as_ref(),
        &unified,
        &traffic_source_ip,
        request_dump.len(),
    )
    .await?;
    Ok(())
}
