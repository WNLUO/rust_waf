#[cfg(feature = "http3")]
use super::*;

#[cfg(feature = "http3")]
pub(crate) async fn handle_http3_quic_connection(
    context: Arc<WafContext>,
    incoming: QuinnIncoming,
    local_addr: SocketAddr,
    setup_permit: OwnedSemaphorePermit,
    connection_semaphore: Arc<Semaphore>,
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
    drop(setup_permit);

    loop {
        match h3_connection.accept().await {
            Ok(Some(resolver)) => {
                let context = Arc::clone(&context);
                let packet = packet.clone();
                let http3_handler = Http3Handler::new(context.config_snapshot().http3_config);
                let connection_semaphore = Arc::clone(&connection_semaphore);
                tokio::spawn(async move {
                    if let Err(err) = handle_http3_request(
                        context,
                        packet,
                        http3_handler,
                        resolver,
                        connection_semaphore,
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

#[cfg(feature = "http3")]
async fn handle_http3_request(
    context: Arc<WafContext>,
    packet: PacketInfo,
    http3_handler: Http3Handler,
    resolver: h3::server::RequestResolver<H3QuinnConnection, Bytes>,
    connection_semaphore: Arc<Semaphore>,
) -> Result<()> {
    let config = context.config_snapshot();
    let peer_addr = std::net::SocketAddr::new(packet.source_ip, packet.source_port);
    let skip_l4_connection_budget =
        should_skip_l4_connection_budget_for_trusted_proxy(context.as_ref(), packet.source_ip);
    let (request, mut stream) = resolver.resolve_request().await?;
    let body = read_http3_request_body(
        &mut stream,
        config.l7_config.max_request_size,
        config.l7_config.read_idle_timeout_ms,
    )
    .await?;

    let mut unified = http3_handler.request_to_unified(
        &request,
        body,
        &packet.source_ip.to_string(),
        packet.dest_port,
    );
    unified.add_metadata("udp.peer".to_string(), packet.source_ip.to_string());
    unified.add_metadata("udp.local".to_string(), packet.dest_ip.to_string());
    apply_client_identity(context.as_ref(), peer_addr, &mut unified);
    let Some(_request_permit) = crate::core::engine::runtime::acquire_permit_auto(
        context.as_ref(),
        Arc::clone(&connection_semaphore),
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
    let matched_site = resolve_gateway_site(context.as_ref(), &unified);
    if let Some(site) = matched_site.as_ref() {
        apply_gateway_site_metadata(&mut unified, site);
    }
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

    let cc_result = context.l7_cc_guard().inspect_request(&mut unified).await;
    if let Some(metrics) = context.metrics.as_ref() {
        record_l7_cc_metrics(metrics, &unified);
    }
    if let Some(result) = cc_result {
        if result.should_persist_event() {
            persist_http_inspection_event(context.as_ref(), &packet, &unified, &result);
        }
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_block(result.layer.clone());
        }
        if let Some(inspector) = context.l4_inspector() {
            inspector.record_l7_feedback(
                &packet,
                &unified,
                crate::l4::behavior::FeedbackSource::L7Block,
            );
        }
        if let Some(response) = result.custom_response.as_ref() {
            let response = resolve_runtime_custom_response(response);
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

    prepare_request_for_proxy(context.as_ref(), &mut unified);

    let request_dump = unified.to_inspection_string();
    let traffic_source_ip = unified
        .client_ip
        .clone()
        .unwrap_or_else(|| packet.source_ip.to_string());
    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_packet(request_dump.len());
    }

    let inspection_result = if request_in_critical_overload(&unified) {
        InspectionResult::allow(InspectionLayer::L7)
    } else {
        inspect_application_layers(context.as_ref(), &packet, &unified, &request_dump)
    };

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
        if let Some(response) = inspection_result.custom_response.as_ref() {
            let response = resolve_runtime_custom_response(response);
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

    let upstream_addr = select_upstream_target(matched_site.as_ref());
    context
        .traffic_map
        .record_ingress(traffic_source_ip.clone(), request_dump.len(), false);
    if let Some(upstream_addr) = upstream_addr.as_deref() {
        if let Err(reason) = enforce_upstream_policy(context.as_ref()) {
            if let Some(metrics) = context.metrics.as_ref() {
                metrics.record_fail_close_rejection();
            }
            send_http3_response(&mut stream, 503, &[], reason.to_string().into_bytes(), None)
                .await?;
            return Ok(());
        }
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_proxy_attempt();
        }
        let proxy_started_at = Instant::now();
        match proxy_http_request(
            context.as_ref(),
            &unified,
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
            Err(err) => {
                if let Some(metrics) = context.metrics.as_ref() {
                    metrics.record_proxy_failure();
                }
                context.set_upstream_health(false, Some(err.to_string()));
                warn!(
                    "Failed to proxy HTTP/3 request from {} to {}: {}",
                    unified.client_ip.as_deref().unwrap_or("unknown"),
                    upstream_addr,
                    err
                );
                send_http3_response(
                    &mut stream,
                    502,
                    &[],
                    b"upstream proxy failed".to_vec(),
                    None,
                )
                .await?;
                return Ok(());
            }
        }
    } else if matched_site.is_some() {
        send_http3_response(
            &mut stream,
            502,
            &[],
            b"site upstream not configured".to_vec(),
            None,
        )
        .await?;
        return Ok(());
    } else if should_reject_unmatched_site(context.as_ref(), &unified) {
        if config.console_settings.drop_unmatched_requests {
            return Ok(());
        }
        send_http3_response(&mut stream, 404, &[], b"site not found".to_vec(), None).await?;
        return Ok(());
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

    send_http3_response(
        &mut stream,
        200,
        &[],
        format!("allowed\n{}\n", metrics_line).into_bytes(),
        None,
    )
    .await?;
    Ok(())
}

#[cfg(feature = "http3")]
async fn read_http3_request_body(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    max_size: usize,
    read_idle_timeout_ms: u64,
) -> Result<Vec<u8>> {
    let mut body = Vec::new();

    while let Some(mut chunk) = tokio::time::timeout(
        std::time::Duration::from_millis(read_idle_timeout_ms),
        stream.recv_data(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("HTTP/3 body read timed out"))??
    {
        let remaining = chunk.remaining();
        if body.len() + remaining > max_size {
            anyhow::bail!("HTTP/3 request body exceeded limit");
        }
        body.extend_from_slice(chunk.copy_to_bytes(remaining).as_ref());
    }

    Ok(body)
}

#[cfg(feature = "http3")]
async fn send_http3_response(
    stream: &mut RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status_code: u16,
    headers: &[(String, String)],
    body: Vec<u8>,
    tarpit: Option<&crate::core::TarpitConfig>,
) -> Result<()> {
    let mut builder = http::Response::builder().status(status_code);
    for (key, value) in headers {
        if key.eq_ignore_ascii_case("transfer-encoding")
            || key.eq_ignore_ascii_case("connection")
            || key.starts_with(':')
        {
            continue;
        }
        builder = builder.header(key, value);
    }

    stream.send_response(builder.body(())?).await?;
    if !body.is_empty() {
        if let Some(tarpit) = tarpit {
            for chunk in body.chunks(tarpit.bytes_per_chunk) {
                stream.send_data(Bytes::copy_from_slice(chunk)).await?;
                if chunk.len() == tarpit.bytes_per_chunk {
                    tokio::time::sleep(std::time::Duration::from_millis(tarpit.chunk_interval_ms))
                        .await;
                }
            }
        } else {
            stream.send_data(Bytes::from(body)).await?;
        }
    }
    stream.finish().await?;
    Ok(())
}
