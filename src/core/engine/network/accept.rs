use super::*;

pub(crate) async fn handle_connection(
    context: Arc<WafContext>,
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    connection_permit: OwnedSemaphorePermit,
    request_semaphore: Arc<Semaphore>,
) -> Result<()> {
    let local_addr = stream.local_addr()?;
    let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::TCP);
    let trusted_proxy_peer = peer_is_configured_trusted_proxy(context.as_ref(), packet.source_ip);
    let skip_l4_connection_budget =
        should_skip_l4_connection_budget_for_trusted_proxy(context.as_ref(), packet.source_ip);

    let l4_result = inspect_transport_layers(context.as_ref(), &packet, trusted_proxy_peer);
    if l4_result.should_persist_event() {
        persist_l4_inspection_event(context.as_ref(), &packet, &l4_result);
    }
    if l4_result.blocked {
        debug!(
            "L4 inspection blocked connection from {}: {}",
            peer_addr, l4_result.reason
        );
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_block(l4_result.layer.clone());
        }
        return Ok(());
    }

    if !skip_l4_connection_budget {
        if let Some(inspector) = context.l4_inspector() {
            let policy = inspector.coarse_connection_admission_policy(
                packet.source_ip,
                "http",
                skip_l4_connection_budget,
            );
            maybe_delay_policy(context.as_ref(), &policy).await;
            if policy.reject_new_connections {
                debug!(
                    "Rejecting TCP connection from {} due to coarse admission pressure",
                    peer_addr
                );
                if let Some(metrics) = context.metrics.as_ref() {
                    metrics.record_l4_bucket_budget_rejection();
                }
                return Ok(());
            }
        }
    }

    let connection_id = next_connection_id(peer_addr, local_addr, "tcp");
    let (stream, mut metadata) =
        parse_proxy_protocol_stream(context.as_ref(), stream, peer_addr).await?;
    metadata.push(("network.connection_id".to_string(), connection_id));

    match detect_and_handle_protocol(
        context,
        stream,
        peer_addr,
        &packet,
        metadata,
        connection_permit,
        request_semaphore,
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(e) => {
            warn!("Connection handling error for {}: {}", peer_addr, e);
            Err(e)
        }
    }
}

pub(crate) async fn handle_tls_connection(
    context: Arc<WafContext>,
    tls_acceptor: TlsAcceptor,
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    handshake_permit: OwnedSemaphorePermit,
    connection_semaphore: Arc<Semaphore>,
    request_semaphore: Arc<Semaphore>,
) -> Result<()> {
    let local_addr = stream.local_addr()?;
    let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::TCP);
    let trusted_proxy_peer = peer_is_configured_trusted_proxy(context.as_ref(), packet.source_ip);
    let skip_l4_connection_budget =
        should_skip_l4_connection_budget_for_trusted_proxy(context.as_ref(), packet.source_ip);
    let config = context.config_snapshot();
    let handshake_timeout_ms =
        if config.console_settings.cdn_525_diagnostic_mode && trusted_proxy_peer {
            config.l7_config.tls_handshake_timeout_ms.max(10_000)
        } else {
            config.l7_config.tls_handshake_timeout_ms
        };

    let l4_result = inspect_transport_layers(context.as_ref(), &packet, trusted_proxy_peer);
    if l4_result.should_persist_event() {
        persist_l4_inspection_event(context.as_ref(), &packet, &l4_result);
    }
    if l4_result.blocked {
        debug!(
            "L4 inspection blocked TLS connection from {}: {}",
            peer_addr, l4_result.reason
        );
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_block(l4_result.layer.clone());
        }
        return Ok(());
    }

    if !skip_l4_connection_budget {
        if let Some(inspector) = context.l4_inspector() {
            let policy = inspector.coarse_connection_admission_policy(
                packet.source_ip,
                "tls",
                skip_l4_connection_budget,
            );
            maybe_delay_policy(context.as_ref(), &policy).await;
            if policy.reject_new_connections {
                warn!(
                    "Rejecting TLS connection from {} before handshake due to coarse admission pressure",
                    peer_addr
                );
                if let Some(metrics) = context.metrics.as_ref() {
                    metrics.record_tls_pre_handshake_rejection();
                    metrics.record_l4_bucket_budget_rejection();
                }
                persist_tls_transport_event(
                    context.as_ref(),
                    &packet,
                    "block",
                    format!(
                        "tls pre-handshake admission rejected: coarse admission pressure peer_ip={} listener={} source_ip_strategy={:?}",
                        peer_addr.ip(),
                        local_addr,
                        config.gateway_config.source_ip_strategy
                    ),
                );
                return Ok(());
            }
        }
    }

    let (stream, mut metadata) =
        parse_proxy_protocol_stream(context.as_ref(), stream, peer_addr).await?;
    let connection_id = next_connection_id(peer_addr, local_addr, "tls");
    metadata.push(("network.connection_id".to_string(), connection_id.clone()));

    let tls_stream = match tokio::time::timeout(
        std::time::Duration::from_millis(handshake_timeout_ms),
        tls_acceptor.accept(stream),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            if let Some(metrics) = context.metrics.as_ref() {
                metrics.record_tls_handshake_failure();
            }
            warn!(
                "TLS handshake failed for peer {} on {}: {}",
                peer_addr, local_addr, err
            );
            persist_tls_transport_event(
                context.as_ref(),
                &packet,
                "alert",
                format!(
                    "tls handshake failed peer_ip={} listener={} reason={}",
                    peer_addr.ip(),
                    local_addr,
                    err
                ),
            );
            return Err(err.into());
        }
        Err(_) => {
            let assessment = context
                .slow_attack_guard()
                .assess(crate::l7::SlowAttackObservation {
                    kind: crate::l7::SlowAttackKind::SlowTlsHandshake,
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
                    detail: format!(
                        "listener={} timeout_ms={}",
                        local_addr, handshake_timeout_ms
                    ),
                });
            if let Some(metrics) = context.metrics.as_ref() {
                metrics.record_tls_handshake_timeout();
                metrics.record_slow_attack_tls_handshake();
                if assessment.should_block_ip {
                    metrics.record_slow_attack_block();
                }
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
                        let blocked_at = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64;
                        store.enqueue_blocked_ip(crate::storage::BlockedIpRecord::new(
                            ip.to_string(),
                            assessment.reason.clone(),
                            blocked_at,
                            blocked_at + assessment.block_duration_secs as i64,
                        ));
                    }
                }
            }
            warn!(
                "TLS handshake timed out for peer {} on {} after {}ms",
                peer_addr, local_addr, handshake_timeout_ms
            );
            persist_tls_transport_event(
                context.as_ref(),
                &packet,
                "alert",
                format!(
                    "tls handshake timed out peer_ip={} listener={} timeout_ms={}",
                    peer_addr.ip(),
                    local_addr,
                    handshake_timeout_ms,
                ),
            );
            return Err(anyhow::anyhow!("TLS handshake timed out"));
        }
    };
    drop(handshake_permit);
    let Some(connection_permit) = crate::core::engine::runtime::acquire_permit_auto(
        context.as_ref(),
        Arc::clone(&connection_semaphore),
        peer_addr,
        "TLS post-handshake",
    )
    .await
    else {
        warn!(
            "Dropping TLS connection from {} after handshake due to connection limit",
            peer_addr
        );
        return Ok(());
    };

    metadata.push(("transport".to_string(), "tls".to_string()));
    let alpn = tls_stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|proto| String::from_utf8_lossy(proto).to_string());
    if let Some(protocol) = &alpn {
        metadata.push(("tls.alpn".to_string(), protocol.clone()));
    }
    let server_name = tls_stream
        .get_ref()
        .1
        .server_name()
        .map(|value| value.to_string());
    if let Some(server_name) = &server_name {
        metadata.push(("tls.sni".to_string(), server_name.clone()));
    }
    let opened_at = std::time::Instant::now();
    let l4_bucket = context.l4_inspector().map(|inspector| {
        inspector.observe_connection_open(
            connection_id.clone(),
            &packet,
            server_name.as_deref(),
            alpn.as_deref(),
            "tls",
            alpn.as_deref().unwrap_or("tls"),
            skip_l4_connection_budget,
        )
    });
    if !skip_l4_connection_budget {
        if let (Some(inspector), Some(bucket_key)) = (context.l4_inspector(), l4_bucket.as_ref()) {
            let policy = inspector.connection_admission_policy(bucket_key);
            maybe_delay_policy(context.as_ref(), &policy).await;
            if policy.reject_new_connections {
                warn!(
                    "Rejecting TLS connection from {} due to bucket admission pressure",
                    peer_addr
                );
                if let Some(metrics) = context.metrics.as_ref() {
                    metrics.record_l4_bucket_budget_rejection();
                }
                persist_tls_transport_event(
                    context.as_ref(),
                    &packet,
                    "block",
                    format!(
                        "tls post-handshake admission rejected: bucket admission pressure peer_ip={} listener={} sni={} alpn={}",
                        peer_addr.ip(),
                        local_addr,
                        server_name.as_deref().unwrap_or("-"),
                        alpn.as_deref().unwrap_or("-"),
                    ),
                );
                inspector.observe_connection_close(bucket_key, &connection_id, opened_at);
                return Ok(());
            }
        }
    }

    let result = match alpn.as_deref() {
        Some("h2") if config.l7_config.http2_config.enabled => {
            handle_http2_connection(
                context.clone(),
                tls_stream,
                peer_addr,
                &packet,
                metadata,
                connection_permit,
                Arc::clone(&request_semaphore),
            )
            .await
        }
        _ => {
            handle_http1_connection(
                context.clone(),
                tls_stream,
                peer_addr,
                &packet,
                metadata,
                connection_permit,
                Arc::clone(&request_semaphore),
            )
            .await
        }
    };
    if let (Some(inspector), Some(bucket_key)) = (context.l4_inspector(), l4_bucket.as_ref()) {
        inspector.observe_connection_close(bucket_key, &connection_id, opened_at);
    }
    result
}

fn persist_tls_transport_event(
    context: &WafContext,
    packet: &PacketInfo,
    action: &str,
    reason: String,
) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    store.enqueue_security_event(SecurityEventRecord::now(
        "L4",
        action,
        reason,
        packet.source_ip.to_string(),
        packet.dest_ip.to_string(),
        packet.source_port,
        packet.dest_port,
        format!("{:?}", packet.protocol),
    ));
}
