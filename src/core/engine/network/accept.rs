use super::*;

pub(crate) async fn handle_connection(
    context: Arc<WafContext>,
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    _permit: OwnedSemaphorePermit,
) -> Result<()> {
    let local_addr = stream.local_addr()?;
    let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::TCP);

    let l4_result = inspect_transport_layers(context.as_ref(), &packet);
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

    if let Some(inspector) = context.l4_inspector() {
        let policy = inspector.coarse_connection_admission_policy(packet.source_ip, "http");
        maybe_delay_policy(&policy).await;
        if policy.reject_new_connections {
            debug!(
                "Rejecting TCP connection from {} due to coarse admission pressure",
                peer_addr
            );
            return Ok(());
        }
    }

    let connection_id = next_connection_id(peer_addr, local_addr, "tcp");
    let (stream, mut metadata) =
        parse_proxy_protocol_stream(context.as_ref(), stream, peer_addr).await?;
    metadata.push(("network.connection_id".to_string(), connection_id));

    match detect_and_handle_protocol(context, stream, peer_addr, &packet, metadata).await {
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
    _permit: OwnedSemaphorePermit,
) -> Result<()> {
    let local_addr = stream.local_addr()?;
    let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::TCP);
    let config = context.config_snapshot();

    let l4_result = inspect_transport_layers(context.as_ref(), &packet);
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

    if let Some(inspector) = context.l4_inspector() {
        let policy = inspector.coarse_connection_admission_policy(packet.source_ip, "tls");
        maybe_delay_policy(&policy).await;
        if policy.reject_new_connections {
            debug!(
                "Rejecting TLS connection from {} before handshake due to coarse admission pressure",
                peer_addr
            );
            return Ok(());
        }
    }

    let (stream, mut metadata) =
        parse_proxy_protocol_stream(context.as_ref(), stream, peer_addr).await?;
    let connection_id = next_connection_id(peer_addr, local_addr, "tls");
    metadata.push(("network.connection_id".to_string(), connection_id.clone()));

    let tls_stream = tokio::time::timeout(
        std::time::Duration::from_millis(config.l7_config.tls_handshake_timeout_ms),
        tls_acceptor.accept(stream),
    )
    .await
    .map_err(|_| anyhow::anyhow!("TLS handshake timed out"))??;
    let alpn = tls_stream
        .get_ref()
        .1
        .alpn_protocol()
        .map(|proto| String::from_utf8_lossy(proto).to_string());
    metadata.push(("transport".to_string(), "tls".to_string()));
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
        )
    });
    if let (Some(inspector), Some(bucket_key)) = (context.l4_inspector(), l4_bucket.as_ref()) {
        let policy = inspector.connection_admission_policy(bucket_key);
        maybe_delay_policy(&policy).await;
        if policy.reject_new_connections {
            debug!(
                "Rejecting TLS connection from {} due to bucket admission pressure",
                peer_addr
            );
            inspector.observe_connection_close(bucket_key, &connection_id, opened_at);
            return Ok(());
        }
    }

    let result = match alpn.as_deref() {
        Some("h2") if config.l7_config.http2_config.enabled => {
            handle_http2_connection(context.clone(), tls_stream, peer_addr, &packet, metadata).await
        }
        _ => {
            handle_http1_connection(context.clone(), tls_stream, peer_addr, &packet, metadata).await
        }
    };
    if let (Some(inspector), Some(bucket_key)) = (context.l4_inspector(), l4_bucket.as_ref()) {
        inspector.observe_connection_close(bucket_key, &connection_id, opened_at);
    }
    result
}
