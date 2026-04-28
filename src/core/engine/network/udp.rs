use super::*;

pub(crate) async fn handle_udp_datagram(
    context: Arc<WafContext>,
    listener_socket: Arc<UdpSocket>,
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
    payload: Vec<u8>,
    _permit: OwnedSemaphorePermit,
) -> Result<()> {
    let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::UDP);
    let config = context.config_snapshot();
    let trusted_proxy_peer = peer_is_configured_trusted_proxy(context.as_ref(), packet.source_ip);

    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_packet(payload.len());
    }

    let l4_result = inspect_transport_layers(context.as_ref(), &packet, trusted_proxy_peer);
    if l4_result.should_persist_event() {
        persist_l4_inspection_event(context.as_ref(), &packet, &l4_result);
    }
    if l4_result.blocked {
        debug!(
            "L4 inspection blocked UDP datagram from {}: {}",
            peer_addr, l4_result.reason
        );
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_block(l4_result.layer.clone());
        }
        return Ok(());
    }

    debug!(
        "Allowed UDP datagram from {} to {} ({} bytes)",
        peer_addr,
        local_addr,
        payload.len()
    );

    if config.http3_config.enabled {
        let mut http3_config = config.http3_config.clone();
        context.apply_http3_runtime_budget(&mut http3_config);
        let http3_handler = Http3Handler::new(http3_config);
        if let Some(mut request) =
            http3_handler.inspect_datagram(&payload, peer_addr, local_addr)?
        {
            context.annotate_runtime_pressure(&mut request);
            debug!("Detected QUIC/HTTP3 datagram from {}", peer_addr);
            let request_dump = request.to_inspection_string();
            let inspection_result =
                inspect_application_layers(context.as_ref(), &packet, &request, &request_dump);

            if inspection_result.should_persist_event() {
                persist_http_inspection_event(
                    context.as_ref(),
                    &packet,
                    &request,
                    &inspection_result,
                );
            }

            if inspection_result.blocked {
                crate::core::engine::policy::enforce_runtime_http_block_if_needed(
                    context.as_ref(),
                    &packet,
                    &request,
                    &inspection_result,
                );
                if let Some(metrics) = context.metrics.as_ref() {
                    metrics.record_block(inspection_result.layer.clone());
                }
                debug!(
                    "Blocked QUIC/HTTP3 datagram from {}: {}",
                    peer_addr, inspection_result.reason
                );
                return Ok(());
            }
        }
    }

    if let Some(upstream_addr) = config.udp_upstream_addr.as_deref() {
        forward_udp_payload(
            listener_socket,
            peer_addr,
            &payload,
            upstream_addr,
            config.udp_upstream_response_timeout_ms,
        )
        .await?;
    }

    Ok(())
}

async fn forward_udp_payload(
    listener_socket: Arc<UdpSocket>,
    client_addr: std::net::SocketAddr,
    payload: &[u8],
    upstream_addr: &str,
    response_timeout_ms: u64,
) -> Result<()> {
    let upstream_addr: std::net::SocketAddr = upstream_addr.parse()?;
    let bind_addr = match upstream_addr {
        std::net::SocketAddr::V4(_) => "0.0.0.0:0",
        std::net::SocketAddr::V6(_) => "[::]:0",
    };
    let upstream_socket = UdpSocket::bind(bind_addr).await?;
    upstream_socket.send_to(payload, upstream_addr).await?;

    let mut response = vec![0u8; 65_535];
    let response_size = tokio::time::timeout(
        std::time::Duration::from_millis(response_timeout_ms.clamp(25, 1_000)),
        upstream_socket.recv(&mut response),
    )
    .await??;

    listener_socket
        .send_to(&response[..response_size], client_addr)
        .await?;
    Ok(())
}
