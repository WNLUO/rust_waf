async fn handle_connection(
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

    let (stream, metadata) =
        parse_proxy_protocol_stream(context.as_ref(), stream, peer_addr).await?;

    // 协议检测和路由
    match detect_and_handle_protocol(context, stream, peer_addr, &packet, metadata).await {
        Ok(_) => Ok(()),
        Err(e) => {
            warn!("Connection handling error for {}: {}", peer_addr, e);
            Err(e)
        }
    }
}

async fn handle_tls_connection(
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

    let (stream, mut metadata) =
        parse_proxy_protocol_stream(context.as_ref(), stream, peer_addr).await?;

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
    if let Some(server_name) = tls_stream.get_ref().1.server_name() {
        metadata.push(("tls.sni".to_string(), server_name.to_string()));
    }

    match alpn.as_deref() {
        Some("h2") if config.l7_config.http2_config.enabled => {
            handle_http2_connection(context, tls_stream, peer_addr, &packet, metadata).await
        }
        _ => handle_http1_connection(context, tls_stream, peer_addr, &packet, metadata).await,
    }
}

#[cfg(feature = "http3")]
async fn handle_http3_quic_connection(
    context: Arc<WafContext>,
    incoming: QuinnIncoming,
    local_addr: SocketAddr,
    _permit: OwnedSemaphorePermit,
) -> Result<()> {
    let connection = incoming.await?;
    let peer_addr = connection.remote_address();
    let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::UDP);

    let l4_result = inspect_transport_layers(context.as_ref(), &packet);
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

    let mut h3_connection = h3::server::builder()
        .build(H3QuinnConnection::new(connection))
        .await?;

    loop {
        match h3_connection.accept().await {
            Ok(Some(resolver)) => {
                let context = Arc::clone(&context);
                let packet = packet.clone();
                let http3_handler = Http3Handler::new(context.config_snapshot().http3_config);
                tokio::spawn(async move {
                    if let Err(err) =
                        handle_http3_request(context, packet, http3_handler, resolver).await
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

    Ok(())
}

#[cfg(feature = "http3")]
async fn handle_http3_request(
    context: Arc<WafContext>,
    packet: PacketInfo,
    http3_handler: Http3Handler,
    resolver: h3::server::RequestResolver<H3QuinnConnection, Bytes>,
) -> Result<()> {
    let config = context.config_snapshot();
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
    apply_client_identity(
        context.as_ref(),
        std::net::SocketAddr::new(packet.source_ip, packet.source_port),
        &mut unified,
    );
    prepare_request_for_routing(context.as_ref(), &mut unified);
    let matched_site = resolve_gateway_site(context.as_ref(), &unified);
    if let Some(site) = matched_site.as_ref() {
        apply_gateway_site_metadata(&mut unified, site);
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

    prepare_request_for_proxy(context.as_ref(), &mut unified);

    let request_dump = unified.to_inspection_string();
    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_packet(request_dump.len());
    }

    let inspection_result =
        inspect_application_layers(context.as_ref(), &packet, &unified, &request_dump);

    if inspection_result.should_persist_event() {
        persist_http_inspection_event(context.as_ref(), &packet, &unified, &inspection_result);
    }

    if inspection_result.blocked {
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

    let upstream_addr = select_upstream_target(context.as_ref(), matched_site.as_ref());
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
        send_http3_response(&mut stream, 421, &[], b"site not found".to_vec(), None).await?;
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

async fn handle_udp_datagram(
    context: Arc<WafContext>,
    listener_socket: Arc<UdpSocket>,
    peer_addr: std::net::SocketAddr,
    local_addr: std::net::SocketAddr,
    payload: Vec<u8>,
    _permit: OwnedSemaphorePermit,
) -> Result<()> {
    let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::UDP);
    let config = context.config_snapshot();

    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_packet(payload.len());
    }

    let l4_result = inspect_transport_layers(context.as_ref(), &packet);
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
        let http3_handler = Http3Handler::new(config.http3_config.clone());
        if let Some(request) = http3_handler.inspect_datagram(&payload, peer_addr, local_addr)? {
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
        forward_udp_payload(listener_socket, peer_addr, &payload, upstream_addr).await?;
    }

    Ok(())
}

async fn forward_udp_payload(
    listener_socket: Arc<UdpSocket>,
    client_addr: std::net::SocketAddr,
    payload: &[u8],
    upstream_addr: &str,
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
        std::time::Duration::from_secs(1),
        upstream_socket.recv(&mut response),
    )
    .await??;

    listener_socket
        .send_to(&response[..response_size], client_addr)
        .await?;
    Ok(())
}

#[cfg_attr(not(test), allow(dead_code))]

async fn parse_proxy_protocol_stream(
    context: &WafContext,
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
) -> Result<(PrefixedStream<TcpStream>, Vec<(String, String)>)> {
    if context.config_snapshot().gateway_config.source_ip_strategy
        != crate::config::SourceIpStrategy::ProxyProtocol
    {
        return Ok((PrefixedStream::new(Vec::new(), stream), Vec::new()));
    }

    let mut peeked = vec![0u8; 256];
    let bytes_read = tokio::time::timeout(
        std::time::Duration::from_millis(context.config_snapshot().l7_config.first_byte_timeout_ms),
        stream.peek(&mut peeked),
    )
    .await??;
    let preview = &peeked[..bytes_read];

    let Some(line_end) = preview.windows(2).position(|item| item == b"\r\n") else {
        return Ok((PrefixedStream::new(Vec::new(), stream), Vec::new()));
    };
    let line = &preview[..line_end + 2];
    let Some(source_ip) = parse_proxy_protocol_v1_source_ip(line) else {
        return Ok((PrefixedStream::new(Vec::new(), stream), Vec::new()));
    };

    let mut stream = stream;
    let mut consumed = vec![0u8; line.len()];
    stream.read_exact(&mut consumed).await?;
    debug!(
        "Parsed PROXY protocol source ip {} for peer {}",
        source_ip, peer_addr
    );

    Ok((
        PrefixedStream::new(Vec::new(), stream),
        vec![("proxy_protocol_source_ip".to_string(), source_ip.to_string())],
    ))
}

fn parse_proxy_protocol_v1_source_ip(line: &[u8]) -> Option<std::net::IpAddr> {
    let text = std::str::from_utf8(line).ok()?.trim();
    let mut parts = text.split_whitespace();
    if parts.next()? != "PROXY" {
        return None;
    }

    match parts.next()? {
        "TCP4" | "TCP6" => parts.next()?.parse::<std::net::IpAddr>().ok(),
        "UNKNOWN" => None,
        _ => None,
    }
}

/// 检测协议版本并路由到相应的处理器
async fn detect_and_handle_protocol<S>(
    context: Arc<WafContext>,
    mut stream: S,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
    extra_metadata: Vec<(String, String)>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let config = context.config_snapshot();
    // 创建协议检测器
    let detector = ProtocolDetector::default();

    // 尝试检测协议版本（读取初始字节）
    let mut initial_buffer = vec![0u8; 256];
    let bytes_read = tokio::time::timeout(
        std::time::Duration::from_millis(config.l7_config.first_byte_timeout_ms),
        stream.read(&mut initial_buffer),
    )
    .await??;
    let stream = PrefixedStream::new(initial_buffer[..bytes_read].to_vec(), stream);

    let detected_version = if bytes_read > 0 {
        let preview = &initial_buffer[..bytes_read];
        if detector.is_http2_upgrade_request(preview) {
            debug!(
                "Detected h2c upgrade request from {}, inspecting first exchange as HTTP/1.1",
                peer_addr
            );
        }
        detector.detect_version(preview)
    } else {
        HttpVersion::Http1_1
    };

    debug!(
        "Detected protocol version: {} for connection from {}",
        detected_version, peer_addr
    );

    // 根据检测到的协议版本路由到相应处理器
    match detected_version {
        HttpVersion::Http2_0 if config.l7_config.http2_config.enabled => {
            handle_http2_connection(context, stream, peer_addr, packet, extra_metadata).await
        }
        _ => handle_http1_connection(context, stream, peer_addr, packet, extra_metadata).await,
    }
}

/// 处理HTTP/1.1连接
async fn handle_http1_connection(
    context: Arc<WafContext>,
    mut stream: impl AsyncRead + AsyncWrite + Unpin,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
    extra_metadata: Vec<(String, String)>,
) -> Result<()> {
    let config = context.config_snapshot();
    let http1_handler = Http1Handler::new();
    let extra_metadata = extra_metadata;
    let mut reusable_upstream_connection = None;

    loop {
        // 读取HTTP/1.1请求
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
        prepare_request_for_routing(context.as_ref(), &mut request);
        let matched_site = resolve_gateway_site(context.as_ref(), &request);
        if let Some(site) = matched_site.as_ref() {
            apply_gateway_site_metadata(&mut request, site);
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

        prepare_request_for_proxy(context.as_ref(), &mut request);

        debug!("HTTP/1.1 request: {} {}", request.method, request.uri);

        let request_dump = request.to_inspection_string();
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_packet(request_dump.len());
        }

        let inspection_result =
            inspect_application_layers(context.as_ref(), packet, &request, &request_dump);

        if inspection_result.should_persist_event() {
            persist_http_inspection_event(context.as_ref(), packet, &request, &inspection_result);
        }

        // 写入响应
        if inspection_result.blocked {
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
            let upstream_addr = select_upstream_target(context.as_ref(), matched_site.as_ref());
            if let Some(upstream_addr) = upstream_addr.as_deref() {
                if let Err(reason) = enforce_upstream_policy(context.as_ref()) {
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
                        match apply_safeline_upstream_action(
                            context.as_ref(),
                            packet,
                            &request,
                            matched_site.as_ref(),
                            resolve_safeline_intercept_config(&config, matched_site.as_ref()),
                            response,
                        ) {
                            UpstreamResponseDisposition::Forward(response) => {
                                write_http1_upstream_response(context.as_ref(), &mut stream, &response)
                                    .await?;
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
                                let _ = stream.shutdown().await;
                                return Ok(());
                            }
                        }
                    }
                    Err(err) => {
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
                http1_handler
                    .write_response(
                        &mut stream,
                        502,
                        "Bad Gateway",
                        b"site upstream not configured",
                    )
                    .await?;
            } else if should_reject_unmatched_site(context.as_ref(), &request) {
                http1_handler
                    .write_response(&mut stream, 421, "Misdirected Request", b"site not found")
                    .await?;
            } else {
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
            return Ok(());
        }
    }
}

/// 处理HTTP/2.0连接
async fn handle_http2_connection(
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

                async move {
                    let config = context.config_snapshot();
                    let mut request = request;
                    apply_client_identity(context.as_ref(), peer_addr, &mut request);
                    for (key, value) in request_metadata {
                        request.add_metadata(key, value);
                    }
                    prepare_request_for_routing(context.as_ref(), &mut request);
                    let matched_site = resolve_gateway_site(context.as_ref(), &request);
                    if let Some(site) = matched_site.as_ref() {
                        apply_gateway_site_metadata(&mut request, site);
                    }

                    if let Some(response) = try_handle_browser_fingerprint_report(
                        context.as_ref(),
                        &packet,
                        &request,
                        matched_site.as_ref(),
                    ) {
                        let body = body_for_request(&request, &response.body);
                        let mut headers = response.headers.clone();
                        apply_response_policies(context.as_ref(), &mut headers, response.status_code);
                        return Ok(Http2Response {
                            status_code: response.status_code,
                            headers,
                            body,
                        });
                    }

                    prepare_request_for_proxy(context.as_ref(), &mut request);

                    debug!("HTTP/2.0 request: {} {}", request.method, request.uri);

                    let request_dump = request.to_inspection_string();
                    if let Some(metrics) = context.metrics.as_ref() {
                        metrics.record_packet(request_dump.len());
                    }

                    let inspection_result = inspect_application_layers(
                        context.as_ref(),
                        &packet,
                        &request,
                        &request_dump,
                    );

                    if inspection_result.should_persist_event() {
                        persist_http_inspection_event(
                            context.as_ref(),
                            &packet,
                            &request,
                            &inspection_result,
                        );
                    }

                    if inspection_result.blocked {
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

                    let upstream_addr =
                        select_upstream_target(context.as_ref(), matched_site.as_ref());
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
                        return Ok(Http2Response {
                            status_code: 421,
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

    Ok(())
}
