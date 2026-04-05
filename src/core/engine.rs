use anyhow::Result;
use log::{debug, info, warn};
use std::sync::Arc;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

use super::WafContext;
use crate::config::{Config, RuntimeProfile};
use crate::core::{InspectionLayer, InspectionResult, PacketInfo, Protocol};
use crate::l4::connection::limiter::RATE_LIMIT_BLOCK_DURATION_SECS;
use crate::protocol::{
    Http1Handler, Http2Handler, Http2Response, Http3Handler, HttpVersion, ProtocolDetector,
    UnifiedHttpRequest,
};
use crate::storage::{BlockedIpRecord, SecurityEventRecord};

pub struct WafEngine {
    context: Arc<WafContext>,
    shutdown_rx: mpsc::Receiver<()>,
    connection_semaphore: Arc<Semaphore>,
}

impl WafEngine {
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing WAF engine...");

        let (_shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let concurrency_limit = config.max_concurrent_tasks.max(1);
        let context = Arc::new(WafContext::new(config).await?);

        Ok(Self {
            context,
            shutdown_rx,
            connection_semaphore: Arc::new(Semaphore::new(concurrency_limit)),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("WAF engine started");
        info!(
            "Concurrency limit set to {} inflight connections",
            self.context.config.max_concurrent_tasks
        );

        if let Some(l4_inspector) = &self.context.l4_inspector {
            l4_inspector.start(self.context.as_ref()).await?;
        }

        if let Some(l7_inspector) = &self.context.l7_inspector {
            l7_inspector.start(self.context.as_ref()).await?;
        }

        #[cfg(feature = "api")]
        if self.context.config.api_enabled {
            let addr = self.context.config.api_bind.parse()?;
            let context = Arc::clone(&self.context);
            tokio::spawn(async move {
                if let Err(err) = crate::api::ApiServer::new(addr, context).start().await {
                    warn!("API server exited with error: {}", err);
                }
            });
        }

        #[cfg(not(feature = "api"))]
        if self.context.config.api_enabled {
            warn!("API support was requested but the binary was built without the 'api' feature");
        }

        let maintenance_interval = self.context.config.maintenance_interval_secs.max(5);
        let mut maintenance =
            tokio::time::interval(tokio::time::Duration::from_secs(maintenance_interval));

        // 创建多个监听器，每个监听器在独立任务中运行
        let mut shutdown_senders = Vec::new();
        let mut tcp_listener_addresses = Vec::new();
        let mut udp_listener_addresses = Vec::new();

        // 先绑定所有TCP/UDP监听器
        for addr in &self.context.config.listen_addrs {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    let addr = listener.local_addr()?;
                    tcp_listener_addresses.push((addr, listener));
                }
                Err(err) => {
                    warn!("Failed to bind TCP listener on {}: {}", addr, err);
                }
            }

            match UdpSocket::bind(addr).await {
                Ok(socket) => {
                    let addr = socket.local_addr()?;
                    udp_listener_addresses.push((addr, Arc::new(socket)));
                }
                Err(err) => {
                    warn!("Failed to bind UDP listener on {}: {}", addr, err);
                }
            }
        }

        if tcp_listener_addresses.is_empty() && udp_listener_addresses.is_empty() {
            anyhow::bail!("No TCP or UDP listeners could be started. Please check configuration.");
        }

        // 为每个TCP监听器启动独立任务
        for (addr, listener) in tcp_listener_addresses {
            info!("TCP inspection listener started on {}", addr);
            let context = Arc::clone(&self.context);
            let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
            let connection_semaphore = Arc::clone(&self.connection_semaphore);

            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            info!("Listener shutdown signal received for {}", addr);
                            break;
                        }
                        accept_result = listener.accept() => {
                            match accept_result {
                                Ok((stream, peer_addr)) => {
                                    match connection_semaphore.clone().try_acquire_owned() {
                                        Ok(permit) => {
                                            let ctx = Arc::clone(&context);
                                            tokio::spawn(async move {
                                                if let Err(err) =
                                                    handle_connection(ctx, stream, peer_addr, permit).await
                                                {
                                                    warn!("Connection handling failed: {}", err);
                                                }
                                            });
                                        }
                                        Err(_) => {
                                            warn!(
                                                "Dropping connection from {} due to concurrency limit",
                                                peer_addr
                                            );
                                        }
                                    }
                                }
                                Err(err) => {
                                    warn!("Failed to accept connection on {}: {}", addr, err);
                                }
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            info!("Ctrl+C received, shutting down listener on {}", addr);
                            break;
                        }
                    }
                }
            });
            shutdown_senders.push((task, shutdown_tx));
        }

        // 为每个UDP监听器启动独立任务
        for (addr, socket) in udp_listener_addresses {
            info!("UDP inspection listener started on {}", addr);
            let context = Arc::clone(&self.context);
            let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
            let connection_semaphore = Arc::clone(&self.connection_semaphore);

            let task = tokio::spawn(async move {
                let mut buffer = vec![0u8; 65_535];
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            info!("UDP listener shutdown signal received for {}", addr);
                            break;
                        }
                        recv_result = socket.recv_from(&mut buffer) => {
                            match recv_result {
                                Ok((bytes_read, peer_addr)) => {
                                    match connection_semaphore.clone().try_acquire_owned() {
                                        Ok(permit) => {
                                            let ctx = Arc::clone(&context);
                                            let listener_socket = Arc::clone(&socket);
                                            let payload = buffer[..bytes_read].to_vec();
                                            tokio::spawn(async move {
                                                if let Err(err) = handle_udp_datagram(
                                                    ctx,
                                                    listener_socket,
                                                    peer_addr,
                                                    addr,
                                                    payload,
                                                    permit,
                                                ).await {
                                                    warn!("UDP datagram handling failed: {}", err);
                                                }
                                            });
                                        }
                                        Err(_) => {
                                            warn!(
                                                "Dropping UDP datagram from {} due to concurrency limit",
                                                peer_addr
                                            );
                                        }
                                    }
                                }
                                Err(err) => {
                                    warn!("Failed to receive UDP datagram on {}: {}", addr, err);
                                }
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            info!("Ctrl+C received, shutting down UDP listener on {}", addr);
                            break;
                        }
                    }
                }
            });
            shutdown_senders.push((task, shutdown_tx));
        }

        info!(
            "Successfully started {} listener task(s)",
            shutdown_senders.len()
        );

        // 主循环处理维护任务
        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    // 通知所有监听器任务关闭
                    for (_, shutdown_tx) in &shutdown_senders {
                        let _ = shutdown_tx.send(()).await;
                    }
                    break Ok(());
                }
                _ = maintenance.tick() => {
                    self.run_maintenance().await;
                }
                _ = tokio::signal::ctrl_c() => {
                    info!("Ctrl+C received, shutting down");
                    // 通知所有监听器任务关闭
                    for (_, shutdown_tx) in &shutdown_senders {
                        let _ = shutdown_tx.send(()).await;
                    }
                    break Ok(());
                }
            }
        }
    }

    async fn run_maintenance(&self) {
        if let Err(err) = self.context.refresh_rules_from_storage().await {
            warn!("Failed to refresh rules from SQLite: {}", err);
        }

        if let Some(l4_inspector) = &self.context.l4_inspector {
            l4_inspector.maintenance_tick();
            if matches!(
                self.context.config.runtime_profile,
                RuntimeProfile::Standard
            ) {
                let stats = l4_inspector.get_statistics();
                info!(
                    "Maintenance tick: active_connections={}, blocked_connections={}, rate_limit_hits={}",
                    stats.connections.active_connections,
                    stats.connections.blocked_connections,
                    stats.connections.rate_limit_hits
                );
                info!(
                    "L4 counters: ddos_events={}, scan_events={}, protocol_anomalies={}, traffic={}, defense_actions={}",
                    stats.ddos_events,
                    stats.scan_events,
                    stats.protocol_anomalies,
                    stats.traffic,
                    stats.defense_actions
                );

                // Display per-port statistics
                if !stats.per_port_stats.is_empty() {
                    info!("=== Per-Port Statistics ===");
                    for (port, port_stats) in &stats.per_port_stats {
                        info!(
                            "Port {}: connections={}, blocks={}, ddos_events={}, scan_events={}",
                            port,
                            port_stats.connections,
                            port_stats.blocks,
                            port_stats.ddos_events,
                            port_stats.scan_events
                        );
                    }
                    info!("=============================");
                }
            }
        }
    }
}

async fn handle_connection(
    context: Arc<WafContext>,
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    _permit: OwnedSemaphorePermit,
) -> Result<()> {
    let local_addr = stream.local_addr()?;
    let packet = PacketInfo::from_socket_addrs(peer_addr, local_addr, Protocol::TCP);

    if let Some(l4_result) = inspect_transport_layers(context.as_ref(), &packet) {
        debug!(
            "L4 inspection blocked connection from {}: {}",
            peer_addr, l4_result.reason
        );
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_block(l4_result.layer.clone());
        }
        persist_l4_block_event(context.as_ref(), &packet, &l4_result);
        return Ok(());
    }

    // 协议检测和路由
    match detect_and_handle_protocol(context, stream, peer_addr, &packet).await {
        Ok(_) => Ok(()),
        Err(e) => {
            warn!("Connection handling error for {}: {}", peer_addr, e);
            Err(e)
        }
    }
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

    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_packet(payload.len());
    }

    if let Some(l4_result) = inspect_transport_layers(context.as_ref(), &packet) {
        debug!(
            "L4 inspection blocked UDP datagram from {}: {}",
            peer_addr, l4_result.reason
        );
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_block(l4_result.layer.clone());
        }
        persist_l4_block_event(context.as_ref(), &packet, &l4_result);
        return Ok(());
    }

    debug!(
        "Allowed UDP datagram from {} to {} ({} bytes)",
        peer_addr,
        local_addr,
        payload.len()
    );

    if context.config.http3_config.enabled {
        let http3_handler = Http3Handler::new(context.config.http3_config.clone());
        if let Some(request) = http3_handler.inspect_datagram(&payload, peer_addr, local_addr)? {
            debug!("Detected QUIC/HTTP3 datagram from {}", peer_addr);
            let request_dump = request.to_inspection_string();
            let inspection_result =
                inspect_application_layers(context.as_ref(), &packet, &request, &request_dump);

            if inspection_result.blocked {
                if let Some(metrics) = context.metrics.as_ref() {
                    metrics.record_block(inspection_result.layer.clone());
                }
                persist_http_block_event(context.as_ref(), &packet, &request, &inspection_result);
                debug!(
                    "Blocked QUIC/HTTP3 datagram from {}: {}",
                    peer_addr, inspection_result.reason
                );
                return Ok(());
            }
        }
    }

    if let Some(upstream_addr) = context.config.udp_upstream_addr.as_deref() {
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

async fn forward_http1_request(
    client_stream: &mut TcpStream,
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
) -> Result<u64> {
    let mut upstream_stream = TcpStream::connect(upstream_addr).await?;
    upstream_stream.write_all(&request.to_http1_bytes()).await?;
    upstream_stream.shutdown().await?;

    let copied = io::copy(&mut upstream_stream, client_stream).await?;
    client_stream.flush().await?;
    Ok(copied)
}

#[derive(Debug, Clone)]
struct UpstreamHttpResponse {
    status_code: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

async fn proxy_http_request(
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
) -> Result<UpstreamHttpResponse> {
    let mut upstream_stream = TcpStream::connect(upstream_addr).await?;
    upstream_stream.write_all(&request.to_http1_bytes()).await?;
    upstream_stream.shutdown().await?;

    let mut response_bytes = Vec::new();
    upstream_stream.read_to_end(&mut response_bytes).await?;

    parse_http1_response(&response_bytes)
}

fn parse_http1_response(response: &[u8]) -> Result<UpstreamHttpResponse> {
    let headers_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow::anyhow!("Invalid upstream HTTP/1 response: missing header terminator"))?;
    let header_block = &response[..headers_end];
    let body_offset = headers_end + 4;
    let header_text = String::from_utf8_lossy(header_block);
    let mut lines = header_text.lines();

    let status_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid upstream HTTP/1 response: missing status line"))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let _version = status_parts.next();
    let status_code = status_parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("Invalid upstream HTTP/1 response: missing status code"))?
        .parse::<u16>()?;

    let mut headers = Vec::new();
    let mut chunked = false;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("transfer-encoding")
                && value.to_ascii_lowercase().contains("chunked")
            {
                chunked = true;
                continue;
            }
            if name.eq_ignore_ascii_case("connection") {
                continue;
            }
            headers.push((name, value));
        }
    }

    let body = if chunked {
        decode_chunked_body(&response[body_offset..])?
    } else {
        response[body_offset..].to_vec()
    };

    Ok(UpstreamHttpResponse {
        status_code,
        headers,
        body,
    })
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = 0usize;
    let mut decoded = Vec::new();

    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| anyhow::anyhow!("Invalid chunked response: missing chunk size terminator"))?
            + cursor;
        let size_line = std::str::from_utf8(&body[cursor..line_end])?;
        let size_hex = size_line.split(';').next().unwrap_or(size_line).trim();
        let chunk_size = usize::from_str_radix(size_hex, 16)?;
        cursor = line_end + 2;

        if chunk_size == 0 {
            break;
        }

        let chunk_end = cursor + chunk_size;
        if chunk_end > body.len() {
            anyhow::bail!("Invalid chunked response: chunk exceeds body length");
        }
        decoded.extend_from_slice(&body[cursor..chunk_end]);
        cursor = chunk_end;

        if body.get(cursor..cursor + 2) != Some(b"\r\n") {
            anyhow::bail!("Invalid chunked response: missing CRLF after chunk");
        }
        cursor += 2;
    }

    Ok(decoded)
}

/// 检测协议版本并路由到相应的处理器
async fn detect_and_handle_protocol(
    context: Arc<WafContext>,
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
) -> Result<()> {
    // 创建协议检测器
    let detector = ProtocolDetector::default();

    // 尝试检测协议版本（读取初始字节）
    let mut initial_buffer = vec![0u8; 256];
    let bytes_read = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        stream.peek(&mut initial_buffer),
    )
    .await??;

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
        HttpVersion::Http2_0 if context.config.l7_config.http2_config.enabled => {
            handle_http2_connection(context, stream, peer_addr, packet).await
        }
        _ => {
            handle_http1_connection(context, stream, peer_addr, packet).await
        }
    }
}

/// 处理HTTP/1.1连接
async fn handle_http1_connection(
    context: Arc<WafContext>,
    mut stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
) -> Result<()> {
    let http1_handler = Http1Handler::new();

    // 读取HTTP/1.1请求
    let mut request = http1_handler
        .read_request(&mut stream, context.config.l7_config.max_request_size)
        .await?;

    request.set_client_ip(peer_addr.ip().to_string());
    request.add_metadata("listener_port".to_string(), packet.dest_port.to_string());
    request.add_metadata("protocol".to_string(), "HTTP/1.1".to_string());

    if request.uri.is_empty() {
        debug!("Empty request from {}, ignoring", peer_addr);
        return Ok(());
    }

    debug!("HTTP/1.1 request: {} {}", request.method, request.uri);

    let request_dump = request.to_inspection_string();
    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_packet(request_dump.len());
    }

    let inspection_result =
        inspect_application_layers(context.as_ref(), packet, &request, &request_dump);

    // 写入响应
    if inspection_result.blocked {
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_block(inspection_result.layer.clone());
        }
        persist_http_block_event(context.as_ref(), packet, &request, &inspection_result);
        http1_handler
            .write_response(
                &mut stream,
                403,
                "Forbidden",
                inspection_result.reason.as_bytes(),
            )
            .await?;
    } else {
        if let Some(upstream_addr) = context.config.tcp_upstream_addr.as_deref() {
            if let Err(err) = forward_http1_request(&mut stream, &request, upstream_addr).await {
                warn!(
                    "Failed to proxy HTTP/1.1 request from {} to {}: {}",
                    peer_addr, upstream_addr, err
                );
                http1_handler
                    .write_response(&mut stream, 502, "Bad Gateway", b"upstream proxy failed")
                    .await?;
            }
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

    Ok(())
}

/// 处理HTTP/2.0连接
async fn handle_http2_connection(
    context: Arc<WafContext>,
    stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
) -> Result<()> {
    let http2_config = &context.config.l7_config.http2_config;
    let http2_handler = Http2Handler::new()
        .with_max_concurrent_streams(http2_config.max_concurrent_streams)
        .with_max_frame_size(http2_config.max_frame_size)
        .with_priorities(http2_config.enable_priorities)
        .with_initial_window_size(http2_config.initial_window_size);

    let packet = packet.clone();
    let context_for_service = Arc::clone(&context);
    let peer_ip = peer_addr.ip().to_string();
    let max_request_size = context.config.l7_config.max_request_size;
    let upstream_addr = context.config.tcp_upstream_addr.clone();

    http2_handler
        .serve_connection(
            stream,
            peer_ip,
            packet.dest_port,
            max_request_size,
            move |request| {
                let context = Arc::clone(&context_for_service);
                let packet = packet.clone();
                let upstream_addr = upstream_addr.clone();

                async move {
                    debug!("HTTP/2.0 request: {} {}", request.method, request.uri);

                    let request_dump = request.to_inspection_string();
                    if let Some(metrics) = context.metrics.as_ref() {
                        metrics.record_packet(request_dump.len());
                    }

                    let inspection_result =
                        inspect_application_layers(context.as_ref(), &packet, &request, &request_dump);

                    if inspection_result.blocked {
                        if let Some(metrics) = context.metrics.as_ref() {
                            metrics.record_block(inspection_result.layer.clone());
                        }
                        persist_http_block_event(
                            context.as_ref(),
                            &packet,
                            &request,
                            &inspection_result,
                        );
                        return Ok(Http2Response {
                            status_code: 403,
                            headers: vec![],
                            body: format!("blocked: {}", inspection_result.reason).into_bytes(),
                        });
                    }

                    if let Some(upstream_addr) = upstream_addr.as_deref() {
                        match proxy_http_request(&request, upstream_addr).await {
                            Ok(response) => {
                                return Ok(Http2Response {
                                    status_code: response.status_code,
                                    headers: response.headers,
                                    body: response.body,
                                });
                            }
                            Err(err) => {
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

fn inspect_application_layers(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    serialized_request: &str,
) -> InspectionResult {
    if let Some(l7_inspector) = &context.l7_inspector {
        let l7_result = l7_inspector.inspect_unified_request(packet, request);
        if l7_result.blocked {
            return l7_result;
        }
    }

    let rule_engine_guard = context
        .rule_engine
        .read()
        .expect("rule_engine lock poisoned");
    if let Some(rule_engine) = rule_engine_guard.as_ref() {
        let rule_result = rule_engine.inspect(packet, Some(serialized_request));
        if rule_result.blocked {
            return rule_result;
        }
        if rule_engine.has_rules() && !rule_result.reason.is_empty() {
            debug!("Non-blocking rule matched: {}", rule_result.reason);
        }
    }

    InspectionResult::allow(InspectionLayer::L7)
}

fn inspect_l4_rules(context: &WafContext, packet: &PacketInfo) -> Option<InspectionResult> {
    let rule_engine_guard = context
        .rule_engine
        .read()
        .expect("rule_engine lock poisoned");
    let rule_engine = rule_engine_guard.as_ref()?;

    let rule_result = rule_engine.inspect(packet, None);
    if rule_result.blocked {
        return Some(rule_result);
    }
    if rule_engine.has_rules() && !rule_result.reason.is_empty() {
        debug!("Non-blocking L4 rule matched: {}", rule_result.reason);
    }

    None
}

fn inspect_transport_layers(context: &WafContext, packet: &PacketInfo) -> Option<InspectionResult> {
    if let Some(l4_inspector) = &context.l4_inspector {
        let l4_result = l4_inspector.inspect_packet(packet);
        if l4_result.blocked {
            return Some(l4_result);
        }
    }

    inspect_l4_rules(context, packet)
}

fn persist_l4_block_event(context: &WafContext, packet: &PacketInfo, result: &InspectionResult) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    store.enqueue_security_event(SecurityEventRecord::now(
        "L4",
        "block",
        result.reason.clone(),
        packet.source_ip.to_string(),
        packet.dest_ip.to_string(),
        packet.source_port,
        packet.dest_port,
        format!("{:?}", packet.protocol),
    ));

    if result.reason.contains("rate limiter") {
        let blocked_at = unix_timestamp();
        store.enqueue_blocked_ip(BlockedIpRecord::new(
            packet.source_ip.to_string(),
            result.reason.clone(),
            blocked_at,
            blocked_at + RATE_LIMIT_BLOCK_DURATION_SECS as i64,
        ));
    }
}

fn persist_http_block_event(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    result: &InspectionResult,
) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    let mut event = SecurityEventRecord::now(
        match result.layer {
            InspectionLayer::L4 => "L4",
            InspectionLayer::L7 => "L7",
        },
        "block",
        result.reason.clone(),
        packet.source_ip.to_string(),
        packet.dest_ip.to_string(),
        packet.source_port,
        packet.dest_port,
        format!("{:?}", packet.protocol),
    );
    event.http_method = Some(request.method.clone());
    event.uri = Some(request.uri.clone());
    event.http_version = Some(request.version.to_string());

    store.enqueue_security_event(event);
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Config, Http3Config, L4Config, L7Config, Rule, RuleAction, RuleLayer, RuntimeProfile,
        Severity,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;

    fn test_config(rules: Vec<Rule>) -> Config {
        Config {
            interface: "lo0".to_string(),
            listen_addrs: vec!["127.0.0.1:0".to_string()],
            tcp_upstream_addr: None,
            udp_upstream_addr: None,
            runtime_profile: RuntimeProfile::Minimal,
            api_enabled: false,
            api_bind: "127.0.0.1:3000".to_string(),
            bloom_enabled: false,
            l4_bloom_false_positive_verification: false,
            l7_bloom_false_positive_verification: false,
            maintenance_interval_secs: 30,
            l4_config: L4Config {
                ddos_protection_enabled: false,
                advanced_ddos_enabled: false,
                connection_rate_limit: 1_000,
                scan_enabled: false,
                ..L4Config::default()
            },
            l7_config: L7Config::default(),
            http3_config: Http3Config::default(),
            rules,
            metrics_enabled: true,
            sqlite_enabled: false,
            sqlite_path: "data/test-waf.db".to_string(),
            sqlite_auto_migrate: false,
            sqlite_rules_enabled: false,
            max_concurrent_tasks: 16,
        }
    }

    fn udp_packet() -> PacketInfo {
        PacketInfo {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            source_port: 40_000,
            dest_port: 53,
            protocol: Protocol::UDP,
            timestamp: 0,
        }
    }

    #[tokio::test]
    async fn inspect_transport_layers_blocks_udp_packets_via_l4_rules() {
        let rule = Rule {
            id: "udp-block".to_string(),
            name: "Block UDP".to_string(),
            enabled: true,
            layer: RuleLayer::L4,
            pattern: r"protocol=UDP".to_string(),
            action: RuleAction::Block,
            severity: Severity::High,
        };
        let context = WafContext::new(test_config(vec![rule])).await.unwrap();

        let result = inspect_transport_layers(&context, &udp_packet()).unwrap();
        assert!(result.blocked);
        assert_eq!(result.layer, InspectionLayer::L4);
    }

    #[tokio::test]
    async fn forward_udp_payload_relays_upstream_response() {
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap();
        let listener_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_socket.local_addr().unwrap();

        let upstream_task = tokio::spawn(async move {
            let mut buffer = vec![0u8; 1024];
            let (size, peer_addr) = upstream_socket.recv_from(&mut buffer).await.unwrap();
            upstream_socket
                .send_to(&buffer[..size], peer_addr)
                .await
                .unwrap();
        });

        forward_udp_payload(
            Arc::clone(&listener_socket),
            client_addr,
            b"ping",
            &upstream_addr.to_string(),
        )
        .await
        .unwrap();

        let mut response = vec![0u8; 1024];
        let (size, peer_addr) = client_socket.recv_from(&mut response).await.unwrap();
        upstream_task.await.unwrap();

        assert_eq!(&response[..size], b"ping");
        assert_eq!(peer_addr, listener_socket.local_addr().unwrap());
    }

    #[tokio::test]
    async fn forward_http1_request_relays_upstream_response() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();
        let front_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let front_addr = front_listener.local_addr().unwrap();

        let client_task = tokio::spawn(async move {
            let mut stream = TcpStream::connect(front_addr).await.unwrap();
            let mut response = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response)
                .await
                .unwrap();
            response
        });

        let upstream_task = tokio::spawn(async move {
            let (mut upstream_stream, _) = upstream_listener.accept().await.unwrap();
            let mut request = Vec::new();
            tokio::io::AsyncReadExt::read_to_end(&mut upstream_stream, &mut request)
                .await
                .unwrap();
            assert!(String::from_utf8_lossy(&request).contains("GET /proxy HTTP/1.1"));
            upstream_stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .await
                .unwrap();
        });

        let (mut client_side_stream, _) = front_listener.accept().await.unwrap();
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/proxy".to_string());
        request.add_header("Host".to_string(), "example.com".to_string());

        forward_http1_request(
            &mut client_side_stream,
            &request,
            &upstream_addr.to_string(),
        )
        .await
        .unwrap();

        upstream_task.await.unwrap();
        drop(client_side_stream);
        let response = client_task.await.unwrap();
        assert!(String::from_utf8_lossy(&response).contains("HTTP/1.1 200 OK"));
        assert!(String::from_utf8_lossy(&response).ends_with("ok"));
    }

    #[test]
    fn parse_http1_response_decodes_chunked_body() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

        let parsed = parse_http1_response(response).unwrap();
        assert_eq!(parsed.status_code, 200);
        assert_eq!(parsed.body, b"test".to_vec());
        assert!(
            parsed
                .headers
                .iter()
                .all(|(name, _)| !name.eq_ignore_ascii_case("transfer-encoding"))
        );
    }
}
