use anyhow::Result;
use log::{debug, info, warn};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};

use super::WafContext;
use crate::config::{Config, RuntimeProfile};
use crate::core::{InspectionLayer, InspectionResult, PacketInfo, Protocol};
use crate::protocol::{
    Http1Handler, Http2Handler, Http3Handler, HttpVersion, ProtocolDetector, UnifiedHttpRequest,
};

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
            tokio::spawn(async move {
                if let Err(err) = crate::api::ApiServer::new(addr).start().await {
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
        let mut listener_addresses = Vec::new();

        // 先绑定所有监听器
        for addr in &self.context.config.listen_addrs {
            match TcpListener::bind(addr).await {
                Ok(listener) => {
                    let addr = listener.local_addr()?;
                    listener_addresses.push((addr, listener));
                }
                Err(err) => {
                    warn!("Failed to bind listener on {}: {}", addr, err);
                }
            }
        }

        if listener_addresses.is_empty() {
            anyhow::bail!("No listeners could be started. Please check configuration.");
        }

        // 为每个监听器启动独立任务
        for (addr, listener) in listener_addresses {
            info!("Inspection listener started on {}", addr);
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

        info!(
            "Successfully started {} listener(s)",
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

    if let Some(l4_inspector) = &context.l4_inspector {
        let l4_result = l4_inspector.inspect_packet(&packet);
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
        detector.detect_version(&initial_buffer[..bytes_read])
    } else {
        HttpVersion::Http1_1 // 默认回退到HTTP/1.1
    };

    debug!(
        "Detected protocol version: {} for connection from {}",
        detected_version, peer_addr
    );

    // 根据检测到的协议版本路由到相应处理器
    match detected_version {
        HttpVersion::Http3_0 if context.config.http3_config.enabled => {
            // HTTP/3.0支持已启用，使用HTTP/3.0处理器
            handle_http3_connection(context, stream, peer_addr, packet).await
        }
        HttpVersion::Http2_0 if context.config.l7_config.http2_config.enabled => {
            // HTTP/2.0支持已启用，使用HTTP/2.0处理器
            handle_http2_connection(context, stream, peer_addr, packet).await
        }
        _ => {
            // HTTP/1.1或其他协议未启用，使用HTTP/1.1处理器
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
        http1_handler
            .write_response(
                &mut stream,
                403,
                "Forbidden",
                inspection_result.reason.as_bytes(),
            )
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

    Ok(())
}

/// 处理HTTP/3.0连接
async fn handle_http3_connection(
    context: Arc<WafContext>,
    _stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
) -> Result<()> {
    let http3_config = &context.config.http3_config;
    let _http3_handler = Http3Handler::new(http3_config.clone());

    info!("HTTP/3.0 connection from {}", peer_addr);

    // 在实际的QUIC实现中，这里会：
    // 1. 建立QUIC连接
    // 2. 读取HTTP/3.0请求
    // 3. 进行L7安全检测
    // 4. 写入HTTP/3.0响应

    // 模拟HTTP/3.0请求处理
    let mut request =
        UnifiedHttpRequest::new(HttpVersion::Http3_0, "GET".to_string(), "/".to_string());

    // 添加HTTP/3.0特定的伪头部
    request.add_header(":method".to_string(), "GET".to_string());
    request.add_header(":path".to_string(), "/".to_string());
    request.add_header(":scheme".to_string(), "https".to_string());
    request.add_header(":authority".to_string(), peer_addr.ip().to_string());

    // 添加常见的HTTP头
    request.add_header("User-Agent".to_string(), "HTTP/3.0 Test Client".to_string());
    request.add_header("Accept".to_string(), "*/*".to_string());

    info!(
        "Parsed HTTP/3.0 request: {} {}",
        request.method, request.uri
    );

    let request_dump = request.to_inspection_string();
    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_packet(request_dump.len());
    }

    let inspection_result =
        inspect_application_layers(context.as_ref(), packet, &request, &request_dump);

    // HTTP/3.0响应处理（模拟）
    // 在实际实现中会使用h3库发送HTTP/3.0响应
    if inspection_result.blocked {
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_block(inspection_result.layer.clone());
        }
        info!("Blocking HTTP/3.0 request: {}", inspection_result.reason);
        // HTTP/3.0会使用流级错误处理
    } else {
        let _metrics = context.metrics_snapshot();
        info!("Allowed HTTP/3.0 request with metrics");
        // HTTP/3.0会发送200状态码和可能的指标
    }

    info!("HTTP/3.0 connection handled for {}", peer_addr);
    Ok(())
}

/// 处理HTTP/2.0连接
async fn handle_http2_connection(
    context: Arc<WafContext>,
    mut stream: TcpStream,
    peer_addr: std::net::SocketAddr,
    packet: &PacketInfo,
) -> Result<()> {
    let http2_config = &context.config.l7_config.http2_config;
    let http2_handler = Http2Handler::new()
        .with_max_concurrent_streams(http2_config.max_concurrent_streams)
        .with_max_frame_size(http2_config.max_frame_size)
        .with_priorities(http2_config.enable_priorities);

    // 读取HTTP/2.0请求
    let mut request = http2_handler
        .read_request(&mut stream, context.config.l7_config.max_request_size)
        .await?;

    request.set_client_ip(peer_addr.ip().to_string());
    request.add_metadata("listener_port".to_string(), packet.dest_port.to_string());
    request.add_metadata("protocol".to_string(), "HTTP/2.0".to_string());

    debug!(
        "HTTP/2.0 request: {} {} (stream {:?})",
        request.method, request.uri, request.stream_id
    );

    let request_dump = request.to_inspection_string();
    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_packet(request_dump.len());
    }

    let inspection_result =
        inspect_application_layers(context.as_ref(), packet, &request, &request_dump);

    // 写入HTTP/2.0响应
    let stream_id = request.stream_id.unwrap_or(1);
    if inspection_result.blocked {
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_block(inspection_result.layer.clone());
        }
        let body = format!("blocked: {}", inspection_result.reason);
        http2_handler
            .write_response(&mut stream, stream_id, 403, &[], body.as_bytes())
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
        http2_handler
            .write_response(&mut stream, stream_id, 200, &[], body.as_bytes())
            .await?;
    }

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

    if let Some(rule_engine) = &context.rule_engine {
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
