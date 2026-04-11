use anyhow::Result;
use flate2::read::{GzDecoder, ZlibDecoder};
use ipnet::IpNet;
use log::{debug, info, warn};
use std::io::Read;
#[cfg(feature = "http3")]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, OwnedSemaphorePermit, Semaphore};
use tokio_rustls::TlsAcceptor;

#[cfg(feature = "http3")]
use bytes::Buf;
#[cfg(feature = "http3")]
use bytes::Bytes;
#[cfg(feature = "http3")]
use h3::server::RequestStream;
#[cfg(feature = "http3")]
use h3_quinn::Connection as H3QuinnConnection;
#[cfg(feature = "http3")]
use quinn::Incoming as QuinnIncoming;

use super::WafContext;
use crate::config::l7::{
    SafeLineInterceptAction, SafeLineInterceptConfig, SafeLineInterceptMatchMode,
    UpstreamFailureMode,
};
use crate::config::{Config, RuntimeProfile};
use crate::core::gateway::{normalize_hostname, GatewaySiteRuntime};
use crate::core::{
    CustomHttpResponse, InspectionAction, InspectionLayer, InspectionResult, PacketInfo, Protocol,
};
use crate::l4::connection::limiter::RATE_LIMIT_BLOCK_DURATION_SECS;
use crate::protocol::{
    Http1Handler, Http2Handler, Http2Response, Http3Handler, HttpVersion, ProtocolDetector,
    UnifiedHttpRequest,
};
use crate::storage::{BlockedIpRecord, SecurityEventRecord};

static REQUEST_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

pub struct WafEngine {
    context: Arc<WafContext>,
    _shutdown_tx: mpsc::Sender<()>,
    shutdown_rx: mpsc::Receiver<()>,
    connection_semaphore: Arc<Semaphore>,
}

impl WafEngine {
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing WAF engine...");

        let (shutdown_tx, shutdown_rx) = mpsc::channel(1);
        let concurrency_limit = config.max_concurrent_tasks.max(1);
        let context = Arc::new(WafContext::new(config).await?);

        Ok(Self {
            context,
            _shutdown_tx: shutdown_tx,
            shutdown_rx,
            connection_semaphore: Arc::new(Semaphore::new(concurrency_limit)),
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        let startup_config = self.context.config_snapshot();
        info!("WAF engine started");
        info!(
            "Concurrency limit set to {} inflight connections",
            startup_config.max_concurrent_tasks
        );

        if let Some(l4_inspector) = &self.context.l4_inspector {
            l4_inspector.start(self.context.as_ref()).await?;
        }

        self.context
            .http_processor
            .start(self.context.as_ref())
            .await?;

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

        let context = Arc::clone(&self.context);
        tokio::spawn(async move {
            super::engine_maintenance::run_upstream_healthcheck_loop(context).await;
        });

        if let Some(store) = self.context.sqlite_store.as_ref().cloned() {
            let fallback_config = startup_config.clone();
            tokio::spawn(async move {
                super::engine_maintenance::run_safeline_auto_sync_loop(store, fallback_config)
                    .await;
            });
        }

        let maintenance_interval = startup_config.maintenance_interval_secs.max(5);
        let mut maintenance =
            tokio::time::interval(tokio::time::Duration::from_secs(maintenance_interval));

        // 创建多个监听器，每个监听器在独立任务中运行
        let mut shutdown_senders = Vec::new();
        let mut tcp_listener_addresses = Vec::new();
        let mut udp_listener_addresses = Vec::new();
        let mut tls_listener = None;
        #[cfg(feature = "http3")]
        let mut quic_listener = None;

        // 先绑定所有TCP/UDP监听器
        for addr in &startup_config.listen_addrs {
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

        if let Some(tls_acceptor) = super::engine_tls::build_tls_acceptor(self.context.as_ref())? {
            let tls_addr = &startup_config.gateway_config.https_listen_addr;
            match TcpListener::bind(tls_addr).await {
                Ok(listener) => {
                    let addr = listener.local_addr()?;
                    tls_listener = Some((addr, listener, tls_acceptor));
                }
                Err(err) => {
                    warn!("Failed to bind TLS listener on {}: {}", tls_addr, err);
                }
            }
        }

        #[cfg(feature = "http3")]
        {
            if let Some(endpoint) =
                super::engine_tls::build_http3_endpoint(&startup_config.http3_config)?
            {
                let addr = endpoint.local_addr()?;
                self.context
                    .set_http3_runtime("running", true, Some(addr.to_string()), None);
                quic_listener = Some((addr, endpoint));
            } else {
                let config = &startup_config.http3_config;
                let (status, last_error) = if !config.enabled {
                    ("disabled".to_string(), None)
                } else if !config.enable_tls13 {
                    (
                        "degraded".to_string(),
                        Some("HTTP/3 requires TLS 1.3".to_string()),
                    )
                } else if config.certificate_path.is_none() || config.private_key_path.is_none() {
                    (
                        "degraded".to_string(),
                        Some("certificate_path/private_key_path are missing".to_string()),
                    )
                } else {
                    (
                        "pending".to_string(),
                        Some("HTTP/3 listener was not started".to_string()),
                    )
                };
                self.context
                    .set_http3_runtime(status, false, None, last_error);
            }
        }

        #[cfg(not(feature = "http3"))]
        if startup_config.http3_config.enabled {
            self.context.set_http3_runtime(
                "unsupported",
                false,
                None,
                Some("Binary was built without the 'http3' feature".to_string()),
            );
            warn!(
                "HTTP/3 support was requested but the binary was built without the 'http3' feature"
            );
        } else {
            self.context
                .set_http3_runtime("disabled", false, None, None);
        }

        #[cfg(feature = "http3")]
        let has_quic_listener = quic_listener.is_some();
        #[cfg(not(feature = "http3"))]
        let has_quic_listener = false;

        if tcp_listener_addresses.is_empty()
            && udp_listener_addresses.is_empty()
            && tls_listener.is_none()
            && !has_quic_listener
        {
            anyhow::bail!("No TCP, UDP, TLS, or HTTP/3 listeners could be started. Please check configuration.");
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

        if let Some((addr, listener, tls_acceptor)) = tls_listener {
            info!("TLS inspection listener started on {}", addr);
            let context = Arc::clone(&self.context);
            let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
            let connection_semaphore = Arc::clone(&self.connection_semaphore);

            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            info!("TLS listener shutdown signal received for {}", addr);
                            break;
                        }
                        accept_result = listener.accept() => {
                            match accept_result {
                                Ok((stream, peer_addr)) => {
                                    match connection_semaphore.clone().try_acquire_owned() {
                                        Ok(permit) => {
                                            let ctx = Arc::clone(&context);
                                            let acceptor = tls_acceptor.clone();
                                            tokio::spawn(async move {
                                                if let Err(err) =
                                                    handle_tls_connection(ctx, acceptor, stream, peer_addr, permit).await
                                                {
                                                    warn!("TLS connection handling failed: {}", err);
                                                }
                                            });
                                        }
                                        Err(_) => {
                                            warn!(
                                                "Dropping TLS connection from {} due to concurrency limit",
                                                peer_addr
                                            );
                                        }
                                    }
                                }
                                Err(err) => {
                                    warn!("Failed to accept TLS connection on {}: {}", addr, err);
                                }
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            info!("Ctrl+C received, shutting down TLS listener on {}", addr);
                            break;
                        }
                    }
                }
            });
            shutdown_senders.push((task, shutdown_tx));
        }

        #[cfg(feature = "http3")]
        if let Some((addr, endpoint)) = quic_listener {
            info!("HTTP/3 listener started on {}", addr);
            let context = Arc::clone(&self.context);
            let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
            let connection_semaphore = Arc::clone(&self.connection_semaphore);

            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            info!("HTTP/3 listener shutdown signal received for {}", addr);
                            break;
                        }
                        accept_result = endpoint.accept() => {
                            match accept_result {
                                Some(incoming) => {
                                    match connection_semaphore.clone().try_acquire_owned() {
                                        Ok(permit) => {
                                            let ctx = Arc::clone(&context);
                                            tokio::spawn(async move {
                                                if let Err(err) =
                                                    handle_http3_quic_connection(ctx, incoming, addr, permit).await
                                                {
                                                    warn!("HTTP/3 connection handling failed: {}", err);
                                                }
                                            });
                                        }
                                        Err(_) => {
                                            warn!(
                                                "Dropping HTTP/3 connection on {} due to concurrency limit",
                                                addr
                                            );
                                        }
                                    }
                                }
                                None => break,
                            }
                        }
                        _ = tokio::signal::ctrl_c() => {
                            info!("Ctrl+C received, shutting down HTTP/3 listener on {}", addr);
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
                debug!(
                    "Maintenance tick: active_connections={}, blocked_connections={}, rate_limit_hits={}",
                    stats.connections.active_connections,
                    stats.connections.blocked_connections,
                    stats.connections.rate_limit_hits
                );
                debug!(
                    "L4 counters: ddos_events={}, protocol_anomalies={}, traffic={}, defense_actions={}",
                    stats.ddos_events,
                    stats.protocol_anomalies,
                    stats.traffic,
                    stats.defense_actions
                );

                // Display per-port statistics
                if !stats.per_port_stats.is_empty() {
                    debug!("=== Per-Port Statistics ===");
                    for (port, port_stats) in &stats.per_port_stats {
                        debug!(
                            "Port {}: connections={}, blocks={}, ddos_events={}",
                            port, port_stats.connections, port_stats.blocks, port_stats.ddos_events
                        );
                    }
                    debug!("=============================");
                }
            }
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
fn build_tls_acceptor(context: &WafContext) -> Result<Option<tokio_rustls::TlsAcceptor>> {
    super::engine_tls::build_tls_acceptor(context)
}

#[cfg_attr(not(test), allow(dead_code))]
#[cfg(feature = "http3")]
fn build_http3_endpoint(config: &crate::config::Http3Config) -> Result<Option<quinn::Endpoint>> {
    super::engine_tls::build_http3_endpoint(config)
}

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

    // 协议检测和路由
    match detect_and_handle_protocol(context, stream, peer_addr, &packet).await {
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
    let mut metadata = vec![("transport".to_string(), "tls".to_string())];
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
    prepare_request_for_proxy(&mut unified);
    let matched_site = resolve_gateway_site(context.as_ref(), &unified);
    if let Some(site) = matched_site.as_ref() {
        apply_gateway_site_metadata(&mut unified, site);
    }

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
            send_http3_response(
                &mut stream,
                response.status_code,
                &response.headers,
                response.body.clone(),
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
async fn forward_http1_request<W>(
    client_stream: &mut W,
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let response = proxy_http_request(
        context,
        request,
        upstream_addr,
        connect_timeout_ms,
        write_timeout_ms,
        read_timeout_ms,
    )
    .await?;
    let approx_bytes = response.body.len() as u64;
    write_http1_upstream_response(client_stream, &response).await?;
    Ok(approx_bytes)
}

#[derive(Debug, Clone)]
struct UpstreamHttpResponse {
    status_code: u16,
    status_text: Option<String>,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SafeLineInterceptMatch {
    event_id: Option<String>,
    evidence: &'static str,
}

#[derive(Debug, Clone)]
enum UpstreamResponseDisposition {
    Forward(UpstreamHttpResponse),
    Custom(CustomHttpResponse),
    Drop,
}

async fn proxy_http_request(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<UpstreamHttpResponse> {
    let mut upstream_stream = tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        TcpStream::connect(upstream_addr),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
    let request_bytes = request.to_http1_bytes();
    tokio::time::timeout(
        std::time::Duration::from_millis(write_timeout_ms),
        upstream_stream.write_all(&request_bytes),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream write timed out"))??;
    tokio::time::timeout(
        std::time::Duration::from_millis(write_timeout_ms),
        upstream_stream.shutdown(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream shutdown timed out"))??;

    let mut response_bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_millis(read_timeout_ms),
        upstream_stream.read_to_end(&mut response_bytes),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream read timed out"))??;

    let parsed = parse_http1_response(&response_bytes)?;
    context.set_upstream_health(true, None);
    Ok(parsed)
}

fn parse_http1_response(response: &[u8]) -> Result<UpstreamHttpResponse> {
    let headers_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| {
            anyhow::anyhow!("Invalid upstream HTTP/1 response: missing header terminator")
        })?;
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
    let status_text = status_parts
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);

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
        status_text,
        headers,
        body,
    })
}

async fn write_http1_upstream_response<W>(
    client_stream: &mut W,
    response: &UpstreamHttpResponse,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    Http1Handler::new()
        .write_response_with_headers(
            client_stream,
            response.status_code,
            response
                .status_text
                .as_deref()
                .unwrap_or(http_status_text(response.status_code)),
            &response.headers,
            &response.body,
        )
        .await?;
    Ok(())
}

fn apply_safeline_upstream_action(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    matched_site: Option<&GatewaySiteRuntime>,
    intercept_config: &SafeLineInterceptConfig,
    response: UpstreamHttpResponse,
) -> UpstreamResponseDisposition {
    if !intercept_config.enabled {
        return UpstreamResponseDisposition::Forward(response);
    }

    let Some(matched) = detect_safeline_block_response(
        &response,
        intercept_config.max_body_bytes,
        intercept_config.match_mode,
    ) else {
        return UpstreamResponseDisposition::Forward(response);
    };
    let response_status = response.status_code;

    let (local_action, disposition) = match intercept_config.action {
        SafeLineInterceptAction::Pass => ("pass", UpstreamResponseDisposition::Forward(response)),
        SafeLineInterceptAction::Replace => {
            match crate::rules::build_custom_response(&intercept_config.response_template) {
                Ok(custom) => ("replace", UpstreamResponseDisposition::Custom(custom)),
                Err(err) => {
                    warn!(
                    "Failed to build SafeLine replacement response, falling back to upstream response: {}",
                    err
                );
                    ("pass", UpstreamResponseDisposition::Forward(response))
                }
            }
        }
        SafeLineInterceptAction::Drop => ("drop", UpstreamResponseDisposition::Drop),
        SafeLineInterceptAction::ReplaceAndBlockIp => {
            match crate::rules::build_custom_response(&intercept_config.response_template) {
                Ok(custom) => {
                    persist_safeline_intercept_blocked_ip(
                        context,
                        packet,
                        request,
                        intercept_config.block_duration_secs,
                        matched.event_id.as_deref(),
                    );
                    (
                        "replace_and_block_ip",
                        UpstreamResponseDisposition::Custom(custom),
                    )
                }
                Err(err) => {
                    warn!(
                        "Failed to build SafeLine replacement response for replace_and_block_ip, falling back to upstream response: {}",
                        err
                    );
                    ("pass", UpstreamResponseDisposition::Forward(response))
                }
            }
        }
    };

    if let Some(metrics) = context.metrics.as_ref() {
        metrics.record_block(InspectionLayer::L7);
    }
    persist_safeline_intercept_event(
        context,
        packet,
        request,
        matched_site,
        &matched,
        response_status,
        local_action,
    );

    disposition
}

fn detect_safeline_block_response(
    response: &UpstreamHttpResponse,
    max_body_bytes: usize,
    match_mode: SafeLineInterceptMatchMode,
) -> Option<SafeLineInterceptMatch> {
    let body = decode_response_body_for_matching(response, max_body_bytes)?;
    let has_signature = body
        .to_ascii_lowercase()
        .contains("blocked by chaitin safeline web application firewall");

    if let Some(event_id) = extract_html_comment_event_id(&body) {
        return Some(SafeLineInterceptMatch {
            event_id: Some(event_id),
            evidence: "html_event_comment",
        });
    }

    let json_event_id = extract_json_event_id(&body);
    if has_signature && json_event_id.is_some() {
        return Some(SafeLineInterceptMatch {
            event_id: json_event_id,
            evidence: "json_signature",
        });
    }

    if has_signature && matches!(response.status_code, 403 | 405) {
        return Some(SafeLineInterceptMatch {
            event_id: None,
            evidence: "status_and_signature",
        });
    }

    if matches!(match_mode, SafeLineInterceptMatchMode::Relaxed)
        && matches!(response.status_code, 403 | 405)
    {
        return Some(SafeLineInterceptMatch {
            event_id: None,
            evidence: "status_only_relaxed",
        });
    }

    None
}

fn decode_response_body_for_matching(
    response: &UpstreamHttpResponse,
    max_body_bytes: usize,
) -> Option<String> {
    let limit = max_body_bytes.max(256);
    let mut decoded = Vec::new();

    match upstream_header_value(&response.headers, "content-encoding")
        .map(|value| value.to_ascii_lowercase())
    {
        Some(value) if value.contains("gzip") => {
            let decoder = GzDecoder::new(response.body.as_slice());
            decoder.take(limit as u64).read_to_end(&mut decoded).ok()?;
        }
        Some(value) if value.contains("deflate") => {
            let decoder = ZlibDecoder::new(response.body.as_slice());
            decoder.take(limit as u64).read_to_end(&mut decoded).ok()?;
        }
        Some(_) => {
            return None;
        }
        None => {
            decoded.extend_from_slice(&response.body[..response.body.len().min(limit)]);
        }
    }

    Some(String::from_utf8_lossy(&decoded).into_owned())
}

fn upstream_header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn extract_json_event_id(body: &str) -> Option<String> {
    let payload = serde_json::from_str::<serde_json::Value>(body).ok()?;
    payload
        .get("event_id")
        .and_then(|value| value.as_str())
        .map(ToOwned::to_owned)
}

fn extract_html_comment_event_id(body: &str) -> Option<String> {
    let marker = "<!-- event_id:";
    let start = body.find(marker)? + marker.len();
    let remainder = body.get(start..)?;
    let end = remainder.find("-->")?;
    let candidate = remainder.get(..end)?.trim();
    let event_id = candidate.split_whitespace().next()?.trim();
    (!event_id.is_empty()
        && event_id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-'))
    .then(|| event_id.to_string())
}

fn decode_chunked_body(body: &[u8]) -> Result<Vec<u8>> {
    let mut cursor = 0usize;
    let mut decoded = Vec::new();

    loop {
        let line_end = body[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(|| {
                anyhow::anyhow!("Invalid chunked response: missing chunk size terminator")
            })?
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
    let config = context.config_snapshot();
    // 创建协议检测器
    let detector = ProtocolDetector::default();

    // 尝试检测协议版本（读取初始字节）
    let mut initial_buffer = vec![0u8; 256];
    let bytes_read = tokio::time::timeout(
        std::time::Duration::from_millis(config.l7_config.first_byte_timeout_ms),
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
        HttpVersion::Http2_0 if config.l7_config.http2_config.enabled => {
            handle_http2_connection(context, stream, peer_addr, packet, Vec::new()).await
        }
        _ => handle_http1_connection(context, stream, peer_addr, packet, Vec::new()).await,
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
    for (key, value) in extra_metadata {
        request.add_metadata(key, value);
    }
    prepare_request_for_proxy(&mut request);
    let matched_site = resolve_gateway_site(context.as_ref(), &request);
    if let Some(site) = matched_site.as_ref() {
        apply_gateway_site_metadata(&mut request, site);
    }

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

    if inspection_result.should_persist_event() {
        persist_http_inspection_event(context.as_ref(), packet, &request, &inspection_result);
    }

    // 写入响应
    if inspection_result.blocked {
        if let Some(metrics) = context.metrics.as_ref() {
            metrics.record_block(inspection_result.layer.clone());
        }
        if let Some(response) = inspection_result.custom_response.as_ref() {
            if let Some(tarpit) = response.tarpit.as_ref() {
                http1_handler
                    .write_response_with_headers_tarpit(
                        &mut stream,
                        response.status_code,
                        http_status_text(response.status_code),
                        &response.headers,
                        &response.body,
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
                        &response.body,
                    )
                    .await?;
            }
            return Ok(());
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
                    match apply_safeline_upstream_action(
                        context.as_ref(),
                        packet,
                        &request,
                        matched_site.as_ref(),
                        resolve_safeline_intercept_config(&config, matched_site.as_ref()),
                        response,
                    ) {
                        UpstreamResponseDisposition::Forward(response) => {
                            write_http1_upstream_response(&mut stream, &response).await?;
                        }
                        UpstreamResponseDisposition::Custom(response) => {
                            if let Some(tarpit) = response.tarpit.as_ref() {
                                http1_handler
                                    .write_response_with_headers_tarpit(
                                        &mut stream,
                                        response.status_code,
                                        http_status_text(response.status_code),
                                        &response.headers,
                                        &response.body,
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
                                        &response.body,
                                    )
                                    .await?;
                            }
                        }
                        UpstreamResponseDisposition::Drop => {
                            let _ = stream.shutdown().await;
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
                        .write_response(&mut stream, 502, "Bad Gateway", b"upstream proxy failed")
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

    Ok(())
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
                    prepare_request_for_proxy(&mut request);
                    let matched_site = resolve_gateway_site(context.as_ref(), &request);
                    if let Some(site) = matched_site.as_ref() {
                        apply_gateway_site_metadata(&mut request, site);
                    }
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
                            return Ok(Http2Response {
                                status_code: response.status_code,
                                headers: response.headers.clone(),
                                body: response.body.clone(),
                            });
                        }
                        return Ok(Http2Response {
                            status_code: 403,
                            headers: vec![],
                            body: format!("blocked: {}", inspection_result.reason).into_bytes(),
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
                                        Ok(Http2Response {
                                            status_code: response.status_code,
                                            headers: response.headers,
                                            body: response.body,
                                        })
                                    }
                                    UpstreamResponseDisposition::Custom(response) => {
                                        Ok(Http2Response {
                                            status_code: response.status_code,
                                            headers: response.headers,
                                            body: response.body,
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

fn inspect_application_layers(
    context: &WafContext,
    _packet: &PacketInfo,
    _request: &UnifiedHttpRequest,
    serialized_request: &str,
) -> InspectionResult {
    let rule_result = inspect_l7_rules(context, _packet, serialized_request);
    if rule_result.blocked || !rule_result.reason.is_empty() {
        return rule_result;
    }

    InspectionResult::allow(InspectionLayer::L7)
}

fn http_status_text(status_code: u16) -> &'static str {
    match status_code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        418 => "I'm a teapot",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

fn inspect_l4_rules(context: &WafContext, packet: &PacketInfo) -> InspectionResult {
    let rule_engine_guard = context
        .rule_engine
        .read()
        .expect("rule_engine lock poisoned");
    let Some(rule_engine) = rule_engine_guard.as_ref() else {
        return InspectionResult::allow(InspectionLayer::L4);
    };

    let rule_result = rule_engine.inspect(packet, None);
    if rule_result.blocked {
        return rule_result;
    }
    if rule_engine.has_rules() && !rule_result.reason.is_empty() {
        match rule_result.action {
            InspectionAction::Alert => {
                debug!("Non-blocking L4 alert rule matched: {}", rule_result.reason);
                return rule_result;
            }
            InspectionAction::Allow => {
                debug!("L4 allow rule matched: {}", rule_result.reason);
                return rule_result;
            }
            InspectionAction::Respond => {
                debug!(
                    "L4 respond rule matched unexpectedly: {}",
                    rule_result.reason
                );
                return rule_result;
            }
            InspectionAction::Block => {}
        }
    }

    InspectionResult::allow(InspectionLayer::L4)
}

fn inspect_l7_rules(
    context: &WafContext,
    packet: &PacketInfo,
    serialized_request: &str,
) -> InspectionResult {
    let rule_engine_guard = context
        .rule_engine
        .read()
        .expect("rule_engine lock poisoned");
    let Some(rule_engine) = rule_engine_guard.as_ref() else {
        return InspectionResult::allow(InspectionLayer::L7);
    };

    let rule_result = rule_engine.inspect(packet, Some(serialized_request));
    if rule_result.blocked {
        return rule_result;
    }
    if rule_engine.has_rules() && !rule_result.reason.is_empty() {
        match rule_result.action {
            InspectionAction::Alert => {
                debug!("Non-blocking L7 alert rule matched: {}", rule_result.reason);
                return rule_result;
            }
            InspectionAction::Allow => {
                debug!("L7 allow rule matched: {}", rule_result.reason);
                return rule_result;
            }
            InspectionAction::Respond => {
                debug!("L7 respond rule matched: {}", rule_result.reason);
                return rule_result;
            }
            InspectionAction::Block => {}
        }
    }

    InspectionResult::allow(InspectionLayer::L7)
}

fn inspect_transport_layers(context: &WafContext, packet: &PacketInfo) -> InspectionResult {
    if let Some(l4_inspector) = &context.l4_inspector {
        let l4_result = l4_inspector.inspect_packet(packet);
        if l4_result.blocked || l4_result.should_persist_event() {
            return l4_result;
        }
    }

    inspect_l4_rules(context, packet)
}

fn persist_l4_inspection_event(
    context: &WafContext,
    packet: &PacketInfo,
    result: &InspectionResult,
) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    store.enqueue_security_event(SecurityEventRecord::now(
        "L4",
        result.event_action(),
        result.reason.clone(),
        packet.source_ip.to_string(),
        packet.dest_ip.to_string(),
        packet.source_port,
        packet.dest_port,
        format!("{:?}", packet.protocol),
    ));

    if result.persist_blocked_ip {
        let blocked_at = unix_timestamp();
        store.enqueue_blocked_ip(BlockedIpRecord::new(
            packet.source_ip.to_string(),
            result.reason.clone(),
            blocked_at,
            blocked_at + RATE_LIMIT_BLOCK_DURATION_SECS as i64,
        ));
    }
}

fn persist_http_inspection_event(
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
        result.event_action(),
        result.reason.clone(),
        request
            .client_ip
            .clone()
            .unwrap_or_else(|| packet.source_ip.to_string()),
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

fn persist_safeline_intercept_event(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    matched_site: Option<&GatewaySiteRuntime>,
    matched: &SafeLineInterceptMatch,
    upstream_status_code: u16,
    local_action: &str,
) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    let mut event = SecurityEventRecord::now(
        "L7",
        "block",
        format!(
            "safeline upstream intercept detected; evidence={}; upstream_status={}; local_action={}",
            matched.evidence, upstream_status_code, local_action
        ),
        request
            .client_ip
            .clone()
            .unwrap_or_else(|| packet.source_ip.to_string()),
        packet.dest_ip.to_string(),
        packet.source_port,
        packet.dest_port,
        format!("{:?}", packet.protocol),
    );
    event.provider = Some("safeline".to_string());
    event.provider_event_id = matched.event_id.clone();
    event.provider_site_name = matched_site.map(|site| site.name.clone());
    event.provider_site_domain = request_hostname(request)
        .or_else(|| matched_site.map(|site| site.primary_hostname.clone()));
    event.http_method = Some(request.method.clone());
    event.uri = Some(request.uri.clone());
    event.http_version = Some(request.version.to_string());

    store.enqueue_security_event(event);
}

fn persist_safeline_intercept_blocked_ip(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    block_duration_secs: u64,
    provider_event_id: Option<&str>,
) {
    let Some(store) = context.sqlite_store.as_ref() else {
        return;
    };

    let blocked_at = unix_timestamp();
    let ip = request
        .client_ip
        .clone()
        .unwrap_or_else(|| packet.source_ip.to_string());
    let reason = provider_event_id
        .map(|event_id| format!("safeline upstream intercept: event_id={event_id}"))
        .unwrap_or_else(|| "safeline upstream intercept".to_string());

    store.enqueue_blocked_ip(BlockedIpRecord::new(
        ip,
        reason,
        blocked_at,
        blocked_at + block_duration_secs as i64,
    ));
}

fn apply_client_identity(
    context: &WafContext,
    peer_addr: std::net::SocketAddr,
    request: &mut UnifiedHttpRequest,
) {
    let resolved_client_ip = resolve_client_ip(context, peer_addr, request);
    let used_forwarded_header = resolved_client_ip != peer_addr.ip();

    request.set_client_ip(resolved_client_ip.to_string());
    request.add_metadata("network.peer_ip".to_string(), peer_addr.ip().to_string());
    request.add_metadata(
        "network.client_ip".to_string(),
        resolved_client_ip.to_string(),
    );
    request.add_metadata(
        "network.client_ip_source".to_string(),
        if used_forwarded_header {
            "forwarded_header".to_string()
        } else {
            "socket_peer".to_string()
        },
    );

    apply_proxy_headers(
        peer_addr,
        request,
        resolved_client_ip,
        used_forwarded_header,
    );
}

fn prepare_request_for_proxy(request: &mut UnifiedHttpRequest) {
    ensure_request_id(request);
    apply_standard_forwarding_headers(request);
}

fn apply_proxy_headers(
    peer_addr: std::net::SocketAddr,
    request: &mut UnifiedHttpRequest,
    resolved_client_ip: std::net::IpAddr,
    preserve_forwarded_chain: bool,
) {
    request.add_header("x-real-ip".to_string(), resolved_client_ip.to_string());

    let forwarded_for = match (
        preserve_forwarded_chain,
        request.get_header("x-forwarded-for"),
    ) {
        (true, Some(existing)) if !existing.trim().is_empty() => {
            let existing = existing.trim();
            let peer_ip = peer_addr.ip().to_string();
            if existing
                .rsplit(',')
                .next()
                .map(|item| item.trim() == peer_ip)
                .unwrap_or(false)
            {
                existing.to_string()
            } else {
                format!("{existing}, {peer_ip}")
            }
        }
        (false, Some(existing)) if !existing.trim().is_empty() => resolved_client_ip.to_string(),
        _ => resolved_client_ip.to_string(),
    };

    request.add_header("x-forwarded-for".to_string(), forwarded_for);
}

fn ensure_request_id(request: &mut UnifiedHttpRequest) {
    let request_id = request
        .get_header("x-request-id")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(generate_request_id);
    request.add_header("x-request-id".to_string(), request_id.clone());
    request.add_metadata("request_id".to_string(), request_id);
}

fn apply_standard_forwarding_headers(request: &mut UnifiedHttpRequest) {
    let forwarded_proto = request
        .get_header("x-forwarded-proto")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| infer_forwarded_proto(request));
    request.add_header("x-forwarded-proto".to_string(), forwarded_proto);

    let forwarded_host = request
        .get_header("x-forwarded-host")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| request.get_header("host").cloned())
        .or_else(|| request.get_metadata("authority").cloned());
    if let Some(forwarded_host) = forwarded_host {
        request.add_header("x-forwarded-host".to_string(), forwarded_host);
    }

    if let Some(port) = request
        .get_header("x-forwarded-port")
        .cloned()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| request.get_metadata("listener_port").cloned())
    {
        request.add_header("x-forwarded-port".to_string(), port);
    }
}

fn infer_forwarded_proto(request: &UnifiedHttpRequest) -> String {
    if matches!(request.version, HttpVersion::Http3_0) {
        return "https".to_string();
    }

    if request
        .get_metadata("transport")
        .map(|transport| {
            transport.eq_ignore_ascii_case("tls") || transport.eq_ignore_ascii_case("quic")
        })
        .unwrap_or(false)
    {
        return "https".to_string();
    }

    "http".to_string()
}

fn resolve_gateway_site(
    context: &WafContext,
    request: &UnifiedHttpRequest,
) -> Option<GatewaySiteRuntime> {
    let listener_port = request
        .get_metadata("listener_port")
        .and_then(|port| port.parse::<u16>().ok())?;
    let hostname = request_hostname(request);
    context
        .gateway_runtime
        .resolve_site(hostname.as_deref(), listener_port)
}

fn apply_gateway_site_metadata(request: &mut UnifiedHttpRequest, site: &GatewaySiteRuntime) {
    request.add_metadata("gateway.site_id".to_string(), site.id.to_string());
    request.add_metadata("gateway.site_name".to_string(), site.name.clone());
    request.add_metadata(
        "gateway.primary_hostname".to_string(),
        site.primary_hostname.clone(),
    );
    if let Some(upstream) = &site.upstream_endpoint {
        request.add_metadata("gateway.upstream".to_string(), upstream.clone());
    }
}

fn request_hostname(request: &UnifiedHttpRequest) -> Option<String> {
    request
        .get_header("host")
        .or_else(|| request.get_metadata("authority"))
        .and_then(|value| normalize_request_host(value))
}

fn normalize_request_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(uri) = format!("http://{}", trimmed).parse::<http::Uri>() {
        if let Some(authority) = uri.authority() {
            return normalize_hostname(authority.host());
        }
    }

    if let Some(host) = trimmed
        .strip_prefix('[')
        .and_then(|value| value.split(']').next())
    {
        return normalize_hostname(host);
    }

    normalize_hostname(trimmed.split(':').next().unwrap_or(trimmed))
}

fn select_upstream_target(
    context: &WafContext,
    site: Option<&GatewaySiteRuntime>,
) -> Option<String> {
    site.and_then(|site| site.upstream_endpoint.clone())
        .or_else(|| context.config_snapshot().tcp_upstream_addr)
}

fn resolve_safeline_intercept_config<'a>(
    config: &'a crate::config::Config,
    site: Option<&'a GatewaySiteRuntime>,
) -> &'a crate::config::l7::SafeLineInterceptConfig {
    site.and_then(|item| item.safeline_intercept.as_ref())
        .unwrap_or(&config.l7_config.safeline_intercept)
}

fn should_reject_unmatched_site(context: &WafContext, request: &UnifiedHttpRequest) -> bool {
    context.gateway_runtime.has_sites() && request_hostname(request).is_some()
}

fn generate_request_id() -> String {
    let sequence = REQUEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}", unix_timestamp(), sequence)
}

fn enforce_upstream_policy(context: &WafContext) -> Result<()> {
    let snapshot = context.upstream_health_snapshot();
    if snapshot.healthy {
        return Ok(());
    }

    match context.config_snapshot().l7_config.upstream_failure_mode {
        UpstreamFailureMode::FailOpen => Ok(()),
        UpstreamFailureMode::FailClose => Err(anyhow::anyhow!(
            "{}",
            snapshot
                .last_error
                .unwrap_or_else(|| "Upstream health check reports unhealthy".to_string())
        )),
    }
}

#[cfg_attr(not(test), allow(dead_code))]
async fn probe_upstream_tcp(upstream_addr: &str, timeout_ms: u64) -> Result<()> {
    super::engine_maintenance::probe_upstream_tcp(upstream_addr, timeout_ms).await
}

fn resolve_client_ip(
    context: &WafContext,
    peer_addr: std::net::SocketAddr,
    request: &UnifiedHttpRequest,
) -> std::net::IpAddr {
    if !peer_is_trusted_proxy(context, peer_addr.ip()) {
        return peer_addr.ip();
    }

    for header in &context.config_snapshot().l7_config.real_ip_headers {
        let Some(value) = request.get_header(header) else {
            continue;
        };

        if let Some(ip) = extract_forwarded_ip(value) {
            return ip;
        }
    }

    peer_addr.ip()
}

fn peer_is_trusted_proxy(context: &WafContext, peer_ip: std::net::IpAddr) -> bool {
    let config = context.config_snapshot();
    config
        .l7_config
        .trusted_proxy_cidrs
        .iter()
        .filter_map(|cidr| cidr.parse::<IpNet>().ok())
        .any(|network| network.contains(&peer_ip))
}

fn extract_forwarded_ip(value: &str) -> Option<std::net::IpAddr> {
    value
        .split(',')
        .find_map(|candidate| candidate.trim().parse::<std::net::IpAddr>().ok())
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
            ..Config::default()
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

    #[test]
    fn build_tls_acceptor_is_disabled_without_https_listener() {
        let context = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(WafContext::new(test_config(vec![])))
            .unwrap();
        assert!(build_tls_acceptor(&context).unwrap().is_none());
    }

    #[test]
    fn build_tls_acceptor_is_disabled_without_loaded_certificates() {
        let mut config = test_config(vec![]);
        config.gateway_config.https_listen_addr = "127.0.0.1:660".to_string();
        let context = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(WafContext::new(config))
            .unwrap();
        assert!(build_tls_acceptor(&context).unwrap().is_none());
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
            plugin_template_id: None,
            response_template: None,
        };
        let context = WafContext::new(test_config(vec![rule])).await.unwrap();

        let result = inspect_transport_layers(&context, &udp_packet());
        assert!(result.blocked);
        assert_eq!(result.layer, InspectionLayer::L4);
    }

    #[tokio::test]
    async fn inspect_application_layers_blocks_requests_via_l7_rules() {
        let rule = Rule {
            id: "l7-block-admin".to_string(),
            name: "Block Admin Path".to_string(),
            enabled: true,
            layer: RuleLayer::L7,
            pattern: r"GET /admin".to_string(),
            action: RuleAction::Block,
            severity: Severity::High,
            plugin_template_id: None,
            response_template: None,
        };
        let context = WafContext::new(test_config(vec![rule])).await.unwrap();
        let packet = PacketInfo {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            source_port: 41_000,
            dest_port: 8080,
            protocol: Protocol::TCP,
            timestamp: 0,
        };
        let request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/admin".to_string(),
        );
        let serialized_request = request.to_inspection_string();

        let result = inspect_application_layers(&context, &packet, &request, &serialized_request);

        assert!(result.blocked);
        assert_eq!(result.layer, InspectionLayer::L7);
        assert!(result.reason.contains("l7-block-admin"));
    }

    #[tokio::test]
    async fn inspect_transport_layers_returns_alert_for_l4_alert_rules() {
        let rule = Rule {
            id: "udp-alert".to_string(),
            name: "Alert UDP".to_string(),
            enabled: true,
            layer: RuleLayer::L4,
            pattern: r"protocol=UDP".to_string(),
            action: RuleAction::Alert,
            severity: Severity::Medium,
            plugin_template_id: None,
            response_template: None,
        };
        let context = WafContext::new(test_config(vec![rule])).await.unwrap();

        let result = inspect_transport_layers(&context, &udp_packet());
        assert!(!result.blocked);
        assert_eq!(result.action, InspectionAction::Alert);
        assert!(result.should_persist_event());
    }

    #[tokio::test]
    async fn inspect_application_layers_returns_allow_for_l7_allow_rules() {
        let rule = Rule {
            id: "l7-allow-health".to_string(),
            name: "Allow Health".to_string(),
            enabled: true,
            layer: RuleLayer::L7,
            pattern: r"GET /health".to_string(),
            action: RuleAction::Allow,
            severity: Severity::Low,
            plugin_template_id: None,
            response_template: None,
        };
        let context = WafContext::new(test_config(vec![rule])).await.unwrap();
        let packet = PacketInfo {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            source_port: 42_000,
            dest_port: 8080,
            protocol: Protocol::TCP,
            timestamp: 0,
        };
        let request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/health".to_string(),
        );
        let serialized_request = request.to_inspection_string();

        let result = inspect_application_layers(&context, &packet, &request, &serialized_request);

        assert!(!result.blocked);
        assert_eq!(result.action, InspectionAction::Allow);
        assert!(!result.should_persist_event());
        assert!(result.reason.contains("l7-allow-health"));
    }

    #[tokio::test]
    async fn apply_client_identity_prefers_forwarded_ip_from_trusted_proxy() {
        let mut config = test_config(vec![]);
        config.l7_config.trusted_proxy_cidrs = vec!["203.0.113.0/24".to_string()];
        let context = WafContext::new(config).await.unwrap();
        let peer_addr = std::net::SocketAddr::from(([203, 0, 113, 10], 443));

        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
        request.add_header(
            "x-forwarded-for".to_string(),
            "198.51.100.24, 203.0.113.10".to_string(),
        );

        apply_client_identity(&context, peer_addr, &mut request);

        assert_eq!(request.client_ip.as_deref(), Some("198.51.100.24"));
        assert_eq!(
            request
                .get_metadata("network.client_ip_source")
                .map(String::as_str),
            Some("forwarded_header")
        );
        assert_eq!(
            request.get_header("x-real-ip").map(String::as_str),
            Some("198.51.100.24")
        );
        assert_eq!(
            request.get_header("x-forwarded-for").map(String::as_str),
            Some("198.51.100.24, 203.0.113.10")
        );
    }

    #[tokio::test]
    async fn apply_client_identity_ignores_forwarded_ip_from_untrusted_peer() {
        let context = WafContext::new(test_config(vec![])).await.unwrap();
        let peer_addr = std::net::SocketAddr::from(([198, 51, 100, 10], 443));

        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
        request.add_header("x-forwarded-for".to_string(), "192.0.2.44".to_string());

        apply_client_identity(&context, peer_addr, &mut request);

        assert_eq!(request.client_ip.as_deref(), Some("198.51.100.10"));
        assert_eq!(
            request
                .get_metadata("network.client_ip_source")
                .map(String::as_str),
            Some("socket_peer")
        );
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
        let context = WafContext::new(test_config(vec![])).await.unwrap();

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
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let (mut client_side_stream, _) = front_listener.accept().await.unwrap();
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/proxy".to_string(),
        );
        request.add_header("Host".to_string(), "example.com".to_string());

        forward_http1_request(
            &mut client_side_stream,
            &context,
            &request,
            &upstream_addr.to_string(),
            500,
            500,
            500,
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
    fn prepare_request_for_proxy_sets_request_id_and_forwarding_headers() {
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
        request.add_header("host".to_string(), "example.com".to_string());
        request.add_metadata("listener_port".to_string(), "8080".to_string());
        request.add_metadata("transport".to_string(), "tls".to_string());

        prepare_request_for_proxy(&mut request);

        assert!(request.get_header("x-request-id").is_some());
        assert_eq!(
            request.get_header("x-forwarded-proto").map(String::as_str),
            Some("https")
        );
        assert_eq!(
            request.get_header("x-forwarded-host").map(String::as_str),
            Some("example.com")
        );
        assert_eq!(
            request.get_header("x-forwarded-port").map(String::as_str),
            Some("8080")
        );
    }

    #[test]
    fn prepare_request_for_proxy_preserves_existing_request_id_and_forwarded_proto() {
        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
        request.add_header("x-request-id".to_string(), "req-123".to_string());
        request.add_header("x-forwarded-proto".to_string(), "https".to_string());

        prepare_request_for_proxy(&mut request);

        assert_eq!(
            request.get_header("x-request-id").map(String::as_str),
            Some("req-123")
        );
        assert_eq!(
            request.get_header("x-forwarded-proto").map(String::as_str),
            Some("https")
        );
    }

    #[tokio::test]
    async fn enforce_upstream_policy_rejects_when_fail_close_and_unhealthy() {
        let mut config = test_config(vec![]);
        config.l7_config.upstream_failure_mode = UpstreamFailureMode::FailClose;
        let context = WafContext::new(config).await.unwrap();
        context.set_upstream_health(false, Some("downstream unavailable".to_string()));

        let result = enforce_upstream_policy(&context);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("downstream unavailable"));
    }

    #[tokio::test]
    async fn enforce_upstream_policy_allows_when_fail_open_and_unhealthy() {
        let context = WafContext::new(test_config(vec![])).await.unwrap();
        context.set_upstream_health(false, Some("temporary failure".to_string()));

        assert!(enforce_upstream_policy(&context).is_ok());
    }

    #[tokio::test]
    async fn probe_upstream_tcp_succeeds_for_listening_socket() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });

        probe_upstream_tcp(&addr.to_string(), 500).await.unwrap();
        accept_task.await.unwrap();
    }

    #[test]
    fn parse_http1_response_decodes_chunked_body() {
        let response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Type: text/plain\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

        let parsed = parse_http1_response(response).unwrap();
        assert_eq!(parsed.status_code, 200);
        assert_eq!(parsed.status_text.as_deref(), Some("OK"));
        assert_eq!(parsed.body, b"test".to_vec());
        assert!(parsed
            .headers
            .iter()
            .all(|(name, _)| !name.eq_ignore_ascii_case("transfer-encoding")));
    }

    #[test]
    fn detect_safeline_block_response_matches_json_signature() {
        let response = UpstreamHttpResponse {
            status_code: 403,
            status_text: Some("Forbidden".to_string()),
            headers: vec![(
                "content-type".to_string(),
                "application/json".to_string(),
            )],
            body: br#"{"code":403,"success":false,"message":"blocked by Chaitin SafeLine Web Application Firewall","event_id":"evt123"}"#.to_vec(),
        };

        let matched =
            detect_safeline_block_response(&response, 4096, SafeLineInterceptMatchMode::Strict)
                .unwrap();
        assert_eq!(matched.event_id.as_deref(), Some("evt123"));
        assert_eq!(matched.evidence, "json_signature");
    }

    #[test]
    fn detect_safeline_block_response_matches_html_event_comment() {
        let response = UpstreamHttpResponse {
            status_code: 405,
            status_text: Some("Method Not Allowed".to_string()),
            headers: vec![("content-type".to_string(), "text/html".to_string())],
            body: b"<html><!-- event_id: abc123 TYPE: A --><body>blocked</body></html>".to_vec(),
        };

        let matched =
            detect_safeline_block_response(&response, 4096, SafeLineInterceptMatchMode::Strict)
                .unwrap();
        assert_eq!(matched.event_id.as_deref(), Some("abc123"));
        assert_eq!(matched.evidence, "html_event_comment");
    }

    #[test]
    fn detect_safeline_block_response_rejects_status_only_in_strict_mode() {
        let response = UpstreamHttpResponse {
            status_code: 403,
            status_text: Some("Forbidden".to_string()),
            headers: vec![("content-type".to_string(), "text/html".to_string())],
            body: b"<html><body>forbidden</body></html>".to_vec(),
        };

        assert!(detect_safeline_block_response(
            &response,
            4096,
            SafeLineInterceptMatchMode::Strict
        )
        .is_none());
        let relaxed =
            detect_safeline_block_response(&response, 4096, SafeLineInterceptMatchMode::Relaxed)
                .unwrap();
        assert_eq!(relaxed.evidence, "status_only_relaxed");
    }

    #[tokio::test]
    async fn apply_safeline_upstream_action_replaces_response_and_records_block_metric() {
        let mut config = test_config(vec![]);
        config.l7_config.safeline_intercept.enabled = true;
        config.l7_config.safeline_intercept.action = SafeLineInterceptAction::Replace;
        let context = WafContext::new(config).await.unwrap();
        let packet = PacketInfo {
            source_ip: "203.0.113.10".parse().unwrap(),
            dest_ip: "198.51.100.20".parse().unwrap(),
            source_port: 44321,
            dest_port: 443,
            protocol: Protocol::TCP,
            timestamp: 0,
        };
        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/login".to_string(),
        );
        request.set_client_ip("203.0.113.10".to_string());
        request.add_header("host".to_string(), "portal.example.com".to_string());
        let response = UpstreamHttpResponse {
            status_code: 403,
            status_text: Some("Forbidden".to_string()),
            headers: vec![(
                "content-type".to_string(),
                "application/json".to_string(),
            )],
            body: br#"{"code":403,"success":false,"message":"blocked by Chaitin SafeLine Web Application Firewall","event_id":"evt456"}"#.to_vec(),
        };

        let disposition = apply_safeline_upstream_action(
            &context,
            &packet,
            &request,
            None,
            &context.config_snapshot().l7_config.safeline_intercept,
            response,
        );

        match disposition {
            UpstreamResponseDisposition::Custom(response) => {
                assert_eq!(response.status_code, 403);
                assert!(response
                    .headers
                    .iter()
                    .any(|(key, value)| key.eq_ignore_ascii_case("cache-control")
                        && value.eq("no-store")));
            }
            other => panic!("expected custom response, got {:?}", other),
        }

        let metrics = context.metrics_snapshot().unwrap();
        assert_eq!(metrics.blocked_packets, 1);
        assert_eq!(metrics.blocked_l7, 1);
    }
}
