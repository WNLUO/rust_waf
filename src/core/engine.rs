use anyhow::Result;
use brotli::Decompressor;
use flate2::read::{GzDecoder, ZlibDecoder};
use ipnet::IpNet;
use log::{debug, info, warn};
use rand::Rng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig as RustlsClientConfig, DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use std::io::Read;
#[cfg(feature = "http3")]
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Instant;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

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
use crate::core::gateway::{
    normalize_hostname, parse_upstream_endpoint, GatewaySiteRuntime, UpstreamScheme,
};
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
pub(crate) const BROWSER_FINGERPRINT_REPORT_PATH: &str =
    "/.well-known/waf/browser-fingerprint-report";
const MAX_BROWSER_FINGERPRINT_DETAILS_BYTES: usize = 128 * 1024;
static ENTRY_LISTENER_RUNTIME: OnceLock<Arc<EntryListenerRuntime>> = OnceLock::new();

#[derive(Default)]
struct EntryListenerRuntimeState {
    http: Vec<RunningEntryListener>,
    https: Option<RunningEntryListener>,
}

struct RunningEntryListener {
    addr: String,
    shutdown_tx: mpsc::Sender<()>,
    task: JoinHandle<()>,
}

struct EntryListenerRuntime {
    state: Mutex<EntryListenerRuntimeState>,
}

impl EntryListenerRuntime {
    fn global() -> Arc<Self> {
        ENTRY_LISTENER_RUNTIME
            .get_or_init(|| {
                Arc::new(Self {
                    state: Mutex::new(EntryListenerRuntimeState::default()),
                })
            })
            .clone()
    }

    async fn validate_config(&self, context: Arc<WafContext>) -> Result<()> {
        let config = context.config_snapshot();
        let requested_http = config.listen_addrs.clone();
        let requested_https = config.gateway_config.https_listen_addr.trim().to_string();
        let tls_enabled = build_tls_acceptor(context.as_ref())?.is_some();

        let guard = self.state.lock().await;
        for addr in &requested_http {
            if guard.http.iter().any(|listener| listener.addr == *addr) {
                continue;
            }
            TcpListener::bind(addr).await.map_err(|err| {
                anyhow::anyhow!("HTTP 入口 {} 已被其他进程占用或无法监听: {}", addr, err)
            })?;
        }

        if !requested_https.is_empty() {
            if !tls_enabled {
                anyhow::bail!("当前没有可用证书，无法开启 HTTPS 入口端口");
            }
            let owned = guard
                .https
                .as_ref()
                .map(|listener| listener.addr == requested_https)
                .unwrap_or(false);
            if !owned {
                TcpListener::bind(&requested_https).await.map_err(|err| {
                    anyhow::anyhow!(
                        "HTTPS 入口 {} 已被其他进程占用或无法监听: {}",
                        requested_https,
                        err
                    )
                })?;
            }
        }

        Ok(())
    }

    async fn sync(
        &self,
        context: Arc<WafContext>,
        connection_semaphore: Arc<Semaphore>,
    ) -> Result<()> {
        let config = context.config_snapshot();
        let tls_acceptor = build_tls_acceptor(context.as_ref())?;
        let requested_http = config.listen_addrs.clone();
        let requested_https = config.gateway_config.https_listen_addr.trim().to_string();

        let mut guard = self.state.lock().await;
        let mut previous_http = std::mem::take(&mut guard.http);
        let previous_https = guard.https.take();
        drop(guard);

        let mut prepared_http = Vec::new();
        let mut stale_http = Vec::new();
        for listener in previous_http.drain(..) {
            if requested_http.iter().any(|addr| addr == &listener.addr) {
                prepared_http.push(listener);
            } else {
                stale_http.push(listener);
            }
        }
        for addr in &requested_http {
            if prepared_http.iter().any(|listener| &listener.addr == addr) {
                continue;
            }
            prepared_http.push(
                spawn_http_entry_listener(
                    addr,
                    Arc::clone(&context),
                    Arc::clone(&connection_semaphore),
                )
                .await?,
            );
        }

        let (prepared_https, stale_https) = if requested_https.is_empty() {
            (None, previous_https)
        } else if let Some(existing) = previous_https {
            if existing.addr == requested_https {
                (Some(existing), None)
            } else if let Some(acceptor) = tls_acceptor {
                (
                    Some(
                        spawn_https_entry_listener(
                            &requested_https,
                            acceptor,
                            Arc::clone(&context),
                            Arc::clone(&connection_semaphore),
                        )
                        .await?,
                    ),
                    Some(existing),
                )
            } else {
                (None, Some(existing))
            }
        } else if let Some(acceptor) = tls_acceptor {
            (
                Some(
                    spawn_https_entry_listener(
                        &requested_https,
                        acceptor,
                        Arc::clone(&context),
                        Arc::clone(&connection_semaphore),
                    )
                    .await?,
                ),
                None,
            )
        } else {
            (None, None)
        };

        let mut guard = self.state.lock().await;
        guard.http = prepared_http;
        guard.https = prepared_https;
        drop(guard);

        shutdown_entry_listeners(stale_http).await;
        if let Some(listener) = stale_https {
            shutdown_entry_listener(listener).await;
        }

        Ok(())
    }

    async fn shutdown_all(&self) {
        let mut guard = self.state.lock().await;
        let previous_http = std::mem::take(&mut guard.http);
        let previous_https = guard.https.take();
        drop(guard);

        shutdown_entry_listeners(previous_http).await;
        if let Some(listener) = previous_https {
            shutdown_entry_listener(listener).await;
        }
    }
}

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
        let mut udp_listener_addresses = Vec::new();
        #[cfg(feature = "http3")]
        let mut quic_listener = None;

        // 先绑定所有 UDP 监听器
        for addr in &startup_config.listen_addrs {
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
        let _has_quic_listener = false;

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

        let entry_runtime = EntryListenerRuntime::global();
        entry_runtime
            .sync(
                Arc::clone(&self.context),
                Arc::clone(&self.connection_semaphore),
            )
            .await?;

        // 主循环处理维护任务
        loop {
            tokio::select! {
                _ = self.shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                    // 通知所有监听器任务关闭
                    for (_, shutdown_tx) in &shutdown_senders {
                        let _ = shutdown_tx.send(()).await;
                    }
                    entry_runtime.shutdown_all().await;
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
                    entry_runtime.shutdown_all().await;
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

pub async fn validate_entry_listener_config(context: Arc<WafContext>) -> Result<()> {
    EntryListenerRuntime::global()
        .validate_config(context)
        .await
}

pub async fn sync_entry_listener_runtime(
    context: Arc<WafContext>,
    concurrency_limit: usize,
) -> Result<()> {
    EntryListenerRuntime::global()
        .sync(context, Arc::new(Semaphore::new(concurrency_limit.max(1))))
        .await
}

async fn spawn_http_entry_listener(
    addr: &str,
    context: Arc<WafContext>,
    connection_semaphore: Arc<Semaphore>,
) -> Result<RunningEntryListener> {
    let listener = TcpListener::bind(addr).await?;
    let addr_string = listener.local_addr()?.to_string();
    info!("HTTP inspection listener started on {}", addr_string);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let task_addr = addr_string.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("HTTP listener shutdown signal received for {}", task_addr);
                    break;
                }
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            match connection_semaphore.clone().try_acquire_owned() {
                                Ok(permit) => {
                                    let ctx = Arc::clone(&context);
                                    tokio::spawn(async move {
                                        if let Err(err) = handle_connection(ctx, stream, peer_addr, permit).await {
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
                            warn!("Failed to accept connection on {}: {}", task_addr, err);
                        }
                    }
                }
            }
        }
    });

    Ok(RunningEntryListener {
        addr: addr_string,
        shutdown_tx,
        task,
    })
}

async fn spawn_https_entry_listener(
    addr: &str,
    tls_acceptor: TlsAcceptor,
    context: Arc<WafContext>,
    connection_semaphore: Arc<Semaphore>,
) -> Result<RunningEntryListener> {
    let listener = TcpListener::bind(addr).await?;
    let addr_string = listener.local_addr()?.to_string();
    info!("TLS inspection listener started on {}", addr_string);
    let (shutdown_tx, mut shutdown_rx) = mpsc::channel::<()>(1);
    let task_addr = addr_string.clone();
    let task = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("TLS listener shutdown signal received for {}", task_addr);
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
                                        if let Err(err) = handle_tls_connection(ctx, acceptor, stream, peer_addr, permit).await {
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
                            warn!("Failed to accept TLS connection on {}: {}", task_addr, err);
                        }
                    }
                }
            }
        }
    });

    Ok(RunningEntryListener {
        addr: addr_string,
        shutdown_tx,
        task,
    })
}

async fn shutdown_entry_listeners(listeners: Vec<RunningEntryListener>) {
    for listener in listeners {
        shutdown_entry_listener(listener).await;
    }
}

async fn shutdown_entry_listener(listener: RunningEntryListener) {
    let _ = listener.shutdown_tx.send(()).await;
    let _ = listener.task.await;
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

fn resolve_runtime_custom_response(response: &CustomHttpResponse) -> CustomHttpResponse {
    let mut resolved = response.clone();
    if let Some(random_status) = response.random_status.as_ref() {
        let roll = rand::thread_rng().gen_range(0..100);
        if roll < u32::from(random_status.success_rate_percent) {
            resolved.status_code = 200;
            resolved.body = random_status.success_body.clone();
        } else if !random_status.failure_statuses.is_empty() {
            let index = rand::thread_rng().gen_range(0..random_status.failure_statuses.len());
            resolved.status_code = random_status.failure_statuses[index];
            resolved.body = random_status.failure_body.clone();
        }
    }
    resolved
}

async fn proxy_http_request(
    context: &WafContext,
    request: &UnifiedHttpRequest,
    upstream_addr: &str,
    connect_timeout_ms: u64,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<UpstreamHttpResponse> {
    let upstream = parse_upstream_endpoint(upstream_addr)?;
    if matches!(upstream.scheme, UpstreamScheme::Http) {
        let upstream_stream = tokio::time::timeout(
            std::time::Duration::from_millis(connect_timeout_ms),
            TcpStream::connect(upstream.authority.as_str()),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
        let parsed = proxy_raw_http1_over_stream(
            upstream_stream,
            request,
            write_timeout_ms,
            read_timeout_ms,
        )
        .await?;
        context.set_upstream_health(true, None);
        return Ok(parsed);
    }

    let upstream_stream = tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        TcpStream::connect(upstream.authority.as_str()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream connect timed out"))??;
    let authority_uri = format!("https://{}", upstream.authority).parse::<http::Uri>()?;
    let server_name = ServerName::try_from(
        authority_uri
            .host()
            .ok_or_else(|| anyhow::anyhow!("HTTPS upstream missing host"))?
            .to_string(),
    )
    .map_err(|_| anyhow::anyhow!("Invalid HTTPS upstream server name"))?;
    let tls_connector = build_insecure_upstream_tls_connector();
    let tls_stream = tokio::time::timeout(
        std::time::Duration::from_millis(connect_timeout_ms),
        tls_connector.connect(server_name, upstream_stream),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream TLS handshake timed out"))??;
    let parsed =
        proxy_raw_http1_over_stream(tls_stream, request, write_timeout_ms, read_timeout_ms).await?;
    context.set_upstream_health(true, None);
    Ok(parsed)
}

async fn proxy_raw_http1_over_stream<S>(
    mut upstream_stream: S,
    request: &UnifiedHttpRequest,
    write_timeout_ms: u64,
    read_timeout_ms: u64,
) -> Result<UpstreamHttpResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request_bytes = request.to_http1_bytes();
    tokio::time::timeout(
        std::time::Duration::from_millis(write_timeout_ms),
        upstream_stream.write_all(&request_bytes),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Upstream write timed out"))??;

    let mut response_bytes = Vec::new();
    let mut buffer = vec![0u8; 8192];
    loop {
        let read_result = tokio::time::timeout(
            std::time::Duration::from_millis(read_timeout_ms),
            upstream_stream.read(&mut buffer),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Upstream read timed out"))?;
        match read_result {
            Ok(0) => break,
            Ok(n) => response_bytes.extend_from_slice(&buffer[..n]),
            Err(err) if !response_bytes.is_empty() => {
                debug!(
                    "Ignoring upstream read error after receiving response bytes: {}",
                    err
                );
                break;
            }
            Err(err) => return Err(err.into()),
        }
    }

    parse_http1_response(&response_bytes)
}

fn build_insecure_upstream_tls_connector() -> TlsConnector {
    crate::tls::ensure_rustls_crypto_provider();
    let config = RustlsClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
        .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
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
    let has_body_signature = body_has_safeline_signature(&body);
    let has_header_signature = headers_have_safeline_signature(&response.headers);
    let has_signature = has_body_signature || has_header_signature;

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
        Some(value) if value.contains("br") => {
            let decoder = Decompressor::new(response.body.as_slice(), 4096);
            decoder.take(limit as u64).read_to_end(&mut decoded).ok()?;
        }
        Some(_) => {
            decoded.extend_from_slice(&response.body[..response.body.len().min(limit)]);
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
    extract_json_string_by_keys(
        &payload,
        &["event_id", "eventId", "eventID", "log_id", "logId"],
    )
}

fn extract_html_comment_event_id(body: &str) -> Option<String> {
    let lower = body.to_ascii_lowercase();
    for marker in ["<!-- event_id:", "<!-- event-id:", "<!-- event id:"] {
        let Some(start) = lower.find(marker) else {
            continue;
        };
        let value_start = start + marker.len();
        let Some(remainder) = body.get(value_start..) else {
            continue;
        };
        let Some(end) = remainder.find("-->") else {
            continue;
        };
        let candidate = remainder.get(..end)?.trim();
        let event_id = candidate.split_whitespace().next()?.trim();
        if is_valid_safeline_event_id(event_id) {
            return Some(event_id.to_string());
        }
    }

    None
}

fn body_has_safeline_signature(body: &str) -> bool {
    let lower = body.to_ascii_lowercase();
    let mentions_safeline = lower.contains("safeline") || lower.contains("chaitin");
    let mentions_block = lower.contains("blocked")
        || lower.contains("forbidden")
        || lower.contains("intercept")
        || lower.contains("web application firewall")
        || lower.contains("\"code\":403")
        || lower.contains("\"status\":403");

    mentions_safeline && mentions_block
}

fn headers_have_safeline_signature(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(key, value)| {
        let key = key.to_ascii_lowercase();
        let value = value.to_ascii_lowercase();
        (matches!(
            key.as_str(),
            "server" | "x-powered-by" | "x-waf" | "x-safeline-event-id" | "x-request-id"
        ) && (value.contains("safeline") || value.contains("chaitin")))
            || (key == "set-cookie" && value.contains("sl-session="))
    })
}

fn extract_json_string_by_keys(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            for key in keys {
                if let Some(candidate) = map
                    .get(*key)
                    .and_then(|item| item.as_str())
                    .filter(|item| is_valid_safeline_event_id(item))
                {
                    return Some(candidate.to_string());
                }
            }

            map.values()
                .find_map(|item| extract_json_string_by_keys(item, keys))
        }
        serde_json::Value::Array(items) => items
            .iter()
            .find_map(|item| extract_json_string_by_keys(item, keys)),
        _ => None,
    }
}

fn is_valid_safeline_event_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | ':'))
}

fn request_expects_empty_body(request: &UnifiedHttpRequest) -> bool {
    request.method.eq_ignore_ascii_case("HEAD")
}

fn body_for_request(request: &UnifiedHttpRequest, body: &[u8]) -> Vec<u8> {
    if request_expects_empty_body(request) {
        Vec::new()
    } else {
        body.to_vec()
    }
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
                            let response = resolve_runtime_custom_response(&response);
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

                    if let Some(response) = try_handle_browser_fingerprint_report(
                        context.as_ref(),
                        &packet,
                        &request,
                        matched_site.as_ref(),
                    ) {
                        let body = body_for_request(&request, &response.body);
                        return Ok(Http2Response {
                            status_code: response.status_code,
                            headers: response.headers,
                            body,
                        });
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
                            let response = resolve_runtime_custom_response(response);
                            let body = body_for_request(&request, &response.body);
                            return Ok(Http2Response {
                                status_code: response.status_code,
                                headers: response.headers,
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
                                        Ok(Http2Response {
                                            status_code: response.status_code,
                                            headers: response.headers,
                                            body: response.body,
                                        })
                                    }
                                    UpstreamResponseDisposition::Custom(response) => {
                                        let response = resolve_runtime_custom_response(&response);
                                        let body = body_for_request(&request, &response.body);
                                        Ok(Http2Response {
                                            status_code: response.status_code,
                                            headers: response.headers,
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

fn try_handle_browser_fingerprint_report(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    matched_site: Option<&GatewaySiteRuntime>,
) -> Option<CustomHttpResponse> {
    if request_path(&request.uri) != BROWSER_FINGERPRINT_REPORT_PATH {
        return None;
    }

    Some(handle_browser_fingerprint_report(
        context,
        packet,
        request,
        matched_site,
    ))
}

fn handle_browser_fingerprint_report(
    context: &WafContext,
    packet: &PacketInfo,
    request: &UnifiedHttpRequest,
    matched_site: Option<&GatewaySiteRuntime>,
) -> CustomHttpResponse {
    if !request.method.eq_ignore_ascii_case("POST") {
        return json_http_response(
            405,
            serde_json::json!({
                "success": false,
                "message": "浏览器指纹上报只接受 POST 请求",
            }),
            &[("allow", "POST")],
        );
    }

    let Some(store) = context.sqlite_store.as_ref() else {
        return json_http_response(
            503,
            serde_json::json!({
                "success": false,
                "message": "SQLite 事件存储未启用，无法落库浏览器指纹",
            }),
            &[],
        );
    };

    if request.body.is_empty() {
        return json_http_response(
            400,
            serde_json::json!({
                "success": false,
                "message": "浏览器指纹上报体不能为空",
            }),
            &[],
        );
    }

    let mut payload = match serde_json::from_slice::<serde_json::Value>(&request.body) {
        Ok(value) => value,
        Err(err) => {
            return json_http_response(
                400,
                serde_json::json!({
                    "success": false,
                    "message": format!("浏览器指纹上报不是合法 JSON: {}", err),
                }),
                &[],
            );
        }
    };

    let provided_provider_event_id = payload
        .get("fingerprintId")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let derived_provider_event_id = derive_browser_fingerprint_id(&payload);

    let Some(payload_object) = payload.as_object_mut() else {
        return json_http_response(
            400,
            serde_json::json!({
                "success": false,
                "message": "浏览器指纹上报必须是 JSON 对象",
            }),
            &[],
        );
    };

    let source_ip = request
        .client_ip
        .clone()
        .unwrap_or_else(|| packet.source_ip.to_string());
    let provider_event_id = provided_provider_event_id.unwrap_or(derived_provider_event_id);

    payload_object.insert(
        "fingerprintId".to_string(),
        serde_json::Value::String(provider_event_id.clone()),
    );
    payload_object.insert(
        "server".to_string(),
        serde_json::json!({
            "received_at": unix_timestamp(),
            "client_ip": source_ip.clone(),
            "request_id": request.get_header("x-request-id").cloned(),
            "host": request_hostname(request),
            "uri": request.uri,
            "method": request.method,
            "http_version": request.version.to_string(),
            "listener_port": request.get_metadata("listener_port").cloned(),
            "site_id": matched_site.map(|site| site.id),
            "site_name": matched_site.map(|site| site.name.clone()),
            "site_primary_hostname": matched_site.map(|site| site.primary_hostname.clone()),
        }),
    );

    let details_json = match serde_json::to_string_pretty(&payload) {
        Ok(serialized) => serialized,
        Err(err) => {
            return json_http_response(
                500,
                serde_json::json!({
                    "success": false,
                    "message": format!("浏览器指纹序列化失败: {}", err),
                }),
                &[],
            );
        }
    };

    if details_json.len() > MAX_BROWSER_FINGERPRINT_DETAILS_BYTES {
        return json_http_response(
            413,
            serde_json::json!({
                "success": false,
                "message": format!(
                    "浏览器指纹详情过大，最大允许 {} 字节",
                    MAX_BROWSER_FINGERPRINT_DETAILS_BYTES
                ),
            }),
            &[],
        );
    }

    let mut event = SecurityEventRecord::now(
        "L7",
        "respond",
        build_browser_fingerprint_reason(&provider_event_id, &payload),
        source_ip,
        packet.dest_ip.to_string(),
        packet.source_port,
        packet.dest_port,
        format!("{:?}", packet.protocol),
    );
    event.provider = Some("browser_fingerprint".to_string());
    event.provider_event_id = Some(provider_event_id.clone());
    event.provider_site_id = matched_site.map(|site| site.id.to_string());
    event.provider_site_name = matched_site.map(|site| site.name.clone());
    event.provider_site_domain = request_hostname(request)
        .or_else(|| matched_site.map(|site| site.primary_hostname.clone()));
    event.http_method = Some(request.method.clone());
    event.uri = Some(request.uri.clone());
    event.http_version = Some(request.version.to_string());
    event.details_json = Some(details_json);
    store.enqueue_security_event(event);

    json_http_response(
        202,
        serde_json::json!({
            "success": true,
            "message": "浏览器指纹已接收并写入事件库",
            "fingerprint_id": provider_event_id,
        }),
        &[],
    )
}

fn build_browser_fingerprint_reason(
    provider_event_id: &str,
    payload: &serde_json::Value,
) -> String {
    let timezone = payload
        .get("timezone")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let platform = payload
        .get("platform")
        .and_then(|value| value.as_str())
        .unwrap_or("unknown");
    let fonts = payload
        .get("fonts")
        .and_then(|value| value.as_array())
        .map(|items| items.len())
        .unwrap_or(0);
    format!(
        "浏览器指纹回传 fp={} tz={} platform={} fonts={}",
        provider_event_id, timezone, platform, fonts
    )
}

fn derive_browser_fingerprint_id(payload: &serde_json::Value) -> String {
    let serialized = serde_json::to_vec(payload).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(&serialized);
    format!("{:x}", hasher.finalize())
        .chars()
        .take(24)
        .collect()
}

fn json_http_response(
    status_code: u16,
    body: serde_json::Value,
    extra_headers: &[(&str, &str)],
) -> CustomHttpResponse {
    let mut headers = vec![
        (
            "content-type".to_string(),
            "application/json; charset=utf-8".to_string(),
        ),
        ("cache-control".to_string(), "no-store".to_string()),
    ];
    headers.extend(
        extra_headers
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string())),
    );

    CustomHttpResponse {
        status_code,
        headers,
        body: serde_json::to_vec(&body).unwrap_or_else(|_| {
            br#"{"success":false,"message":"response serialization failed"}"#.to_vec()
        }),
        tarpit: None,
        random_status: None,
    }
}

fn request_path(uri: &str) -> &str {
    uri.split('?').next().unwrap_or(uri)
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
        202 => "Accepted",
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
    event.provider_site_id = matched_site.map(|site| site.id.to_string());
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
    if peer_ip.is_loopback() {
        return true;
    }

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
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::net::UdpSocket;

    fn test_config(rules: Vec<Rule>) -> Config {
        Config {
            interface: "lo0".to_string(),
            listen_addrs: vec!["127.0.0.1:0".to_string()],
            tcp_upstream_addr: None,
            udp_upstream_addr: None,
            runtime_profile: RuntimeProfile::Minimal,
            api_enabled: false,
            api_bind: "127.0.0.1:3740".to_string(),
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

    fn unique_test_db_path(name: &str) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let suffix = rand::random::<u64>();
        std::env::temp_dir()
            .join(format!("waf_engine_{}_{}_{}.db", name, nanos, suffix))
            .display()
            .to_string()
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
    async fn browser_fingerprint_report_is_persisted_to_event_store() {
        let mut config = test_config(vec![]);
        config.sqlite_enabled = true;
        config.sqlite_auto_migrate = true;
        config.sqlite_path = unique_test_db_path("browser_fingerprint");
        let context = WafContext::new(config).await.unwrap();
        let packet = PacketInfo {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            source_port: 45_678,
            dest_port: 443,
            protocol: Protocol::TCP,
            timestamp: 0,
        };

        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "POST".to_string(),
            BROWSER_FINGERPRINT_REPORT_PATH.to_string(),
        );
        request.set_client_ip("203.0.113.77".to_string());
        request.add_header("host".to_string(), "portal.example.com".to_string());
        request.add_metadata("listener_port".to_string(), "443".to_string());
        request.body = br#"{"fingerprintId":"fp-test-123","timezone":"Asia/Shanghai","platform":"MacIntel","fonts":["Arial","Monaco"],"canvas":"data:image/png;base64,abc"}"#.to_vec();
        prepare_request_for_proxy(&mut request);

        let response =
            try_handle_browser_fingerprint_report(&context, &packet, &request, None).unwrap();
        assert_eq!(response.status_code, 202);

        tokio::time::sleep(tokio::time::Duration::from_millis(60)).await;

        let events = context
            .sqlite_store
            .as_ref()
            .unwrap()
            .list_security_events(&crate::storage::SecurityEventQuery::default())
            .await
            .unwrap();
        assert_eq!(events.total, 1);
        assert_eq!(
            events.items[0].provider.as_deref(),
            Some("browser_fingerprint")
        );
        assert_eq!(
            events.items[0].provider_event_id.as_deref(),
            Some("fp-test-123")
        );
        assert_eq!(
            events.items[0].uri.as_deref(),
            Some(BROWSER_FINGERPRINT_REPORT_PATH)
        );
        assert!(events.items[0]
            .details_json
            .as_deref()
            .unwrap_or_default()
            .contains("\"server\""));
    }

    #[tokio::test]
    async fn browser_fingerprint_report_rejects_non_post_request() {
        let context = WafContext::new(test_config(vec![])).await.unwrap();
        let packet = PacketInfo {
            source_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)),
            dest_ip: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            source_port: 45_678,
            dest_port: 443,
            protocol: Protocol::TCP,
            timestamp: 0,
        };
        let request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            BROWSER_FINGERPRINT_REPORT_PATH.to_string(),
        );

        let response =
            try_handle_browser_fingerprint_report(&context, &packet, &request, None).unwrap();
        assert_eq!(response.status_code, 405);
        assert!(response.headers.iter().any(|(key, value)| {
            key.eq_ignore_ascii_case("allow") && value.eq_ignore_ascii_case("POST")
        }));
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
    async fn apply_client_identity_trusts_loopback_proxy_by_default() {
        let context = WafContext::new(test_config(vec![])).await.unwrap();
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 443));

        let mut request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "GET".to_string(), "/".to_string());
        request.add_header(
            "x-forwarded-for".to_string(),
            "198.51.100.88, 127.0.0.1".to_string(),
        );

        apply_client_identity(&context, peer_addr, &mut request);

        assert_eq!(request.client_ip.as_deref(), Some("198.51.100.88"));
        assert_eq!(
            request
                .get_metadata("network.client_ip_source")
                .map(String::as_str),
            Some("forwarded_header")
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
    fn detect_safeline_block_response_matches_nested_json_event_id() {
        let response = UpstreamHttpResponse {
            status_code: 403,
            status_text: Some("Forbidden".to_string()),
            headers: vec![("server".to_string(), "Chaitin SafeLine".to_string())],
            body:
                br#"{"data":{"eventId":"evt-nested-123"},"message":"request blocked by safeline"}"#
                    .to_vec(),
        };

        let matched =
            detect_safeline_block_response(&response, 4096, SafeLineInterceptMatchMode::Strict)
                .unwrap();
        assert_eq!(matched.event_id.as_deref(), Some("evt-nested-123"));
        assert_eq!(matched.evidence, "json_signature");
    }

    #[test]
    fn detect_safeline_block_response_matches_brotli_encoded_body() {
        let mut encoded = Vec::new();
        {
            let mut compressor = brotli::CompressorWriter::new(&mut encoded, 4096, 5, 22);
            std::io::Write::write_all(
                &mut compressor,
                br#"{"message":"blocked by Chaitin SafeLine Web Application Firewall","event_id":"evt-br-1"}"#,
            )
            .unwrap();
        }

        let response = UpstreamHttpResponse {
            status_code: 403,
            status_text: Some("Forbidden".to_string()),
            headers: vec![
                ("content-type".to_string(), "application/json".to_string()),
                ("content-encoding".to_string(), "br".to_string()),
            ],
            body: encoded,
        };

        let matched =
            detect_safeline_block_response(&response, 4096, SafeLineInterceptMatchMode::Strict)
                .unwrap();
        assert_eq!(matched.event_id.as_deref(), Some("evt-br-1"));
        assert_eq!(matched.evidence, "json_signature");
    }

    #[test]
    fn detect_safeline_block_response_matches_head_style_cookie_signature() {
        let response = UpstreamHttpResponse {
            status_code: 403,
            status_text: Some("Forbidden".to_string()),
            headers: vec![
                ("content-type".to_string(), "text/plain".to_string()),
                (
                    "set-cookie".to_string(),
                    "sl-session=test-token; SameSite=None; Secure; Path=/".to_string(),
                ),
            ],
            body: Vec::new(),
        };

        let matched =
            detect_safeline_block_response(&response, 4096, SafeLineInterceptMatchMode::Strict)
                .unwrap();
        assert_eq!(matched.event_id, None);
        assert_eq!(matched.evidence, "status_and_signature");
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

    #[test]
    fn body_for_request_omits_body_for_head_requests() {
        let request =
            UnifiedHttpRequest::new(HttpVersion::Http1_1, "HEAD".to_string(), "/".to_string());

        assert!(body_for_request(&request, b"blocked").is_empty());
    }

    #[tokio::test]
    async fn replace_and_block_ip_uses_forwarded_client_ip_from_loopback_proxy() {
        let mut config = test_config(vec![]);
        config.sqlite_enabled = true;
        config.sqlite_auto_migrate = true;
        config.sqlite_path = unique_test_db_path("safeline_replace_and_block_ip");
        config.l7_config.safeline_intercept.enabled = true;
        config.l7_config.safeline_intercept.action = SafeLineInterceptAction::ReplaceAndBlockIp;

        let context = WafContext::new(config).await.unwrap();
        let packet = PacketInfo {
            source_ip: "127.0.0.1".parse().unwrap(),
            dest_ip: "198.51.100.20".parse().unwrap(),
            source_port: 44321,
            dest_port: 443,
            protocol: Protocol::TCP,
            timestamp: 0,
        };
        let peer_addr = std::net::SocketAddr::from(([127, 0, 0, 1], 44321));

        let mut request = UnifiedHttpRequest::new(
            HttpVersion::Http1_1,
            "GET".to_string(),
            "/blocked".to_string(),
        );
        request.add_header("host".to_string(), "portal.example.com".to_string());
        request.add_header(
            "x-forwarded-for".to_string(),
            "198.51.100.88, 127.0.0.1".to_string(),
        );
        apply_client_identity(&context, peer_addr, &mut request);

        let response = UpstreamHttpResponse {
            status_code: 403,
            status_text: Some("Forbidden".to_string()),
            headers: vec![(
                "content-type".to_string(),
                "application/json".to_string(),
            )],
            body: br#"{"code":403,"success":false,"message":"blocked by Chaitin SafeLine Web Application Firewall","event_id":"evt-block-1"}"#.to_vec(),
        };

        let disposition = apply_safeline_upstream_action(
            &context,
            &packet,
            &request,
            None,
            &context.config_snapshot().l7_config.safeline_intercept,
            response,
        );

        assert!(matches!(
            disposition,
            UpstreamResponseDisposition::Custom(_)
        ));

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let blocked = context
            .sqlite_store
            .as_ref()
            .unwrap()
            .list_blocked_ips(&crate::storage::BlockedIpQuery::default())
            .await
            .unwrap();

        assert_eq!(blocked.items.len(), 1);
        assert_eq!(blocked.items[0].ip, "198.51.100.88");
        assert_eq!(
            blocked.items[0].reason,
            "safeline upstream intercept: event_id=evt-block-1"
        );
    }
}
